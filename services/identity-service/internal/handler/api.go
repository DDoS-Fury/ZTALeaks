package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/models"

	"log/slog"
)

type IdentityAPI struct {
	Repo *db.UserRepository
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func (api *IdentityAPI) Login(w http.ResponseWriter, r *http.Request) {
	slog.Info("Richiesta di login ricevuta", "ip", r.RemoteAddr)

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Formato JSON non valido", "error", err.Error())
		http.Error(w, "Richiesta non valida", http.StatusBadRequest)
		return
	}

	// Evitare di interrogare DB in caso di credenziali vuote
	if req.Username == "" || req.Password == "" {
		slog.Warn("Tentativo di accesso con credenziali vuote")
		http.Error(w, "Credenziali mancanti", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Recupero utente asincrono nel contesto
	user, err := api.Repo.FindByUsername(ctx, req.Username)
	if err != nil {
		slog.Warn("Utente non trovato", "username", req.Username)
		// IMPORTANTE: anche se l'utente non c'è, controlliamo un hash dummy
		// per impedire agli attaccanti di misurare il tempo di esecuzione
		// (prevenzione enumerazione username)
		dummyHash, _ := crypto.GenerateFromPassword("dummy_password")
		crypto.ComparePasswordAndHash(req.Password, dummyHash)

		http.Error(w, "Credenziali non valide", http.StatusUnauthorized)
		return
	}

	// 2. Controllo password costante nel tempo (Argon2id)
	valid, err := crypto.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil || !valid {
		slog.Warn("Password errata", "username", req.Username)
		http.Error(w, "Credenziali non valide", http.StatusUnauthorized)
		return
	}

	// 3. Elaborazione attributi di sicurezza e ZTA (JA3)
	ja3Finger := r.Header.Get("X-JA3-Fingerprint")
	if ja3Finger == "" {
		slog.Warn("Fingerprint JA3 mancante - Contesto Zero Trust non valutabile", "username", req.Username)
		// In ambiente reale ZTA rigoroso qui potremmo bloccare l'accesso.
		// Lasciamo passare l'autenticazione ma lo segnamo nel token
	}

	// Logica per Security Enclave e 2FA
	twoFAVerified := !user.TwoFAEnabled // Se disabilitata, contiamo come verificata
	secureEnclaveValid := user.SecureEnclaveValid

	// 4. Generazione JSON Web Token
	token, err := crypto.GenerateJWT(user.ID, user.Role, twoFAVerified, secureEnclaveValid, ja3Finger)
	if err != nil {
		slog.Error("Impossibile generare JWT", "username", req.Username, "error", err.Error())
		http.Error(w, "Errore interno (Security Service)", http.StatusInternalServerError)
		return
	}

	// 5. Aggiornamento Security DB (in background, non blochante - uso delle Go-routines)
	loginInfo := models.LoginInfo{
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		JA3Finger: ja3Finger,
	}

	go func(u string, info models.LoginInfo) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := api.Repo.UpdateLastLogin(bgCtx, u, info); err != nil {
			slog.Error("Impossibile aggiornare i log del SecurityDB in background", "error", err.Error())
		}
	}(user.Username, loginInfo)

	// Invia riscontro OK con token nei cookie HTTP-Only (opzionale ma preferibile per ZTA)
	// e come payload per consumare con fetch
	http.SetCookie(w, &http.Cookie{
		Name:     "ztaleaks_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(crypto.TokenValidDuration),
		HttpOnly: true, // Previene XSS
		Secure:   true, // Garantisce HTTPS (Envoy si assicura di inviarlo in HTTPS)
		SameSite: http.SameSiteStrictMode,
	})

	slog.Info("Autenticazione riuscita e token rilasciato", "username", req.Username, "ja3", ja3Finger)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
}
