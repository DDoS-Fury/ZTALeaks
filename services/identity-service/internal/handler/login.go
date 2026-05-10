package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/models"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Status       string `json:"status"`
	SessionToken string `json:"session_token,omitempty"`
	Message      string `json:"message,omitempty"`
}

// Login verifica username + password Argon2id; in caso di successo
// genera un OTP a 6 cifre, lo salva hashato in DB con TTL 5 min e lo
// invia via email. Il client poi chiama /verify-otp con session_token + otp.
func (api *IdentityAPI) Login(w http.ResponseWriter, r *http.Request) {
	slog.Info("login richiesto", "remote", r.RemoteAddr)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		respondError(w, "credenziali mancanti", http.StatusBadRequest)
		return
	}

	user, err := api.Users.FindByUsername(r.Context(), req.Username)
	if err != nil {
		// timing-attack mitigation: pareggia il costo Argon2id anche su utente assente
		dummy, _ := crypto.GenerateFromPassword("dummy")
		_, _ = crypto.ComparePasswordAndHash(req.Password, dummy)
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		return
	}

	ok, err := crypto.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil || !ok {
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		return
	}

	// OTP a 6 cifre, hash Argon2id, TTL 5 min, max 3 tentativi
	otp, err := generateOTP()
	if err != nil {
		respondError(w, "errore generazione OTP", http.StatusInternalServerError)
		return
	}
	otpHash, err := crypto.GenerateFromPassword(otp)
	if err != nil {
		respondError(w, "errore hash OTP", http.StatusInternalServerError)
		return
	}
	sessionToken := newSessionToken()

	if err := api.OTP.Create(r.Context(), models.OTPSession{
		SessionToken: sessionToken,
		UserID:       user.ID,
		OTPHash:      otpHash,
		Attempts:     0,
	}); err != nil {
		slog.Error("login: store OTP", "error", err)
		respondError(w, "errore interno", http.StatusInternalServerError)
		return
	}

	// Best-effort: se l'email fallisce l'OTP è in DB e l'utente puo' ritentare.
	if err := api.Mail.SendOTP(user.Email, otp); err != nil {
		slog.Error("login: invio email OTP", "error", err, "to", user.Email)
	}

	slog.Info("OTP emesso", "user_id", user.ID, "email", user.Email)
	respondJSON(w, http.StatusOK, loginResponse{
		Status:       "otp_required",
		SessionToken: sessionToken,
		Message:      "OTP inviato all'email registrata",
	})
}
