package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

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

	// Estrazione e verifica del certificato Envoy X-Forwarded-Client-Cert
	certHeader := r.Header.Get("X-Forwarded-Client-Cert")
	cn, ou, certPresent := extractCertFields(certHeader)

	if !certPresent {
		// 1. Se il certificato non è presente, l'utente DEVE avere il ruolo guest
		if !strings.EqualFold(user.Role, "guest") {
			slog.Warn("login fallito: certificato mancante per non-guest", "username", req.Username)
			respondError(w, "accesso negato: certificato mTLS richiesto per questo ruolo", http.StatusForbidden)
			return
		}
	} else {
		// 2. Controllo CN == username (case-insensitive)
		if !strings.EqualFold(cn, req.Username) {
			slog.Warn("login fallito: mismatch CN-Username", "cn", cn, "username", req.Username)
			respondError(w, "accesso negato: certificato non corrisponde all'utente", http.StatusForbidden)
			return
		}
		// 3. Controllo OU (nel certificato) == Role (nel database) (case-insensitive)
		if !strings.EqualFold(ou, user.Role) {
			slog.Warn("login fallito: mismatch OU-Role", "ou", ou, "role", user.Role)
			respondError(w, "accesso negato: ruolo certificato non valido", http.StatusForbidden)
			return
		}
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

// extractCertFields processa l'header 'x-forwarded-client-cert' generato da Envoy.
// L'header standard è una stringa separata da punto e virgola:
// By=...;Hash=...;Subject="CN=admin,OU=admin,O=ZTA";URI=...
func extractCertFields(header string) (cn string, ou string, present bool) {
	if header == "" {
		return "", "", false
	}
	present = true
	parts := strings.Split(header, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(kv[0])) == "subject" {
			subject := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			// Analizza i campi del Subject divisi da virgola
			subParts := strings.Split(subject, ",")
			for _, sp := range subParts {
				skv := strings.SplitN(strings.TrimSpace(sp), "=", 2)
				if len(skv) == 2 {
					key := strings.ToUpper(strings.TrimSpace(skv[0]))
					val := strings.TrimSpace(skv[1])
					switch key {
					case "CN":
						cn = val
					case "OU":
						ou = val
					}
				}
			}
		}
	}
	return cn, ou, present
}
