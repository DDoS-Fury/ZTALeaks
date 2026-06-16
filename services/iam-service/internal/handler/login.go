package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"ztaleaks/iam-service/internal/crypto"
	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/models"
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
	ip := r.Header.Get("x-envoy-external-address")
	if ip == "" {
		slog.Warn("login fallito: ip non trovato")
		respondError(w, "ip non trovato", http.StatusBadRequest)
		return
	}

	if err := api.RateLimits.CheckRateLimit(r.Context(), ip); err != nil {
		if errors.Is(err, db.ErrRateLimitExceeded) {
			slog.Warn("login fallito: rate limit superato", "ip", ip)
			respondError(w, "troppi tentativi falliti, riprova più tardi", http.StatusTooManyRequests)
			return
		}
		slog.Error("errore controllo rate limit", "error", err)
		respondError(w, "errore interno", http.StatusInternalServerError)
		return
	}

	slog.Info("login richiesto", "remote", r.RemoteAddr, "ip", ip)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		slog.Error("failed to decode login request", "error", err, "src_ip", r.Header.Get("x-envoy-external-address"))
		return
	}
	slog.Info("login richiesto", "src_ip", r.Header.Get("x-envoy-external-address"), "cert_present", r.Header.Get("X-Forwarded-Client-Cert") != "", "username", req.Username)
	if req.Username == "" || req.Password == "" {
		respondError(w, "credenziali mancanti", http.StatusBadRequest)
		slog.Warn("login fallito: credenziali mancanti", "username", req.Username, "role", "guest", "src_ip", r.Header.Get("x-envoy-external-address"))
		if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
			slog.Error("errore recording rate limit", "error", err)
		}
		return
	}

	user, err := api.Users.FindByUsername(r.Context(), req.Username)
	if err != nil {
		// timing-attack mitigation: pareggia il costo Argon2id anche su utente assente
		dummy, _ := crypto.GenerateFromPassword("dummy")
		_, _ = crypto.ComparePasswordAndHash(req.Password, dummy)
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		slog.Warn("login fallito: utente non trovato", "username", req.Username, "src_ip", r.Header.Get("x-envoy-external-address"))
		if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
			slog.Error("errore recording rate limit", "error", err)
		}
		return
	}

	// Estrazione e verifica del certificato Envoy X-Forwarded-Client-Cert
	certHeader := r.Header.Get("X-Forwarded-Client-Cert")
	cn, ou, certPresent := extractCertFields(certHeader)

	if !certPresent {
		// 1. Se il certificato non è presente, l'utente DEVE avere il ruolo guest
		if !strings.EqualFold(user.Role, "guest") {
			slog.Warn("login fallito: certificato mancante per non-guest", "username", user.Username, "role", user.Role, "src_ip", r.Header.Get("x-envoy-external-address"))
			if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
				slog.Error("errore recording rate limit", "error", err)
			}
			respondError(w, "accesso negato: certificato mTLS richiesto per questo ruolo", http.StatusForbidden)
			return
		}
	} else {
		// 2. Controllo CN == username (case-insensitive)
		if !strings.EqualFold(cn, req.Username) {
			slog.Warn("login fallito: mismatch CN-Username", "cn", cn, "username", user.Username, "role", user.Role, "src_ip", r.Header.Get("x-envoy-external-address"))
			if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
				slog.Error("errore recording rate limit", "error", err)
			}
			respondError(w, "accesso negato: certificato non corrisponde all'utente", http.StatusForbidden)
			return
		}
		// 3. Controllo OU (nel certificato) == Role (nel database) (case-insensitive)
		if !strings.EqualFold(ou, user.Role) {
			slog.Warn("login fallito: mismatch OU-Role", "ou", ou, "username", user.Username, "role", user.Role, "src_ip", r.Header.Get("x-envoy-external-address"))
			if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
				slog.Error("errore recording rate limit", "error", err)
			}
			respondError(w, "accesso negato: ruolo certificato non valido", http.StatusForbidden)
			return
		}
	}

	ok, err := crypto.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil || !ok {
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		slog.Warn("login fallito: password errata", "username", user.Username, "role", user.Role, "src_ip", r.Header.Get("x-envoy-external-address"))
		if err := api.RateLimits.RecordFailure(r.Context(), ip); err != nil {
			slog.Error("errore recording rate limit", "error", err)
		}
		return
	}

	// OTP a 6 cifre, hash HMAC-SHA256 (chiave = session token), TTL 5 min, max 3 tentativi
	otp, err := crypto.GenerateOTP()
	if err != nil {
		respondError(w, "errore generazione OTP", http.StatusInternalServerError)
		slog.Error("login: generate OTP", "error", err, "src_ip", r.Header.Get("x-envoy-external-address"))

		return
	}

	_ = api.RateLimits.ResetLimit(r.Context(), ip)

	sessionToken := newSessionToken()
	otpHash := crypto.HashOTP(otp, sessionToken)

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

	// Best-effort asincrono: l'invio SMTP non deve bloccare la risposta del
	// login. L'OTP è gia' salvato in DB, quindi anche se la mail fallisce
	// l'utente puo' ritentare.
	go func(to, code string) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("PANIC nell'invio mail OTP", "recover", r)
			}
		}()

		if api.Mail == nil {
			slog.Error("impossibile inviare mail: mailer non inizializzato (nil)")
			return
		}

		slog.Debug("tentativo invio mail OTP", "to", to)
		if err := api.Mail.SendOTP(to, code); err != nil {
			slog.Error("login: invio email OTP", "error", err, "to", to)
		}
	}(user.Email, otp)

	slog.Info("OTP emesso", "user_id", user.ID, "email", user.Email)
	ensureDeviceCookie(w, r)
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
