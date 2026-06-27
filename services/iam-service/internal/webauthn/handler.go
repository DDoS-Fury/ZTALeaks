// Package webauthn implementa le cerimonie FIDO2/WebAuthn (enrollment del
// device TPM e login con device registrato) sopra la libreria standard
// github.com/go-webauthn/webauthn.
//
//	register.go — POST /auth/register/{begin,finish}: enrolla un nuovo device
//	login.go    — POST /auth/login/{begin,finish}: autentica con device noto
//	handler.go  — Handler struct + helper condivisi
//
// La verifica crittografica reale (hash di clientDataJSON sulla challenge,
// firma su authenticatorData++clientDataHash con la chiave pubblica registrata,
// attestation object CBOR-decodificato e clone-counter) è interamente delegata
// a go-webauthn nelle Finish*.
package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"

	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/mailer"
)

// Handler raggruppa le dipendenze delle cerimonie WebAuthn.
//
// Niente JWTManager qui: l'identita' dell'utente per /register/begin arriva
// dall'header X-Current-User iniettato (e firmato in HMAC) dalla
// security-orchestrator e validato dal middleware prima di arrivare qui.
type Handler struct {
	users      *db.UserRepository
	devices    *db.DeviceRepository
	challenges *db.ChallengeRepository
	OTP        *db.OTPRepository
	Mail       *mailer.SMTPMailer

	wa         *webauthn.WebAuthn
	rateLimits *db.RateLimitRepository
	enumSecret []byte
}

func NewHandler(
	users *db.UserRepository,
	devices *db.DeviceRepository,
	challenges *db.ChallengeRepository,
	otp *db.OTPRepository,
	mail *mailer.SMTPMailer,
	wa *webauthn.WebAuthn,
	rateLimits *db.RateLimitRepository,
	enumSecret []byte,
) *Handler {
	return &Handler{
		users:      users,
		devices:    devices,
		challenges: challenges,
		OTP:        otp,
		Mail:       mail,
		wa:         wa,
		rateLimits: rateLimits,
		enumSecret: enumSecret,
	}
}

// newSessionID — token opaco da 128 bit che lega /begin → /finish.
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// clientIP estrae l'IP del client per il rate-limit. Dietro Envoy l'indirizzo
// reale arriva in x-envoy-external-address (coerente con internal/handler/login.go);
// RemoteAddr è il fallback.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("x-envoy-external-address"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
