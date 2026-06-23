// Package webauthn implementa una cerimonia FIDO2 lab-grade per l'enrollment
// del TPM e il login con device gia' registrato.
//
//	register.go — POST /auth/register/{begin,finish}: enrolla un nuovo device
//	login.go    — POST /auth/login/{begin,finish}: autentica con device noto
//	handler.go  — Handler struct + helper di response/encoding condivisi
//
// In un'implementazione production-grade la /finish dovrebbe verificare:
//   - hash di clientDataJSON con la challenge attesa
//   - signature su (authenticatorData ++ clientDataHash) con la public_key
//   - attestation object CBOR-decodificato
//
// Per il lab consideriamo sufficiente la presenza della challenge in DB e
// lasciamo la verify cryptografica come hook futuro.
package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/mailer"
)

// Handler raggruppa le dipendenze delle cerimonie WebAuthn.
//
// Niente JWTManager qui: l'identita' dell'utente per /register/begin arriva
// dall'header X-Current-User iniettato dalla security-orchestrator (che e'
// l'unica responsabile della verifica del JWT, via JWKS dell'iam-service).
type Handler struct {
	users      *db.UserRepository
	devices    *db.DeviceRepository
	challenges *db.ChallengeRepository
	OTP        *db.OTPRepository
	Mail       *mailer.SMTPMailer
}

func NewHandler(users *db.UserRepository, devices *db.DeviceRepository, challenges *db.ChallengeRepository, otp *db.OTPRepository, mail *mailer.SMTPMailer) *Handler {
	return &Handler{users: users, devices: devices, challenges: challenges, OTP: otp, Mail: mail}
}

// newSessionID — token opaco da 128 bit per legare /begin → /finish.
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// newChallenge — challenge random da 256 bit, base64url senza padding.
func newChallenge() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
