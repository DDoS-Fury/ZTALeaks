// Package handler contiene gli HTTP handler dell'identity-service.
//
// Tre flussi distinti, ciascuno in un file dedicato:
//   - register.go     POST /api/v1/auth/register
//   - login.go        POST /api/v1/auth/login        (genera OTP)
//   - verify_otp.go   POST /api/v1/auth/verify-otp   (rilascia JWT RS256)
//
// Le dipendenze condivise (repository + JWT manager + mailer) e gli helper
// di response/encoding stanno qui in handler.go cosi' nessun file di flusso
// si porta dietro stato globale.
package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/mailer"
)

// IdentityAPI raccoglie tutte le dipendenze degli handler.
type IdentityAPI struct {
	Users   *db.UserRepository
	OTP     *db.OTPRepository
	Devices *db.DeviceRepository
	JWT     *crypto.JWTManager
	Mail    *mailer.SMTPMailer
}

// generateOTP — 6 cifre random crittograficamente sicure.
func generateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// newSessionToken — token opaco da 192 bit per legare login → verify-otp.
func newSessionToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// hashOTP — SHA-256 dell'OTP. L'OTP ha gia' entropia bassa (6 cifre) ma vita
// breve (5 min, max 3 tentativi), quindi non serve un KDF lento tipo Argon2id:
// SHA-256 evita di mantenere il segreto in chiaro in DB senza pesare sul flusso.
func hashOTP(otp string) string {
	sum := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(sum[:])
}

// compareOTP — confronto a tempo costante tra l'OTP fornito e l'hash salvato.
func compareOTP(otp, encoded string) bool {
	return subtle.ConstantTimeCompare([]byte(hashOTP(otp)), []byte(encoded)) == 1
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "error", err)
	}
}

func respondError(w http.ResponseWriter, msg string, status int) {
	respondJSON(w, status, map[string]string{"error": msg})
}
