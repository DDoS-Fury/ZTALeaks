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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	Users      *db.UserRepository
	OTP        *db.OTPRepository
	Devices    *db.DeviceRepository
	RateLimits *db.RateLimitRepository
	JWT        *crypto.JWTManager
	Mail       *mailer.SMTPMailer
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

// hashOTP — HMAC-SHA256 dell'OTP con il session token come chiave/salt.
// L'OTP ha entropia bassa (6 cifre) ma vita breve (5 min, max 3 tentativi),
// quindi non serve un KDF lento tipo Argon2id. Usare il session token (192 bit
// random, uno per login) come chiave rende ogni hash unico per sessione: anche
// se il DB trapela, gli hash non sono attaccabili con rainbow table precalcolate.
func hashOTP(otp, sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte(otp))
	return hex.EncodeToString(mac.Sum(nil))
}

// compareOTP — confronto a tempo costante (hmac.Equal) tra l'OTP fornito e
// l'hash salvato, legato allo stesso session token usato in fase di login.
func compareOTP(otp, sessionToken, encoded string) bool {
	return hmac.Equal([]byte(hashOTP(otp, sessionToken)), []byte(encoded))
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
