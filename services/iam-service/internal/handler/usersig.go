package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
)

// Trust boundary su X-Current-User.
//
// La security-orchestrator è l'unica a conoscere il secret condiviso e firma
// l'header come "<userID>.<base64url(HMAC_SHA256(secret, userID))>". Senza
// questa validazione un qualunque peer di rete potrebbe raggiungere
// direttamente l'iam-service (bypassando l'orchestrator) e spoofare l'identità
// per enrollare un device su un account arbitrario.
//
// Il middleware valida la firma e, in caso di successo, riscrive l'header al
// solo userID: gli handler a valle (es. BeginRegistration) restano invariati.

// VerifyUserHeader ritorna un middleware che valida l'HMAC di X-Current-User.
func VerifyUserHeader(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signed := r.Header.Get("X-Current-User")
			userID, ok := verifyUserHeader(secret, signed)
			if !ok {
				http.Error(w, "invalid or missing authenticated user", http.StatusUnauthorized)
				slog.Error("X-Current-User HMAC non valido", "path", r.URL.Path)
				return
			}
			r.Header.Set("X-Current-User", userID)
			next.ServeHTTP(w, r)
		})
	}
}

// verifyUserHeader valida "<userID>.<sig>" e ritorna lo userID se l'HMAC torna.
func verifyUserHeader(secret []byte, signed string) (string, bool) {
	i := strings.LastIndexByte(signed, '.')
	if i <= 0 || i == len(signed)-1 {
		return "", false
	}
	userID, sig := signed[:i], signed[i+1:]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(userID))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "", false
	}
	return userID, true
}
