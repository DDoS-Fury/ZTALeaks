package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// UserHeaderMiddleware valida l'HMAC dell'header X-Current-User firmato dalla
// security-orchestrator e lo riscrive al solo userID per gli handler a valle
// (logging, audit, api). Chiude il vettore di spoof dell'identità per un peer
// che raggiunga business-logic bypassando l'orchestrator.
//
//   - header assente  → pass-through (pagine pubbliche anonime)
//   - header valido    → riscritto a userID nudo
//   - header invalido  → 401
func UserHeaderMiddleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signed := r.Header.Get("X-Current-User")
			if signed == "" {
				next.ServeHTTP(w, r)
				return
			}
			userID, ok := verifyUserHeader(secret, signed)
			if !ok {
				http.Error(w, "invalid authenticated user", http.StatusUnauthorized)
				slog.Error("X-Current-User HMAC non valido", "path", r.URL.Path)
				return
			}
			r.Header.Set("X-Current-User", userID)
			next.ServeHTTP(w, r)
		})
	}
}

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

// LoadUserHeaderSecret legge il secret condiviso con l'orchestrator.
func LoadUserHeaderSecret() []byte {
	if v := os.Getenv("ORCH_IAM_SHARED_SECRET"); v != "" {
		return []byte(v)
	}
	slog.Warn("ORCH_IAM_SHARED_SECRET non impostato, uso un default da lab (NON usare in produzione)")
	return []byte("ztaleaks-dev-ORCH_IAM_SHARED_SECRET")
}
