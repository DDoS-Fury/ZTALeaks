package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Il cookie dispositivo "zta_device" (valore "v1.<uuid-hex>.<hmac-hex>") e'
// emesso dall'iam-service e firmato HMAC-SHA256 con il segreto condiviso
// DEVICE_COOKIE_SECRET. Formato e firma devono restare allineati a
// services/iam-service/internal/crypto/devicecookie.go. La verifica qui
// impedisce a un client di forgiare device-key arbitrarie e inondare il
// NodeRegistry LRU del modello AI: un cookie non valido viene ignorato.
const (
	deviceCookieName   = "zta_device"
	deviceCookiePrefix = "v1"
)

var (
	deviceCookieSecretOnce sync.Once
	deviceCookieSecretVal  []byte
)

func deviceCookieSecret() []byte {
	deviceCookieSecretOnce.Do(func() {
		s := os.Getenv("DEVICE_COOKIE_SECRET")
		if s == "" {
			s = "ztaleaks-dev-device-cookie-secret"
			slog.Warn("DEVICE_COOKIE_SECRET non impostato: uso il default di sviluppo")
		}
		deviceCookieSecretVal = []byte(s)
	})
	return deviceCookieSecretVal
}

// deviceIDFromCookie estrae e verifica l'uuid del dispositivo dal cookie.
// Ritorna ("", false) se il cookie manca o la firma non torna.
func deviceIDFromCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(deviceCookieName)
	if err != nil {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || parts[0] != deviceCookiePrefix || parts[1] == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, deviceCookieSecret())
	mac.Write([]byte(deviceCookiePrefix + "." + parts[1]))
	if !hmac.Equal([]byte(parts[2]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return "", false
	}
	return parts[1], true
}
