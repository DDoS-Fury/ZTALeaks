// =============================================================================
// Device Cookie — identificatore persistente del dispositivo (fallback no-TPM)
// Project: ZTALeaks - Identity Service
// =============================================================================
// Per i client senza TPM/WebAuthn il modello AI (schema v2, 4 nodi) ha bisogno
// di una key dispositivo stabile: un cookie persistente firmato HMAC-SHA256.
// La firma NON protegge dal furto del cookie (equivale al furto del device id,
// che il modello rileva come anomalia di binding); impedisce pero' a un client
// di forgiare device-key arbitrarie e inondare il NodeRegistry LRU del modello.
// Il segreto e' condiviso con la security-orchestrator, che verifica il cookie
// prima di usarlo come key_device ("ck:<uuid>").
// =============================================================================

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// DeviceCookieName e' il nome del cookie persistente del dispositivo.
const DeviceCookieName = "zta_device"

const deviceCookiePrefix = "v1"

func deviceCookieSign(id string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(deviceCookiePrefix + "." + id))
	return hex.EncodeToString(mac.Sum(nil))
}

// NewDeviceCookieValue genera un nuovo valore "v1.<uuid-hex>.<hmac-hex>".
func NewDeviceCookieValue(secret []byte) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("device cookie: random id: %w", err)
	}
	id := hex.EncodeToString(b)
	return deviceCookiePrefix + "." + id + "." + deviceCookieSign(id, secret), nil
}

// VerifyDeviceCookieValue valida formato e firma; ritorna l'uuid del device.
func VerifyDeviceCookieValue(value string, secret []byte) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != deviceCookiePrefix || parts[1] == "" {
		return "", false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(deviceCookieSign(parts[1], secret))) {
		return "", false
	}
	return parts[1], true
}
