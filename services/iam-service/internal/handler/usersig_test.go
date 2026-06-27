package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// sign replica esattamente il formato prodotto dalla security-orchestrator
// (internal/handler/usersig.go: signCurrentUser). Se i due formati divergono,
// questo test fallisce — guardia contro la rottura del trust boundary.
func sign(secret []byte, userID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(userID))
	return userID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyUserHeader(t *testing.T) {
	secret := []byte("ztaleaks-dev-ORCH_IAM_SHARED_SECRET")
	const userID = "507f1f77bcf86cd799439011"

	signed := sign(secret, userID)
	if got, ok := verifyUserHeader(secret, signed); !ok || got != userID {
		t.Fatalf("valid header rejected: got=%q ok=%v", got, ok)
	}

	bad := []string{
		"",                            // assente
		userID,                        // senza firma
		userID + ".",                  // firma vuota
		userID + ".deadbeef",          // firma errata
		sign([]byte("other"), userID), // secret diverso (spoof)
		"attacker." + signed[len(userID)+1:], // userID manomesso, firma riusata
	}
	for _, b := range bad {
		if _, ok := verifyUserHeader(secret, b); ok {
			t.Errorf("invalid header accepted: %q", b)
		}
	}
}
