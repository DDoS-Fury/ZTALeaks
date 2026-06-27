package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"os"
)

// signCurrentUser firma lo userID per l'header X-Current-User inoltrato
// upstream (iam-service / business-logic). Solo l'orchestrator conosce il
// secret condiviso: gli upstream validano l'HMAC e rifiutano un header
// spoofato da un peer che li raggiunga bypassando l'orchestrator.
//
// Formato: "<userID>.<base64url(HMAC_SHA256(secret, userID))>".
func signCurrentUser(userID string) string {
	mac := hmac.New(sha256.New, userHeaderSecret)
	mac.Write([]byte(userID))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return userID + "." + sig
}

var userHeaderSecret = loadUserHeaderSecret()

func loadUserHeaderSecret() []byte {
	if v := os.Getenv("ORCH_IAM_SHARED_SECRET"); v != "" {
		return []byte(v)
	}
	slog.Warn("ORCH_IAM_SHARED_SECRET non impostato, uso un default da lab (NON usare in produzione)")
	return []byte("ztaleaks-dev-ORCH_IAM_SHARED_SECRET")
}
