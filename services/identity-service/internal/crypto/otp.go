package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenerateOTP genera 6 cifre random crittograficamente sicure.
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// HashOTP genera HMAC-SHA256 dell'OTP con il session token come chiave/salt.
func HashOTP(otp, sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte(otp))
	return hex.EncodeToString(mac.Sum(nil))
}

// CompareOTP esegue un confronto a tempo costante (hmac.Equal) tra l'OTP fornito e l'hash salvato.
func CompareOTP(otp, sessionToken, encoded string) bool {
	return hmac.Equal([]byte(HashOTP(otp, sessionToken)), []byte(encoded))
}
