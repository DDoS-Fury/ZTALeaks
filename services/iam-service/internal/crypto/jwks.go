package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// JWK rappresenta una chiave pubblica RSA in formato JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS è un set di chiavi (RFC 7517). Identity ne pubblica una sola alla volta
// (la chiave ephemeral generata a startup).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSHandler espone GET /.well-known/jwks.json. La security-orchestrator
// scarica questo JSON e lo usa per verificare le firme dei JWT.
func JWKSHandler(m *JWTManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwk := publicKeyToJWK(m.PublicKey(), m.KeyID())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{jwk}})
	}
}

func publicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	// N = modulus base64url senza padding
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// E = exponent big-endian senza zeri leading, base64url senza padding
	eBytes := bigIntBytesNoLeadingZeros(pub.E)
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   n,
		E:   e,
	}
}

func bigIntBytesNoLeadingZeros(n int) []byte {
	// L'esponente RSA tipico è 65537 → 3 byte 0x010001
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}
