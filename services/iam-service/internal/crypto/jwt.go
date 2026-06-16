// =============================================================================
// JWT Package — RS256 token issuance + JWKS exposure
// Project: ZTALeaks - Identity Service (mix-master-zta-core split)
// =============================================================================
// Identity firma con la chiave privata. La chiave pubblica è pubblicata sul
// JWKS endpoint /.well-known/jwks.json: la security-orchestrator la scarica e
// verifica il token *senza* shared secret. Validità access token: 15 min.
// =============================================================================

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	// AccessTokenTTL — JWT di accesso. 15 minuti per minimizzare la finestra
	// di esposizione in caso di leak (Zero Trust).
	AccessTokenTTL = 15 * time.Minute

	// Issuer del token — usato anche da security-orchestrator per rifiutare
	// token firmati da emettitori diversi.
	Issuer = "iam-service.ztaleaks.local"
)

// ZTAClaims è il payload firmato del JWT. La struttura è condivisa
// (per parsing) anche dalla security-orchestrator.
type ZTAClaims struct {
	UserID         string `json:"sub"`
	Role           string `json:"role"`
	ClearanceLevel string `json:"clearance_level"`
	MFAVerified    bool   `json:"mfa_verified"`
	DeviceID       string `json:"device_id,omitempty"`
	JA3            string `json:"ja3,omitempty"`
	jwtlib.RegisteredClaims
}

// JWTManager incapsula la coppia di chiavi RSA usata per firmare i token.
// La chiave è ephemeral (rigenerata a ogni avvio dell'iam-service).
// Conseguenza: i token emessi prima del restart vengono invalidati. Per il
// lab è accettabile; in produzione la chiave andrebbe persistita o caricata
// da Vault/KMS.
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewJWTManager genera una nuova coppia RSA-2048 e calcola il key ID
// come SHA-256 del DER della chiave pubblica (primi 16 byte hex).
func NewJWTManager() (*JWTManager, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa generate: %w", err)
	}
	pub := &priv.PublicKey

	// Key ID derivato dalla chiave pubblica (deterministico, no random)
	hash := sha256.Sum256(append(pub.N.Bytes(), 1, 0, 1))
	kid := hex.EncodeToString(hash[:8])

	return &JWTManager{
		privateKey: priv,
		publicKey:  pub,
		keyID:      kid,
	}, nil
}

// Issue firma un access token RS256 con i claim ZTA + RegisteredClaims standard.
func (m *JWTManager) Issue(userID, role, clearance, deviceID, ja3 string, mfaVerified bool) (string, error) {
	now := time.Now()
	claims := ZTAClaims{
		UserID:         userID,
		Role:           role,
		ClearanceLevel: clearance,
		MFAVerified:    mfaVerified,
		DeviceID:       deviceID,
		JA3:            ja3,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        generateJTI(),
			Issuer:    Issuer,
			Subject:   userID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(AccessTokenTTL)),
		},
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID

	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("jwt sign: %w", err)
	}
	return signed, nil
}

// PublicKey restituisce la chiave pubblica RSA (per JWKS).
func (m *JWTManager) PublicKey() *rsa.PublicKey {
	return m.publicKey
}

// KeyID restituisce il kid usato negli header dei token e nel JWKS.
func (m *JWTManager) KeyID() string {
	return m.keyID
}

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
