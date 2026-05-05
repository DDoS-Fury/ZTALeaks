package crypto

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// In un ambiente di produzione questa chiave deve provenire da Vault o Variabili d'ambiente cifrate
	// Per ora è hardcoded come placeholder (Secure Enclave o Secret Manger dovrebbero fornirla)
	jwtSecretKey = []byte("ZTA-Secrets-Should-Be-Isolated")
	// Il tempo di validità è ridotto a 15 minuti come auspicato nelle configurazioni Zero Trust rigide.
	TokenValidDuration = 15 * time.Minute
)

// IdentityClaims rappresenta i claim (dati) inseriti e firmati nel token JWT.
type IdentityClaims struct {
	UserID             string `json:"sub"`
	Role               string `json:"role"`
	TwoFAVerified      bool   `json:"2fa_verified"`
	SecureEnclaveValid bool   `json:"secure_enclave_valid"`
	JA3Fingerprint     string `json:"ja3,omitempty"`
	jwt.RegisteredClaims
}

// GenerateJWT crea un nuovo token firmato HMAC-SHA256 con scadenza breve per le sessioni
func GenerateJWT(userID, role string, twoFAVerified bool, secureEnclave bool, ja3 string) (string, error) {
	now := time.Now()
	claims := IdentityClaims{
		UserID:             userID,
		Role:               role,
		TwoFAVerified:      twoFAVerified,
		SecureEnclaveValid: secureEnclave,
		JA3Fingerprint:     ja3,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenValidDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "identity-service.ztaleaks.local",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateJWT controlla l'integrità, la firma e la scadenza (oltre agli altri RegisteredClaims)
func ValidateJWT(tokenString string) (*IdentityClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(tokenString, &IdentityClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validazione del metodo di firma (deve essere HMAC) per evitare attacchi downgrade ('none' o 'RSA')
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("metodo di firma inatteso")
		}
		return jwtSecretKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return nil, err
	}

	// Estrazione dei claims se validi
	if claims, ok := parsedToken.Claims.(*IdentityClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("token invalido o scaduto")
}
