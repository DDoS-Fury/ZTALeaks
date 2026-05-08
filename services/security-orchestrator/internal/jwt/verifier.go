// =============================================================================
// JWT Verifier — Pulls JWKS from identity-service and verifies RS256 tokens
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Identity firma con la chiave privata, orchestrator verifica con la chiave
// pubblica scaricata dal JWKS endpoint. Cache della JWKS per 5 min.
// =============================================================================

package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	jwksCacheTTL = 5 * time.Minute
	expectedAlg  = "RS256"
)

// ZTAClaims rispecchia la struct in identity-service/internal/crypto/jwt.go.
// I tag json devono coincidere perché lo unmarshal va a fattore di nome.
type ZTAClaims struct {
	UserID         string `json:"sub"`
	Role           string `json:"role"`
	ClearanceLevel string `json:"clearance_level"`
	MFAVerified    bool   `json:"mfa_verified"`
	DeviceID       string `json:"device_id,omitempty"`
	JA3            string `json:"ja3,omitempty"`
	jwtlib.RegisteredClaims
}

// Verifier scarica e cacheca la chiave pubblica dell'identity-service.
type Verifier struct {
	jwksURL    string
	httpClient *http.Client

	mu          sync.RWMutex
	keysByKID   map[string]*rsa.PublicKey
	cachedAt    time.Time
}

// NewVerifier costruisce un verifier che carica le chiavi su prima richiesta.
func NewVerifier(jwksURL string) *Verifier {
	return &Verifier{
		jwksURL:    jwksURL,
		httpClient: &http.Client{Timeout: 3 * time.Second},
		keysByKID:  make(map[string]*rsa.PublicKey),
	}
}

// Verify parsa il token, recupera la chiave pubblica via kid header e verifica.
func (v *Verifier) Verify(tokenStr string) (*ZTAClaims, error) {
	token, err := jwtlib.ParseWithClaims(tokenStr, &ZTAClaims{}, func(t *jwtlib.Token) (interface{}, error) {
		if t.Method.Alg() != expectedAlg {
			return nil, fmt.Errorf("alg inatteso: %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid mancante nell'header")
		}
		return v.getKey(kid)
	}, jwtlib.WithValidMethods([]string{expectedAlg}))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*ZTAClaims)
	if !ok || !token.Valid {
		return nil, errors.New("claims invalidi")
	}
	return claims, nil
}

// getKey restituisce la chiave RSA per kid, refreshing la cache se necessario.
func (v *Verifier) getKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	if time.Since(v.cachedAt) < jwksCacheTTL {
		if k := v.keysByKID[kid]; k != nil {
			v.mu.RUnlock()
			return k, nil
		}
	}
	v.mu.RUnlock()

	if err := v.refresh(); err != nil {
		return nil, fmt.Errorf("refresh JWKS: %w", err)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	k := v.keysByKID[kid]
	if k == nil {
		return nil, fmt.Errorf("kid %q non trovato in JWKS", kid)
	}
	return k, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (v *Verifier) refresh() error {
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var doc jwks
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	v.mu.Lock()
	v.keysByKID = keys
	v.cachedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
