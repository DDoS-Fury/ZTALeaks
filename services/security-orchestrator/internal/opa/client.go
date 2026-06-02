// =============================================================================
// OPA HTTP Client — costruisce input arricchito e chiama il PDP
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Input passati a OPA per ogni decisione:
//   {
//     request: {method, path, headers},
//     claims:  {sub, role, clearance_level, mfa_verified, device_id, ja3},
//     cert_present, cert_subject,
//     tpm_verified,
//     zone_id,
//     ai:      {score, confidence}            (opt, da microservizio AI)
//     context: {timestamp, hour_of_day,        (opt, per fallback Rego e
//               day_of_week, session_age_seconds, audit/dataset training)
//               client_ip}
//     ja3:     {md5}                          (opt; trust_level rimandato)
//   }
// La policy decide tier (cert+tpm / cert / none), ruolo↔rotta,
// clearance↔risorsa, applica risk_bucket (sezione 6) e ritorna allow.
// =============================================================================

package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Client struct {
	url        string
	httpClient *http.Client
}

func New() *Client {
	url := os.Getenv("OPA_URL")
	if url == "" {
		url = "http://opa:8181/v1/data/envoy/authz"
	}
	return &Client{
		url:        url,
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}
}

// Input è la struttura JSON serializzata e mandata a OPA.
type Input struct {
	Request     Request        `json:"request"`
	Claims      map[string]any `json:"claims"`
	CertPresent bool           `json:"cert_present"`
	CertSubject string         `json:"cert_subject,omitempty"`
	TPMVerified bool           `json:"tpm_verified"`
	ZoneID      string         `json:"zone_id,omitempty"`
	AI          *AI            `json:"ai,omitempty"`
	Context     *Context       `json:"context,omitempty"`
	JA3         *JA3           `json:"ja3,omitempty"`
}

type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

// AI ripiega il risultato del microservizio AI. Confidence "low" segnala
// alla policy che deve usare il fallback Rego.
type AI struct {
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
}

// Context raccoglie segnali temporali/di rete usati sia dall'AI come feature
// sia dal fallback in policy.rego quando l'AI non risponde.
type Context struct {
	Timestamp         string `json:"timestamp"`
	HourOfDay         int    `json:"hour_of_day"`
	DayOfWeek         int    `json:"day_of_week"`
	SessionAgeSeconds int64  `json:"session_age_seconds"`
	ClientIP          string `json:"client_ip,omitempty"`
}

// JA3 viene passato strutturato cosi' che il modello AI lo trovi come feature
// del grafo. Il campo trust_level (known/unknown/suspicious) sara' aggiunto
// in un commit dedicato dopo la decisione sul source-of-truth (Security DB).
type JA3 struct {
	MD5 string `json:"md5,omitempty"`
}

// Evaluate fa POST a OPA e ritorna il bool di allow.
func (c *Client) Evaluate(ctx context.Context, in Input) (bool, error) {
	payload := map[string]any{"input": in}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA HTTP %d", resp.StatusCode)
	}
	var out struct {
		Result struct {
			Allow bool `json:"allow"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Result.Allow, nil
}
