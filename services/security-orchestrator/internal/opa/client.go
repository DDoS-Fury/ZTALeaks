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
//     zone_id
//   }
// La policy (step 3) deciderà tier (cert+tpm / cert / none), ruolo↔rotta,
// clearance↔risorsa e restituirà bool su `data.envoy.authz.allow`.
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
		url = "http://opa:8181/v1/data/envoy/authz/allow"
	}
	return &Client{
		url:        url,
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}
}

// Input è la struttura JSON serializzata e mandata a OPA.
type Input struct {
	Request      Request          `json:"request"`
	Claims       map[string]any   `json:"claims"`
	CertPresent  bool             `json:"cert_present"`
	CertSubject  string           `json:"cert_subject,omitempty"`
	TPMVerified  bool             `json:"tpm_verified"`
	ZoneID       string           `json:"zone_id,omitempty"`
}

type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
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
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Result, nil
}
