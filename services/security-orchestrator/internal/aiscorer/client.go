// =============================================================================
// AI Scorer Client — chiama il microservizio di anomaly detection
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Il microservizio (separato, in arrivo) e' un anomaly detector graph-based
// che ricostruisce il pattern di richieste dell'utente e restituisce uno
// score [0, 0.99]: piu' alto = piu' anomalo. Lo score viene poi consumato
// da policy.rego (sezione 6) come threshold per la decisione.
//
// In caso di errore/timeout/URL non configurato → confidence "low" e score 0.
// La policy in Rego attivera' il fallback deterministico basato sul contesto.
// =============================================================================

package aiscorer

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const defaultTimeout = 5 * time.Second

// Confidence dell'evaluation: "high" se il modello ha risposto, "low" altrimenti.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// Score e' il risultato della valutazione AI.
type Score struct {
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
}

// Features sono le feature inviate al microservizio per la singola richiesta.
// Il modello accumulera' la sequenza per user_id costruendo il grafo lato AI.
type Features struct {
	UserID    string `json:"user_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Timestamp string `json:"timestamp"`
	HourOfDay int    `json:"hour_of_day"`
	DayOfWeek int    `json:"day_of_week"`
	JA3       string `json:"ja3,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
}

// Client e' il client HTTP verso ai-scorer. Url vuoto → fallback immediato.
type Client struct {
	url        string
	httpClient *http.Client
}

func New() *Client {
	return &Client{
		url:        os.Getenv("AI_SCORER_URL"),
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// Evaluate chiama il microservizio. Su qualsiasi problema (env mancante,
// timeout, HTTP non-200, JSON malformato) ritorna confidence "low" e score 0.
func (c *Client) Evaluate(ctx context.Context, f Features) Score {
	if c.url == "" {
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	body, err := json.Marshal(f)
	if err != nil {
		slog.Warn("ai-scorer: marshal fallito", "error", err)
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("ai-scorer: request fallita", "error", err)
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Warn("ai-scorer: chiamata fallita (timeout o rete)", "error", err)
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("ai-scorer: HTTP non OK", "status", resp.StatusCode)
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	var out struct {
		Score float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		slog.Warn("ai-scorer: decode fallito", "error", err)
		return Score{Score: 0, Confidence: ConfidenceLow}
	}
	return Score{Score: out.Score, Confidence: ConfidenceHigh}
}
