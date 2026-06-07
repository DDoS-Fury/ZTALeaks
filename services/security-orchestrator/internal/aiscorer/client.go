// =============================================================================
// AI Scorer Client — chiama il microservizio di anomaly detection
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Il microservizio TGN valuta le richieste ricostruendo il grafo storico.
// Implementa il flusso Anti-Poisoning in due step:
// 1. Infer() valuta lo score (sola lettura).
// 2. OPA decide.
// 3. Se ALLOW, Update() committa l'evento nella memoria del modello.
// =============================================================================

package aiscorer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// ScoreResp e' il risultato della valutazione AI (restituito da /infer o /score).
type ScoreResp struct {
	AnomalyScore float64 `json:"anomaly_score"`
	IsAnomaly    bool    `json:"is_anomaly"`
	Threshold    float64 `json:"threshold"`
}

// Score incapsula la risposta del modello e la confidence della chiamata di rete.
type Score struct {
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
}

// Event rappresenta la tupla da inviare al modello TGN.
type Event struct {
	KeySrc    string    `json:"key_src"`
	KeyDst    string    `json:"key_dst"`
	Timestamp int64     `json:"timestamp"`
	Features  []float64 `json:"features"`
	SrcFeat   []float64 `json:"src_feat,omitempty"`
	DstFeat   []float64 `json:"dst_feat,omitempty"`
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

// post effettua la chiamata HTTP.
func (c *Client) post(ctx context.Context, path string, in any, out any) error {
	if c.url == "" {
		return fmt.Errorf("AI_SCORER_URL non configurato")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal fallito: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request fallita: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("chiamata HTTP fallita: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode fallito: %w", err)
		}
	}
	return nil
}

// Infer chiama il microservizio in modalita' sola lettura (/infer) per ottenere lo score.
func (c *Client) Infer(ctx context.Context, event Event) Score {
	if c.url == "" {
		return Score{Score: 0.99, Confidence: ConfidenceLow}
	}
	var s ScoreResp
	if err := c.post(ctx, "/infer", event, &s); err != nil {
		slog.Warn("ai-scorer: infer fallito (timeout o rete)", "error", err)
		return Score{Score: 0.99, Confidence: ConfidenceLow}
	}
	return Score{Score: s.AnomalyScore, Confidence: ConfidenceHigh}
}

// Update committa un evento nel modello chiamando /update.
func (c *Client) Update(ctx context.Context, event Event) error {
	if c.url == "" {
		return nil
	}
	err := c.post(ctx, "/update", event, nil)
	if err != nil {
		slog.Warn("ai-scorer: update fallito", "error", err)
	}
	return err
}
