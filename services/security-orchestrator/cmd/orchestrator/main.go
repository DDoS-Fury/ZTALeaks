package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// OPARequest rappresenta il payload JSON che inviamo ad OPA
type OPARequest struct {
	Input map[string]interface{} `json:"input"`
}

// OPAResponse rappresenta la risposta JSON di OPA
// Supponiamo che la policy restituisca un booleano in `result` (es. default allow = false)
type OPAResponse struct {
	Result bool `json:"result"`
}

// getAIRiskScore simula una chiamata al modello AI
func getAIRiskScore(ctx context.Context, userID string) (float64, error) {
	// Simuliamo un minimo di latenza di rete (es. 50ms)
	time.Sleep(50 * time.Millisecond)

	// Per ora restituiamo sempre 0.2 fisso
	return 0.2, nil
}

// askOPA esegue la chiamata HTTP verso OPA
func askOPA(ctx context.Context, opaURL string, payload OPARequest) (bool, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("errore encoding JSON per OPA: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opaURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("errore creazione richiesta per OPA: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Usiamo un client HTTP custom con timeout per non bloccare l'orchestratore
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("errore chiamata HTTP ad OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA ha risposto con status code: %d", resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var opaResp OPAResponse
	if err := json.Unmarshal(bodyBytes, &opaResp); err != nil {
		return false, fmt.Errorf("errore decoding risposta OPA: %w", err)
	}

	return opaResp.Result, nil
}

// --- MAIN ---

func main() {
	logDir := "/var/log/ztaleaks/orchestrator"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Impossibile creare directory dei log: %v\n", err)
	}

	logFilePath := filepath.Join(logDir, "app.jsonl")
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Impossibile aprire file dei log: %v\n", err)
	}

	var logWriter io.Writer
	if err == nil {
		logWriter = io.MultiWriter(os.Stdout, logFile)
	} else {
		logWriter = os.Stdout
	}

	logger := slog.New(slog.NewJSONHandler(logWriter, nil))
	slog.SetDefault(logger)

	// Inizializza file log per OPA Decision Logs
	opaLogFilePath := filepath.Join(logDir, "opa_decision.jsonl")
	opaLogFile, err := os.OpenFile(opaLogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Impossibile aprire file dei log per OPA: %v\n", err)
	}

	port := os.Getenv("SECURITY_ORCHESTRATOR_PORT")
	if port == "" {
		port = "8081"
	}

	// URL di default di OPA (puoi sovrascriverla con una variabile d'ambiente)
	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		// Endpoint tipico per valutare una regola 'allow' nel package 'envoy.authz'
		opaURL = "http://opa:8181/v1/data/envoy/authz/allow"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	// Handler per i log di decisione OPA
	mux.HandleFunc("/api/v1/opa/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				slog.Error("Errore decodifica gzip log OPA", "error", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			reader = gz
		}

		var logs []interface{}
		if err := json.NewDecoder(reader).Decode(&logs); err != nil {
			slog.Error("Errore decodifica JSON log OPA", "error", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		for _, logEntry := range logs {
			b, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}
			b = append(b, '\n')
			if opaLogFile != nil {
				opaLogFile.Write(b)
			}
		}

		w.WriteHeader(http.StatusOK)
	})

	evalHandler := func(w http.ResponseWriter, r *http.Request) {
		// 1. (Simulato) Estrai identificativo utente, IP, ecc. dalla richiesta
		userID := "user-123"

		// 2. Interroga il modello AI
		riskScore, err := getAIRiskScore(r.Context(), userID)
		if err != nil {
			slog.Error("Errore calcolo rischio AI", "error", err)
			http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			return
		}
		slog.Info("Rischio calcolato", "user", userID, "risk_score", riskScore)

		// Tenta di estrarre il path originale dagli header inseriti da Envoy (ext_authz http_service)
		originalPath := r.Header.Get("X-Authz-Request-Path")
		if originalPath == "" {
			originalPath = r.Header.Get("X-Original-Uri")
		}
		if originalPath == "" {
			originalPath = r.URL.Path // Fallback
		}
		slog.Info("Valutazione rotta", "path", originalPath, "method", r.Method)

		// Prepara l'input combinato per OPA
		opaInput := OPARequest{
			Input: map[string]interface{}{
				"risk_score": riskScore,
				"attributes": map[string]interface{}{
					"request": map[string]interface{}{
						"http": map[string]interface{}{
							"method": r.Method, // Envoy invia il metodo originale in X-Authz-Request-Method di solito
							"path":   originalPath,
						},
					},
				},
			},
		}

		// 4. Interroga OPA
		isAllowed, err := askOPA(r.Context(), opaURL, opaInput)
		if err != nil {
			slog.Error("Errore comunicazione con OPA", "error", err)
			// Fail-safe: se OPA è irraggiungibile, neghiamo l'accesso
			http.Error(w, `{"allowed": false, "reason": "policy engine unavailable"}`, http.StatusServiceUnavailable)
			return
		}

		slog.Info("Decisione OPA", "allowed", isAllowed)

		// 5. Restituisci il verdetto al chiamante (es. Envoy)
		w.Header().Set("Content-Type", "application/json")
		if isAllowed {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"allowed": true}`))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"allowed": false, "reason": "policy denied"}`))
		}
	}
	
	mux.HandleFunc("/api/v1/evaluate", evalHandler)
	mux.HandleFunc("/api/v1/evaluate/", evalHandler)

	// In Envoy's HTTP ext_authz, the original path and method are preserved by default.
	// Therefore, we register evalHandler as the catch-all to evaluate all incoming requests.
	mux.HandleFunc("/", evalHandler)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("Avvio del server Security Orchestrator", "port", port, "opa_url", opaURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Errore critico del server", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Avvio graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Errore durante lo shutdown", "error", err)
	}
	slog.Info("Server spento correttamente")
}
