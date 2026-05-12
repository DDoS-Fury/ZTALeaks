// =============================================================================
// Security Orchestrator — PDP coordinator (PEP-side ext_authz target)
// Project: ZTALeaks - mix-master-zta-core split architecture
// =============================================================================
// Responsabilità (per direttive del compagno):
//   - verificare il token JWT (scarica la pubkey via JWKS da identity-service)
//   - verificare TPM via security-db (lookup read-only su device_fingerprints)
//   - controllare il certificato client (header forwarded da Envoy)
//   - costruire input arricchito e chiamare OPA per la decisione finale
// =============================================================================

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ztaleaks/security-orchestrator/internal/db"
	"ztaleaks/security-orchestrator/internal/handler"
	jwtpkg "ztaleaks/security-orchestrator/internal/jwt"
	"ztaleaks/security-orchestrator/internal/opa"
	"ztaleaks/security-orchestrator/internal/tpm"
)

func main() {
	logDir := "/var/log/ztaleaks/orchestrator"
	_ = os.MkdirAll(logDir, 0755)

	// JSON logger su file + stdout per Splunk forwarding
	var logWriter io.Writer = os.Stdout
	if f, err := os.OpenFile(filepath.Join(logDir, "app.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logWriter = io.MultiWriter(os.Stdout, f)
	}
	// Pre-popola l'attributo `service` sul default logger: ogni slog.X in
	// tutto il package erediter automaticamente la provenienza.
	slog.SetDefault(slog.New(slog.NewJSONHandler(logWriter, nil)).With("service", "security-orchestrator"))

	port := getenv("SECURITY_ORCHESTRATOR_PORT", "8081")

	// File log dedicato per le decision-logs di OPA (preservato dal master)
	opaLogPath := filepath.Join(logDir, "opa_decision.jsonl")
	opaLogFile, _ := os.OpenFile(opaLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	// --- Wiring dei moduli ---
	ctx := context.Background()
	mongoClient, err := db.Connect(ctx)
	if err != nil {
		slog.Error("connessione security-db fallita", "error", err)
		os.Exit(1)
	}
	defer mongoClient.Disconnect()

	jwksURL := getenv("IDENTITY_JWKS_URL", "http://identity-service:8082/.well-known/jwks.json")
	verifier := jwtpkg.NewVerifier(jwksURL)
	tpmLookup := tpm.New(mongoClient.DB())
	usersColl := mongoClient.DB().Collection("identity_users")
	opaClient := opa.New()

	// --- HTTP routes ---
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"security-orchestrator"}`))
	})

	// Decision logs ricevuti da OPA (--set=services.orchestrator...) — preservato
	mux.HandleFunc("POST /api/v1/opa/logs", handler.OPALogsHandler(opaLogFile))

	// ext_authz endpoint chiamato da Envoy
	evaluate := handler.BuildEvaluateHandler(verifier, tpmLookup, usersColl, opaClient)
	mux.HandleFunc("/api/v1/evaluate", evaluate)
	mux.HandleFunc("/api/v1/evaluate/", evaluate)
	// Envoy con http_service ext_authz inoltra il path originale come parte
	// dell'URL — usiamo "/" come catch-all ultimo. (non sostituisce evaluate)
	mux.HandleFunc("/", evaluate)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("security-orchestrator in ascolto", "port", port, "jwks", jwksURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutdown")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
