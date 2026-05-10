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
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ztaleaks/security-orchestrator/internal/cert"
	"ztaleaks/security-orchestrator/internal/db"
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
	slog.SetDefault(slog.New(slog.NewJSONHandler(logWriter, nil)))

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
	opaClient := opa.New()

	// --- HTTP routes ---
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"security-orchestrator"}`))
	})

	// Decision logs ricevuti da OPA (--set=services.orchestrator...) — preservato
	mux.HandleFunc("POST /api/v1/opa/logs", func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "bad gzip", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			reader = gz
		}
		var entries []json.RawMessage
		if err := json.NewDecoder(reader).Decode(&entries); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		for _, e := range entries {
			if opaLogFile != nil {
				_, _ = opaLogFile.Write(append([]byte(e), '\n'))
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// ext_authz endpoint chiamato da Envoy
	evaluate := buildEvaluateHandler(verifier, tpmLookup, opaClient)
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

// buildEvaluateHandler costruisce l'handler ext_authz: legge gli header
// forwardati da Envoy, verifica JWT, parse cert, lookup TPM, chiama OPA.
func buildEvaluateHandler(verifier *jwtpkg.Verifier, tpmLookup *tpm.Lookup, opaClient *opa.Client) http.HandlerFunc {
	const evalPrefix = "/api/v1/evaluate"
	return func(w http.ResponseWriter, r *http.Request) {
		// Path originale: con path_prefix "/api/v1/evaluate" Envoy preopne
		// quel prefisso al path di partenza prima di chiamarci. Strippiamolo.
		origPath := r.URL.Path
		if strings.HasPrefix(origPath, evalPrefix) {
			origPath = strings.TrimPrefix(origPath, evalPrefix)
			if origPath == "" {
				origPath = "/"
			}
		}
		// Header X-Original-Uri ha priorità se Envoy lo inietta esplicitamente
		// (utile per chiamate di test diretto via curl).
		if h := r.Header.Get("X-Original-Uri"); h != "" {
			origPath = h
		} else if h := r.Header.Get("X-Authz-Request-Path"); h != "" {
			origPath = h
		}

		method := r.Header.Get("X-Authz-Request-Method")
		if method == "" {
			method = r.Method
		}
		zoneID := r.Header.Get("X-Zone-Id")

		// La decisione su quali rotte siano pubbliche e' delegata a OPA
		// (vedi public_paths nel policy.rego). Qui ci limitiamo a estrarre
		// JWT/cert/TPM e a inoltrare l'input arricchito al PDP.
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			// niente JWT → tier "niente" (anonimo). Mandiamo comunque il
			// caso a OPA perché certe rotte pubbliche potrebbero ammettere
			// senza autenticazione.
			slog.Info("ext_authz: nessun token", "path", origPath)
			ok := evalOPA(r.Context(), opaClient, opa.Input{
				Request:     opa.Request{Method: method, Path: origPath},
				Claims:      nil,
				CertPresent: false,
				TPMVerified: false,
				ZoneID:      zoneID,
			})
			respondAllow(w, ok, "")
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("JWT verify fallita", "error", err)
			http.Error(w, `{"allowed":false,"reason":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// 3. Certificate
		cc := cert.Parse(r.Header.Get("X-Forwarded-Client-Cert"))

		// 4. TPM lookup
		tpmOK := tpmLookup.Verify(r.Context(), claims.UserID, claims.DeviceID)

		// 5. OPA call con input arricchito
		input := opa.Input{
			Request:     opa.Request{Method: method, Path: origPath},
			Claims:      claimsToMap(claims),
			CertPresent: cc.Present,
			CertSubject: cc.Subject,
			TPMVerified: tpmOK,
			ZoneID:      zoneID,
		}
		allow := evalOPA(r.Context(), opaClient, input)
		slog.Info("decisione",
			"path", origPath, "method", method, "user", claims.UserID,
			"role", claims.Role, "clearance", claims.ClearanceLevel,
			"cert_present", cc.Present, "tpm_verified", tpmOK,
			"zone", zoneID, "allow", allow,
		)
		respondAllow(w, allow, claims.UserID)
	}
}

// evalOPA wraps the OPA client call con fail-safe: se OPA non risponde →
// nega (Zero Trust default).
func evalOPA(ctx context.Context, c *opa.Client, in opa.Input) bool {
	allow, err := c.Evaluate(ctx, in)
	if err != nil {
		slog.Error("OPA error → deny by default", "error", err)
		return false
	}
	return allow
}

// respondAllow chiude la risposta verso Envoy. 200 → allow; 403 → deny.
// Inietta x-current-user (allowed_upstream_headers in envoy.yaml).
func respondAllow(w http.ResponseWriter, allow bool, userID string) {
	w.Header().Set("Content-Type", "application/json")
	if allow {
		if userID != "" {
			w.Header().Set("x-current-user", userID)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true}`))
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"allowed":false,"reason":"policy denied"}`))
}

func bearerToken(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// claimsToMap serializza ZTAClaims in mappa generica (più comoda per Rego).
func claimsToMap(c *jwtpkg.ZTAClaims) map[string]any {
	m := map[string]any{
		"sub":             c.UserID,
		"role":            c.Role,
		"clearance_level": c.ClearanceLevel,
		"mfa_verified":    c.MFAVerified,
	}
	if c.DeviceID != "" {
		m["device_id"] = c.DeviceID
	}
	if c.JA3 != "" {
		m["ja3"] = c.JA3
	}
	return m
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
