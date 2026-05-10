package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ztaleaks/identity-service/config"
	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/handler"
	"ztaleaks/identity-service/internal/logger"
	"ztaleaks/identity-service/internal/mailer"
	"ztaleaks/identity-service/internal/seed"
	wa "ztaleaks/identity-service/internal/webauthn"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if _, err := logger.InitLogger(cfg.LogDir, "identity_events.json"); err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	slog.Info("Identity service starting")
	defer cfg.DB.Disconnect()

	repos := db.InitRepositories(cfg.DB)

	jwtMgr, err := crypto.NewJWTManager()
	if err != nil {
		slog.Error("JWT manager init", "error", err)
		os.Exit(1)
	}
	slog.Info("JWT manager pronto", "kid", jwtMgr.KeyID(), "alg", "RS256")

	mail := mailer.New()

	seed.Users(repos.Users)

	api := &handler.IdentityAPI{
		Users:   repos.Users,
		OTP:     repos.OTP,
		Devices: repos.Devices,
		JWT:     jwtMgr,
		Mail:    mail,
	}
	waHandler := wa.NewHandler(repos.Users, repos.Devices, repos.Challenges, jwtMgr)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"identity"}`))
	})

	// JWKS — chiave pubblica per la security-orchestrator
	mux.HandleFunc("GET /.well-known/jwks.json", crypto.JWKSHandler(jwtMgr))

	// Auth (register, login a 2 step)
	mux.HandleFunc("POST /api/v1/auth/register", api.Register)
	mux.HandleFunc("POST /api/v1/auth/login", api.Login)
	mux.HandleFunc("POST /api/v1/auth/verify-otp", api.VerifyOTP)

	// WebAuthn / FIDO2 / TPM enrollment
	mux.HandleFunc("POST /api/v1/auth/register/begin", waHandler.BeginRegistration)
	mux.HandleFunc("POST /api/v1/auth/register/finish", waHandler.FinishRegistration)
	mux.HandleFunc("POST /api/v1/auth/login/begin", waHandler.BeginLogin)
	mux.HandleFunc("POST /api/v1/auth/login/finish", waHandler.FinishLogin)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("Identity service in ascolto", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutdown identity-service")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "error", err)
	}
}
