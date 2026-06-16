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

	"ztaleaks/iam-service/config"
	"ztaleaks/iam-service/internal/crypto"
	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/handler"
	"ztaleaks/iam-service/internal/logger"
	"ztaleaks/iam-service/internal/mailer"
	wa "ztaleaks/iam-service/internal/webauthn"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	defer cfg.DB.Disconnect()

	if _, err := logger.InitLogger(cfg.LogDir, "identity_events.json"); err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	slog.Info("Identity service starting")

	repos := db.InitRepositories(cfg.DB)

	jwtMgr, err := crypto.NewJWTManager()
	if err != nil {
		slog.Error("JWT manager init", "error", err)
		os.Exit(1)
	}
	slog.Info("JWT manager pronto", "kid", jwtMgr.KeyID(), "alg", "RS256")

	mail := mailer.New()

	router := &handler.Router{
		API: &handler.IdentityAPI{
			Users:      repos.Users,
			OTP:        repos.OTP,
			Devices:    repos.Devices,
			RateLimits: repos.RateLimits,
			JWT:        jwtMgr,
			Mail:       mail,
		},
		WebAuthn: wa.NewHandler(repos.Users, repos.Devices, repos.Challenges, repos.OTP, mail),
		JWT:      jwtMgr,
	}

	mux := http.NewServeMux()
	router.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := repos.RateLimits.CleanupExpired(context.Background()); err != nil {
				slog.Error("rate_limits cleanup err", "error", err)
			}
		}
	}()

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
	slog.Info("shutdown iam-service")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "error", err)
	}
}
