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

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/handler"
	"ztaleaks/identity-service/internal/logger"
	"ztaleaks/identity-service/internal/mailer"
	"ztaleaks/identity-service/internal/models"
	wa "ztaleaks/identity-service/internal/webauthn"
)

// seedUsers crea (se non esistono) gli utenti di test multi-ruolo.
// Argon2id viene calcolato qui in Go: la pre-genezione lato JS sarebbe
// fragile (Argon2 non è disponibile nello shell mongo).
func seedUsers(repo *db.UserRepository) {
	type seed struct {
		username, email, role, clearance string
	}
	seeds := []seed{
		{"admin", "admin@ztaleaks.local", "plant_manager", "TOP_SECRET"},
		{"operator1", "operator1@ztaleaks.local", "operator", "CONFIDENTIAL"},
		{"maint_tech1", "maint_tech1@ztaleaks.local", "maintenance_technician", "INTERNAL"},
		{"rad_officer1", "rad_officer1@ztaleaks.local", "radiation_protection_officer", "SECRET"},
		{"sec_officer1", "sec_officer1@ztaleaks.local", "security_officer", "SECRET"},
		{"inspector1", "inspector1@ztaleaks.local", "inspector", "SECRET"},
	}
	hash, err := crypto.GenerateFromPassword("admin123")
	if err != nil {
		slog.Error("seed: hash password", "error", err)
		return
	}
	for _, s := range seeds {
		u := &models.User{
			Username:       s.username,
			Email:          s.email,
			PasswordHash:   hash,
			Role:           s.role,
			ClearanceLevel: s.clearance,
			TwoFAEnabled:   true,
			Status:         "active",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := repo.Create(ctx, u)
		cancel()
		if err != nil {
			slog.Debug("seed user skipped (probably already exists)", "username", s.username, "reason", err.Error())
			continue
		}
		slog.Info("seed user creato", "username", s.username, "role", s.role, "clearance", s.clearance)
	}
}

func main() {
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "/var/log/ztaleaks/identity"
	}
	if _, err := logger.InitLogger(logDir, "identity_events.json"); err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	slog.Info("Identity service starting")

	// --- Connessione Security DB ---
	dbUri := os.Getenv("SECURITY_DB_URI")
	if dbUri == "" {
		dbUri = "mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin"
	}
	dbName := os.Getenv("SECURITY_DB_NAME")
	if dbName == "" {
		dbName = "securitydb"
	}
	mongoClient, err := db.Connect(dbUri, dbName)
	if err != nil {
		slog.Error("DB connect", "error", err)
		os.Exit(1)
	}
	defer mongoClient.Disconnect()

	// --- Repositories ---
	userRepo := db.NewUserRepository(mongoClient)
	otpRepo := db.NewOTPRepository(mongoClient)
	deviceRepo := db.NewDeviceRepository(mongoClient)
	challengeRepo := db.NewChallengeRepository(mongoClient)

	// --- JWT manager (RS256, chiave ephemeral) ---
	jwtMgr, err := crypto.NewJWTManager()
	if err != nil {
		slog.Error("JWT manager init", "error", err)
		os.Exit(1)
	}
	slog.Info("JWT manager pronto", "kid", jwtMgr.KeyID(), "alg", "RS256")

	// --- Mailer (MailHog) ---
	mail := mailer.New()

	// --- Seed utenti test ---
	seedUsers(userRepo)

	// --- Handlers ---
	api := &handler.IdentityAPI{
		Users:   userRepo,
		OTP:     otpRepo,
		Devices: deviceRepo,
		JWT:     jwtMgr,
		Mail:    mail,
	}
	waHandler := wa.NewHandler(userRepo, deviceRepo, challengeRepo, jwtMgr)

	// --- Routing ---
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

	port := os.Getenv("IDENTITY_SERVICE_PORT")
	if port == "" {
		port = "8082"
	}
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("Identity service in ascolto", "port", port)
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
