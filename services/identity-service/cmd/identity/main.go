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
	"ztaleaks/identity-service/internal/models"
)

func seedDummyAdmin(repo *db.UserRepository) {
	slog.Info("Esecuzione Seed dell'Amministratore (ambiente locale)...")

	// Creo una password hashata sicura con Argon2id
	adminPass, err := crypto.GenerateFromPassword("admin123")
	if err != nil {
		slog.Error("Errore durante la creazione dell'hash Admin", "error", err.Error())
		return
	}

	adminUser := &models.User{
		Username:           "admin",
		PasswordHash:       adminPass,
		Role:               "admin",
		TwoFAEnabled:       false, // Per semplicità in locale, ma il DB supporta il 2FA
		SecureEnclaveValid: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = repo.Create(ctx, adminUser)
	if err != nil {
		slog.Warn("Admin inserito in precedenza (collezione isolata) o errore", "error", err.Error())
	} else {
		slog.Info("Utente Admin creato nel Security DB.", "username", "admin")
	}
}

func main() {
	// 1. Inizializzare il Logger JSON per l'Event Collector
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "/var/log/ztaleaks/identity"
	}

	_, err := logger.InitLogger(logDir, "identity_events.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Errore fatale: impossibile inizializzare il file di log json per l'identità nel volume (%v)\n", err)
		os.Exit(1)
	}

	slog.Info("Servizio Identity avviato, configurazione Sicurezza Zero Trust in corso...")

	// 2. Connessione al MongoDB "Security DB" (in container separato e isolato dalla business logic)
	dbUri := os.Getenv("SECURITY_DB_URI")
	if dbUri == "" {
		dbUri = "mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin"
	}

	mongoClient, err := db.Connect(dbUri, "securitydb")
	if err != nil {
		slog.Error("Impossibile connettersi al database di sicurezza", "error", err.Error())
		os.Exit(1)
	}
	defer mongoClient.Disconnect()

	// 3. Inizializza Repository e API handler (nella collezione identity_users)
	userRepo := db.NewUserRepository(mongoClient)

	// Seed (solo per testing e setup immediato: se la collezione è vuota inietta l'utente admin)
	seedDummyAdmin(userRepo)

	identityApi := &handler.IdentityAPI{
		Repo: userRepo,
	}

	// 4. Configurazione Router
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", identityApi.Login)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082" // Identity Service sulla porta 8082 della auth-net
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,  // Sicurezza base: mitiga attacchi lente come Slowloris
		WriteTimeout: 10 * time.Second, // Sicurezza base
		IdleTimeout:  120 * time.Second,
	}

	// 5. Avvio e Graceful Shutdown
	go func() {
		slog.Info("Server di identificazione ZTA in ascolto", "porta", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Errore d'ascolto del server", "error", err.Error())
			os.Exit(1)
		}
	}()

	// Intercettare i segnali O.S. (es: Docker SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Chiusura Identity Service...")

	// Shutdown dolce senza troncare le connessioni attive (tempo limite: 10 secondi)
	ctxShut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctxShut); err != nil {
		slog.Error("Forzatura arresto server", "error", err.Error())
	}
	slog.Info("Identity Service terminato correttamente.")
}
