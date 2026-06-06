package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ztaleaks/business-logic/config"
	"ztaleaks/business-logic/internal/db"
	"ztaleaks/business-logic/internal/handler"
	"ztaleaks/business-logic/internal/middleware"
)

func main() {
	// Prepara la cartella dei log come richiesto nel LOGGING_PLAN.md
	logDir := "/var/log/ztaleaks/business-logic"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("Warning: Impossibile creare la cartella dei log %s: %v", logDir, err)
	}

	// Apri o crea il file di log (Double-write: Splunk UF leggerà questo)
	var logWriter io.Writer = os.Stdout
	logFile, err := os.OpenFile(filepath.Join(logDir, "app.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Warning: Impossibile aprire il file di log, fallback stdout: %v", err)
	} else {
		defer logFile.Close()
		logWriter = io.MultiWriter(os.Stdout, logFile)
	}

	// Imposta logger standard a JSON strutturato per Splunk indirizzato a console + file.
	// L'attributo `service` viene pre-popolato qui in modo che ogni slog.X in tutto
	// il package erediti automaticamente la provenienza del log.
	logger := slog.New(slog.NewJSONHandler(logWriter, nil)).With("service", "business-logic")
	slog.SetDefault(logger)

	appConfig, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Initialize repositories and API handler
	repos := db.InitRepositories(appConfig.OperatorDB, appConfig.AdminDB, appConfig.ManagerDB)
	api := handler.NewAPIHandler(repos)

	// Register routes
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// Inietta il Middleware di Logging per il tracciamento JSON Splunk
	wrappedHandler := middleware.LoggingMiddleware(mux)

	// Start server with graceful shutdown
	server := &http.Server{
		Addr:    ":" + appConfig.Port,
		Handler: wrappedHandler,
	}

	go func() {
		log.Printf("Business Logic server starting on :%s", appConfig.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	if err := appConfig.DBClient.Disconnect(shutdownCtx); err != nil {
		log.Printf("Error disconnecting from MongoDB: %v", err)
	}

	log.Println("Server stopped")
}
