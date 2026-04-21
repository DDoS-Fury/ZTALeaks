package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ztaleaks/business-logic/config"
	"ztaleaks/business-logic/internal/db"
	"ztaleaks/business-logic/internal/handler"
)

func main() {
	appConfig, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	database := appConfig.Database

	// Initialize repositories and API handler
	repos := db.InitRepositories(database)
	api := handler.NewAPIHandler(repos)

	// Register routes
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// Start server with graceful shutdown
	server := &http.Server{
		Addr:    ":" + appConfig.Port,
		Handler: mux,
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
