package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ztaleaks/business-logic/internal/db"
	"ztaleaks/business-logic/internal/handler"
)

func main() {
	port := os.Getenv("BUSINESS_LOGIC_PORT")
	if port == "" {
		port = "8080"
	}

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://seed_service:seedServicePass2025!@business-db:27017/nuclear_plant_db?authSource=nuclear_plant_db"
	}

	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "nuclear_plant_db"
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoClient, err := db.Connect(ctx, mongoURI)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	if err := mongoClient.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}
	log.Println("Connected to MongoDB")

	database := mongoClient.Client.Database(dbName)

	// Instantiate repositories
	personnelRepo := db.NewMongoPersonnelRepository(database)
	zoneRepo := db.NewMongoZoneRepository(database)
	badgeRepo := db.NewMongoBadgeRepository(database)
	reactorRepo := db.NewMongoReactorRepository(database)
	maintenanceRepo := db.NewMongoMaintenanceOrderRepository(database)
	documentRepo := db.NewMongoDocumentRepository(database)
	nuclearMaterialRepo := db.NewMongoNuclearMaterialRepository(database)

	// Create API handler
	api := handler.NewAPIHandler(
		personnelRepo,
		zoneRepo,
		badgeRepo,
		reactorRepo,
		maintenanceRepo,
		documentRepo,
		nuclearMaterialRepo,
	)

	// Register routes
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	mux.HandleFunc("/", handler.HomeHandler)

	// Start server with graceful shutdown
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		log.Printf("Business Logic server starting on :%s", port)
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

	if err := mongoClient.Disconnect(shutdownCtx); err != nil {
		log.Printf("Error disconnecting from MongoDB: %v", err)
	}

	log.Println("Server stopped")
}
