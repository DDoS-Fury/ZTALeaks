package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"ztaleaks/business-logic/internal/db"

	"go.mongodb.org/mongo-driver/mongo"
)

type AppConfig struct {
	Port     string
	DBClient *db.MongoDBClient
	Database *mongo.Database
}

// LoadConfig initialize environment variables and sets up the database connection
func LoadConfig() (*AppConfig, error) {
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
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := mongoClient.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}
	log.Println("Connected to MongoDB")

	database := mongoClient.Client.Database(dbName)

	return &AppConfig{
		Port:     port,
		DBClient: mongoClient,
		Database: database,
	}, nil
}
