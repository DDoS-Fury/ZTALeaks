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
	Port           string
	DBClient       *db.MongoDBClient // For backward compatibility, maps to AdminClient
	Database       *mongo.Database   // For backward compatibility, maps to AdminDB
	AdminClient    *db.MongoDBClient
	ManagerClient  *db.MongoDBClient
	OperatorClient *db.MongoDBClient
	AdminDB        *mongo.Database
	ManagerDB      *mongo.Database
	OperatorDB     *mongo.Database
}

// LoadConfig initialize environment variables and sets up the database connection
func LoadConfig() (*AppConfig, error) {
	port := os.Getenv("BUSINESS_LOGIC_PORT")
	if port == "" {
		port = "8080"
	}

	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "nuclear_plant_db"
	}

	adminURI := os.Getenv("MONGO_ADMIN_URI")
	if adminURI == "" {
		adminURI = "mongodb://admin_client:adminPass2026!@business-db:27017/" + dbName + "?authSource=" + dbName
	}

	managerURI := os.Getenv("MONGO_MANAGER_URI")
	if managerURI == "" {
		managerURI = "mongodb://manager_client:managerPass2026!@business-db:27017/" + dbName + "?authSource=" + dbName
	}

	operatorURI := os.Getenv("MONGO_OPERATOR_URI")
	if operatorURI == "" {
		operatorURI = "mongodb://operator_client:operatorPass2026!@business-db:27017/" + dbName + "?authSource=" + dbName
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect Admin Client
	adminClient, err := db.Connect(ctx, adminURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB Admin: %w", err)
	}
	if err := adminClient.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB Admin: %w", err)
	}
	adminDB := adminClient.Client.Database(dbName)

	// Connect Manager Client
	managerClient, err := db.Connect(ctx, managerURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB Manager: %w", err)
	}
	if err := managerClient.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB Manager: %w", err)
	}
	managerDB := managerClient.Client.Database(dbName)

	// Connect Operator Client
	operatorClient, err := db.Connect(ctx, operatorURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB Operator: %w", err)
	}
	if err := operatorClient.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB Operator: %w", err)
	}
	operatorDB := operatorClient.Client.Database(dbName)

	log.Println("Connected to MongoDB for all 3 clients")

	return &AppConfig{
		Port:           port,
		DBClient:       adminClient,
		Database:       adminDB,
		AdminClient:    adminClient,
		ManagerClient:  managerClient,
		OperatorClient: operatorClient,
		AdminDB:        adminDB,
		ManagerDB:      managerDB,
		OperatorDB:     operatorDB,
	}, nil
}
