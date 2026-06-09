// =============================================================================
// Business Database Seed - Entry Point
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This program connects to the Business MongoDB instance and populates all
// seven collections with realistic seed data for the nuclear plant scenario.
//
// The seeding order is deterministic and respects referential dependencies:
//   1. zones       - referenced by all other collections
//   2. personnel   - references zones, referenced by badges and orders
//   3. access_badges - references personnel and zones
//   4. reactor_parameters - references personnel (recorded_by)
//   5. maintenance_orders - references personnel and zones
//   6. documents   - references personnel, zones, and roles
//   7. nuclear_materials  - references zones and personnel
//
// Environment variables:
//   MONGO_URI - MongoDB connection string (includes credentials)
//   MONGO_DB  - Target database name (default: nuclear_plant_db)
// =============================================================================

package main

import (
	"context"
	"log"
	"os"
	"time"

	"nuclear-zta-seed/seeders"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// Create a context with a generous timeout to accommodate slow container startup
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Read connection parameters from environment variables
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://seed_service:seedServicePass2025!@localhost:27017/nuclear_plant_db?authSource=nuclear_plant_db"
	}

	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "nuclear_plant_db"
	}

	// Establish connection to MongoDB
	log.Println("[SEED] Connecting to MongoDB...")
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("[SEED] Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Printf("[SEED] Warning: error during disconnect: %v", err)
		}
	}()

	// Verify connectivity
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatalf("[SEED] Failed to ping MongoDB: %v", err)
	}
	log.Println("[SEED] Successfully connected to MongoDB")

	db := client.Database(dbName)

	// Execute seeders in dependency order for business_db
	log.Println("[SEED] Beginning database population...")

	seeders.SeedZones(ctx, db)
	seeders.SeedPersonnel(ctx, db)
	seeders.SeedAccessBadges(ctx, db)
	seeders.SeedReactorParameters(ctx, db)
	seeders.SeedMaintenanceOrders(ctx, db)
	seeders.SeedDocuments(ctx, db)
	seeders.SeedNuclearMaterials(ctx, db)

	log.Println("[SEED] Business database population completed successfully")

	// Now connect to Security DB and seed users
	securityMongoURI := os.Getenv("SECURITY_DB_URI")
	if securityMongoURI == "" {
		securityMongoURI = "mongodb://ztadmin:ztpassword@localhost:27017/securitydb?authSource=admin"
	}

	secDBName := os.Getenv("SECURITY_DB_NAME")
	if secDBName == "" {
		secDBName = "securitydb"
	}

	log.Println("[SEED] Connecting to Security MongoDB...")
	secClient, err := mongo.Connect(ctx, options.Client().ApplyURI(securityMongoURI))
	if err != nil {
		log.Fatalf("[SEED] Failed to connect to Security MongoDB: %v", err)
	}
	defer func() {
		if err := secClient.Disconnect(ctx); err != nil {
			log.Printf("[SEED] Warning: error during security db disconnect: %v", err)
		}
	}()

	if err = secClient.Ping(ctx, nil); err != nil {
		log.Fatalf("[SEED] Failed to ping Security MongoDB: %v", err)
	}
	log.Println("[SEED] Successfully connected to Security MongoDB")

	secDB := secClient.Database(secDBName)
	seeders.SeedUsers(ctx, secDB)

	log.Println("[SEED] Database population completed successfully")
}