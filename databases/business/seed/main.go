package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"nuclear-zta-seed/seeders"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://seed_service:seedServicePass2025!@localhost:27017/nuclear_plant_db?authSource=nuclear_plant_db"
	}

	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "nuclear_plant_db"
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("❌ Failed to connect:", err)
	}
	defer client.Disconnect(ctx)

	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal("❌ Failed to ping:", err)
	}
	fmt.Println("✅ Connected to MongoDB")

	db := client.Database(dbName)

	// Seed in ordine: zones prima perché referenziata da altri
	fmt.Println("\n📦 Seeding database...")

	seeders.SeedZones(ctx, db)
	seeders.SeedPersonnel(ctx, db)
	seeders.SeedAccessBadges(ctx, db)
	seeders.SeedReactorParameters(ctx, db)
	seeders.SeedMaintenanceOrders(ctx, db)
	seeders.SeedDocuments(ctx, db)
	seeders.SeedNuclearMaterials(ctx, db)

	fmt.Println("\n🎉 All seed data inserted successfully!")
}
