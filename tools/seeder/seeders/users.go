package seeders

import (
	"context"
	"log"
	"time"

	"nuclear-zta-seed/crypto"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type userSeed struct {
	username, email, role, clearance string
}

var defaultUsers = []userSeed{
	{"admin", "admin@ztaleaks.local", "admin", "TOP_SECRET"},
	{"manager1", "manager1@ztaleaks.local", "manager", "SECRET"},
	{"operator1", "operator1@ztaleaks.local", "operator", "CONFIDENTIAL"},
}

const defaultPassword = "admin123"

func SeedUsers(ctx context.Context, db *mongo.Database) {
	log.Println("[SEED] Seeding identity_users...")
	coll := db.Collection("identity_users")

	// Ensure unique index
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("[SEED] Warning: error creating index on identity_users: %v", err)
	}

	hash, err := crypto.GenerateFromPassword(defaultPassword)
	if err != nil {
		log.Printf("[SEED] Error generating hash for default password: %v", err)
		return
	}

	count := 0
	for _, s := range defaultUsers {
		now := time.Now()
		u := bson.M{
			"_id":           primitive.NewObjectID(),
			"username":      s.username,
			"email":         s.email,
			"password_hash": hash,
			"two_fa_enabled": true,
			"status":        "active",
			"created_at":    now,
		}

		filter := bson.M{"username": s.username}
		// role/clearance in $set: re-running the seeder realigns existing
		// users to the current role model (e.g. plant_manager -> admin)
		update := bson.M{
			"$setOnInsert": u,
			"$set": bson.M{
				"role":       s.role,
				"clearance":  s.clearance,
				"updated_at": now,
			},
		}
		opts := options.Update().SetUpsert(true)

		res, err := coll.UpdateOne(ctx, filter, update, opts)
		if err != nil {
			log.Printf("[SEED] Error upserting user %s: %v", s.username, err)
			continue
		}
		if res.UpsertedCount > 0 {
			count++
			log.Printf("[SEED] Created user %s (role: %s)", s.username, s.role)
		}
	}

	log.Printf("[SEED] identity_users: inserted %d new records.", count)
}
