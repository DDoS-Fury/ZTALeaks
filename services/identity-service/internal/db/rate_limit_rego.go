package db

import (
	"context"
	"errors"
	"time"
	"ztaleaks/identity-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	MaxLoginAttempts = 5
	BlockDuration    = 5 * time.Minute
)

var ErrRateLimitExceeded = errors.New("rate limit exceeded")

type RateLimitRepository struct {
	coll *mongo.Collection
}

func NewRateLimitRepository(m *MongoDB) *RateLimitRepository {
	return &RateLimitRepository{
		coll: m.DB.Collection("rate_limits"),
	}
}

// CheckRateLimit verifica se l'IP ha superato il numero massimo di tentativi
func (r *RateLimitRepository) CheckRateLimit(ctx context.Context, ip string) error {
	var rl models.RateLimit
	err := r.coll.FindOne(ctx, bson.M{"_id": ip}).Decode(&rl)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil // Nessun record, limite non superato
		}
		return err // Errore DB
	}
	// Se il record è scaduto non lo blocchiamo
	if time.Now().After(rl.ExpiresAt) {
		return nil
	}
	if rl.Attempts >= MaxLoginAttempts {
		return ErrRateLimitExceeded
	}
	return nil
}

// RecordFailure incrementa il contatore dei tentativi per l'IP
func (r *RateLimitRepository) RecordFailure(ctx context.Context, ip string) error {
	filter := bson.M{"_id": ip}
	now := time.Now()
	update := bson.M{
		"$inc": bson.M{"attempts": 1},
		"$set": bson.M{"expires_at": now.Add(BlockDuration)},
	}
	opts := options.Update().SetUpsert(true)
	_, err := r.coll.UpdateOne(ctx, filter, update, opts)
	return err
}

// ResetLimit rimuove il contatore per l'IP su login con successo
func (r *RateLimitRepository) ResetLimit(ctx context.Context, ip string) error {
	_, err := r.coll.DeleteOne(ctx, bson.M{"_id": ip})
	return err
}

// CleanupExpired elimina i record scaduti
func (r *RateLimitRepository) CleanupExpired(ctx context.Context) error {
	_, err := r.coll.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": time.Now()}})
	return err
}
