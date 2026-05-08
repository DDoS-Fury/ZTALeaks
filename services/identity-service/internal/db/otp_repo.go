package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/identity-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const otpCollection = "otp_sessions"

type OTPRepository struct {
	coll *mongo.Collection
}

func NewOTPRepository(m *MongoDB) *OTPRepository {
	return &OTPRepository{coll: m.DB.Collection(otpCollection)}
}

func (r *OTPRepository) Create(ctx context.Context, s models.OTPSession) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s.CreatedAt = time.Now()
	_, err := r.coll.InsertOne(ctx, s)
	return err
}

// FindBySessionToken restituisce ErrNotFound se il documento è stato già pulito
// dal TTL Mongo (5 min).
var ErrSessionNotFound = errors.New("session non trovata o scaduta")

func (r *OTPRepository) FindBySessionToken(ctx context.Context, token string) (*models.OTPSession, error) {
	var s models.OTPSession
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := r.coll.FindOne(ctx, bson.M{"session_token": token}).Decode(&s)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (r *OTPRepository) IncrementAttempts(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.coll.UpdateOne(ctx,
		bson.M{"session_token": token},
		bson.M{"$inc": bson.M{"attempts": 1}},
	)
	return err
}

func (r *OTPRepository) Delete(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.coll.DeleteOne(ctx, bson.M{"session_token": token})
	return err
}
