package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/identity-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const challengesCollection = "webauthn_challenges"

type ChallengeRepository struct {
	coll *mongo.Collection
}

func NewChallengeRepository(m *MongoDB) *ChallengeRepository {
	return &ChallengeRepository{coll: m.DB.Collection(challengesCollection)}
}

func (r *ChallengeRepository) Create(ctx context.Context, c models.WebAuthnChallenge) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c.CreatedAt = time.Now()
	_, err := r.coll.InsertOne(ctx, c)
	return err
}

var ErrChallengeNotFound = errors.New("challenge non trovata o scaduta")

func (r *ChallengeRepository) FindBySessionID(ctx context.Context, sessionID string) (*models.WebAuthnChallenge, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var c models.WebAuthnChallenge
	err := r.coll.FindOne(ctx, bson.M{"session_id": sessionID}).Decode(&c)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrChallengeNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (r *ChallengeRepository) Delete(ctx context.Context, sessionID string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.coll.DeleteOne(ctx, bson.M{"session_id": sessionID})
	return err
}
