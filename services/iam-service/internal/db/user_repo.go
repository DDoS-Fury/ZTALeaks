package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/iam-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const usersCollection = "identity_users"

type UserRepository struct {
	coll *mongo.Collection
}

func NewUserRepository(m *MongoDB) *UserRepository {
	return &UserRepository{coll: m.DB.Collection(usersCollection)}
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := r.coll.FindOne(ctx, bson.M{"username": username}, cFindOne(username)).Decode(&u)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("utente non trovato")
		}
		return nil, err
	}
	return &u, nil
}

// FindByID — usato dal flusso /verify-otp per recuperare i claim al rilascio del JWT.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New("id utente non valido")
	}
	var u models.User
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.coll.FindOne(ctx, bson.M{"_id": objID}, cFindOne(id)).Decode(&u); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("utente non trovato")
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	if user.Status == "" {
		user.Status = "active"
	}

	count, err := r.coll.CountDocuments(ctx, bson.M{"username": user.Username}, cCount(user.Username))
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username gia in uso")
	}

	res, err := r.coll.InsertOne(ctx, user, cInsert(user.Username))
	if err != nil {
		return err
	}
	if oid, ok := res.InsertedID.(primitive.ObjectID); ok {
		user.ID = oid.Hex()
	}
	return nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID string, info models.LoginInfo) error {
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = r.coll.UpdateOne(ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{
			"last_login_info": info,
			"updated_at":      time.Now(),
		}},
		cUpdate(userID),
	)
	return err
}

// MarkTPMEnrolled è chiamato dal finish della cerimonia WebAuthn registration.
func (r *UserRepository) MarkTPMEnrolled(ctx context.Context, userID string, tpmPubKeyB64 string) error {
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = r.coll.UpdateOne(ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{
			"has_tpm":         true,
			"tpm_public_key":  tpmPubKeyB64,
			"secure_enclave_valid": true,
			"updated_at":      time.Now(),
		}},
		cUpdate(userID),
	)
	return err
}
