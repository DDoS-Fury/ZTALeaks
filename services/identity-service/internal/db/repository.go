package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/identity-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	usersCollection = "identity_users" // Collezione dedicata, isolata da altre eventualmente presenti
)

type UserRepository struct {
	coll *mongo.Collection
}

func NewUserRepository(m *MongoDB) *UserRepository {
	// Assicura l'uso della collezione specificata ("identity_users")
	return &UserRepository{
		coll: m.DB.Collection(usersCollection),
	}
}

// FindByUsername cerca un utente tramire lo username nel database
func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User

	filter := bson.M{"username": username}

	// Per gestire timeout al database
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err := r.coll.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("utente non trovato")
		}
		return nil, err
	}

	return &user, nil
}

// Create inserisce un nuovo User. Da invocare preferibilmente con un seeder di Identity.
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	// Controlliamo che l'username non esista già
	count, err := r.coll.CountDocuments(ctx, bson.M{"username": user.Username})
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username gia in uso")
	}

	result, err := r.coll.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	if oid, ok := result.InsertedID.(primitive.ObjectID); ok {
		user.ID = oid.Hex()
	}

	return nil
}

// UpdateLastLogin aggiorna le informazioni sull'ultimo login (IP, fingerprint, timestamp)
func (r *UserRepository) UpdateLastLogin(ctx context.Context, username string, info models.LoginInfo) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	filter := bson.M{"username": username}
	update := bson.M{
		"$set": bson.M{
			"last_login_info": info,
			"updated_at":      time.Now(),
		},
	}

	_, err := r.coll.UpdateOne(ctx, filter, update)
	return err
}
