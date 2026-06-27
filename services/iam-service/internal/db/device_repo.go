package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/iam-service/internal/models"

	"github.com/go-webauthn/webauthn/webauthn"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const deviceCollection = "device_fingerprints"

type DeviceRepository struct {
	coll *mongo.Collection
}

func NewDeviceRepository(m *MongoDB) *DeviceRepository {
	return &DeviceRepository{coll: m.DB.Collection(deviceCollection)}
}

func (r *DeviceRepository) Create(ctx context.Context, d models.DeviceCredential) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d.CreatedAt = time.Now()
	d.LastUsedAt = time.Now()
	_, err := r.coll.InsertOne(ctx, d)
	return err
}

// FindMostRecentByUser è usato dal flusso /verify-otp per recuperare il
// device_id da iniettare nel JWT (così OPA vede tier=cert+tpm quando l'utente
// ha enrollato).
func (r *DeviceRepository) FindMostRecentByUser(ctx context.Context, userID string) (*models.DeviceCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	opts := options.FindOne().SetSort(bson.D{{Key: "last_used_at", Value: -1}})
	var d models.DeviceCredential
	err := r.coll.FindOne(ctx, bson.M{"user_id": userID}, opts).Decode(&d)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil // utente senza TPM enrollato — niente errore
		}
		return nil, err
	}
	return &d, nil
}

func (r *DeviceRepository) FindByCredentialID(ctx context.Context, credID string) (*models.DeviceCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var d models.DeviceCredential
	err := r.coll.FindOne(ctx, bson.M{"credential_id": credID}).Decode(&d)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &d, nil
}

// UpdateCredential ripersiste la webauthn.Credential restituita da
// FinishLogin (sign-count aggiornato dalla libreria, eventuale clone-warning)
// e aggiorna last_used_at. Sostituisce il vecchio UpdateSignCount che si
// fidava di un contatore auto-dichiarato dal client.
func (r *DeviceRepository) UpdateCredential(ctx context.Context, credID string, cred webauthn.Credential) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.coll.UpdateOne(ctx,
		bson.M{"credential_id": credID},
		bson.M{"$set": bson.M{
			"credential":   cred,
			"last_used_at": time.Now(),
		}},
	)
	return err
}

func (r *DeviceRepository) ListByUser(ctx context.Context, userID string) ([]models.DeviceCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cur, err := r.coll.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []models.DeviceCredential
	for cur.Next(ctx) {
		var d models.DeviceCredential
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
