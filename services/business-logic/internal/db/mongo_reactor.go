package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"ztaleaks/business-logic/internal/models"
)

type mongoReactorRepo struct {
	collection *mongo.Collection
}

// NewMongoReactorRepository creates a new ReactorRepository connected to the specified MongoDB database.
func NewMongoReactorRepository(db *mongo.Database) ReactorRepository {
	return &mongoReactorRepo{
		collection: db.Collection("reactor_parameters"),
	}
}

// computeDataIntegrityHash calculates a SHA-256 hash of the reactor parameters
// to ensure data integrity during transit and at rest.
func computeDataIntegrityHash(rp *models.ReactorParameters) string {
	// A simple string formatting of key metrics to generate the hash.
	// In a real scenario, this might use json.Marshal or a deterministic serialization.
	data := fmt.Sprintf("%s|%s|%.2f|%.2f|%.2f|%s",
		rp.ReactorID,
		rp.Timestamp.UTC().String(),
		rp.ThermalPowerMW,
		rp.ElectricalPowerMW,
		rp.NeutronFlux,
		rp.ReactorStatus,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Create computes the data integrity hash and inserts the reactor parameter into the database.
func (r *mongoReactorRepo) Create(ctx context.Context, rp *models.ReactorParameters) error {

	// Compute and set the data integrity hash before insertion
	rp.DataIntegrityHash = computeDataIntegrityHash(rp)

	_, err := r.collection.InsertOne(ctx, rp, cInsert(ctx))
	if err != nil {
		return fmt.Errorf("failed to create reactor parameter: %w", err)
	}

	slog.Info("Reactor parameter created successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "reactor_id", rp.ReactorID)
	return nil
}

// GetByID retrieves a reactor parameter by its internal ID
func (r *mongoReactorRepo) GetByID(ctx context.Context, id string) (*models.ReactorParameters, error) {

	var rp models.ReactorParameters
	err := r.collection.FindOne(ctx, bson.M{"reactor_id": id}, cFindOne(ctx)).Decode(&rp)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("reactor parameter not found")
		}
		slog.Error("Failed to get reactor parameter by id", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "error", err)
		return nil, fmt.Errorf("failed to get reactor parameter by id: %w", err)
	}
	return &rp, nil
}

// GetAll retrieves all reactor parameters
func (r *mongoReactorRepo) GetAll(ctx context.Context) ([]*models.ReactorParameters, error) {

	cursor, err := r.collection.Find(ctx, bson.M{}, cFind(ctx))
	if err != nil {

		return nil, fmt.Errorf("failed to query all reactor parameters: %w", err)
	}
	defer cursor.Close(ctx)

	var results []*models.ReactorParameters
	if err := cursor.All(ctx, &results); err != nil {

		return nil, fmt.Errorf("failed to decode reactor parameters: %w", err)
	}
	slog.Info("Reactor parameters fetched successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "count", len(results))
	return results, nil
}

// Update modifies an existing reactor parameter.
func (r *mongoReactorRepo) Update(ctx context.Context, rp *models.ReactorParameters) error {

	rp.DataIntegrityHash = computeDataIntegrityHash(rp)

	filter := bson.M{"reactor_id": rp.ReactorID, "timestamp": rp.Timestamp}
	update := bson.M{"$set": rp}

	_, err := r.collection.UpdateOne(ctx, filter, update, cUpdate(ctx))
	if err != nil {

		return fmt.Errorf("failed to update reactor parameter: %w", err)
	}
	slog.Info("Reactor parameter updated successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "reactor_id", rp.ReactorID)
	return nil
}

// Delete removes a reactor parameter by ID.
func (r *mongoReactorRepo) Delete(ctx context.Context, id string) error {

	result, err := r.collection.DeleteOne(ctx, bson.M{"reactor_id": id}, cDelete(ctx))
	if err != nil {

		return fmt.Errorf("failed to delete reactor parameter: %w", err)
	}

	slog.Info("Reactor parameter deleted successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "reactor_id", id)
	if result.DeletedCount == 0 {
		return fmt.Errorf("reactor parameter not found")
	}

	return nil
}
