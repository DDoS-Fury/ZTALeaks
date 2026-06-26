package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"ztaleaks/business-logic/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoNuclearMaterialRepo struct {
	collection *mongo.Collection
}

// NewMongoNuclearMaterialRepository creates a new NuclearMaterialRepository
func NewMongoNuclearMaterialRepository(db *mongo.Database) NuclearMaterialRepository {
	return &mongoNuclearMaterialRepo{
		collection: db.Collection("nuclear_materials"),
	}
}

func (r *mongoNuclearMaterialRepo) computeDataIntegrityHash(m *models.NuclearMaterial) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		m.MaterialID,
		m.Type,
		m.Description,
		m.ClassificationLevel,
		m.Status,
		m.SerialNumber,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoNuclearMaterialRepo) Create(ctx context.Context, material *models.NuclearMaterial) error {

	material.DataIntegrityHash = r.computeDataIntegrityHash(material)

	_, err := r.collection.InsertOne(ctx, material)
	if err != nil {
		return fmt.Errorf("failed to create nuclear material: %w", err)
	}
	slog.Info("Nuclear material created successfully", "user_id", ctx.Value("user_id"), "material_id", material.MaterialID)
	return nil
}

func (r *mongoNuclearMaterialRepo) GetByID(ctx context.Context, id string) (*models.NuclearMaterial, error) {

	var material models.NuclearMaterial
	err := r.collection.FindOne(ctx, bson.M{"material_id": id}).Decode(&material)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("nuclear material not found")
		}
		slog.Error("Failed to fetch nuclear material", "error", err)
		return nil, fmt.Errorf("failed to fetch nuclear material: %w", err)
	}

	slog.Info("Nuclear material fetched successfully", "material_id", material.MaterialID)
	return &material, nil
}

func (r *mongoNuclearMaterialRepo) GetAll(ctx context.Context) ([]*models.NuclearMaterial, error) {

	opts := options.Find().SetSort(bson.D{{Key: "material_id", Value: 1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch nuclear materials", "error", err)
		return nil, fmt.Errorf("failed to fetch nuclear materials: %w", err)
	}
	defer cursor.Close(ctx)

	var materials []*models.NuclearMaterial
	if err = cursor.All(ctx, &materials); err != nil {
		slog.Error("Failed to decode nuclear materials", "error", err)
		return nil, fmt.Errorf("failed to decode nuclear materials: %w", err)
	}

	slog.Info("Nuclear materials fetched successfully", "user_id", ctx.Value("user_id"), "count", len(materials))
	return materials, nil
}

func (r *mongoNuclearMaterialRepo) Update(ctx context.Context, material *models.NuclearMaterial) error {

	material.DataIntegrityHash = r.computeDataIntegrityHash(material)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"material_id": material.MaterialID},
		bson.M{"$set": material},
	)
	if err != nil {
		return fmt.Errorf("failed to update nuclear material: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("nuclear material not found")
	}

	slog.Info("Nuclear material updated successfully", "user_id", ctx.Value("user_id"), "material_id", material.MaterialID)
	return nil
}

func (r *mongoNuclearMaterialRepo) Delete(ctx context.Context, id string) error {

	result, err := r.collection.DeleteOne(ctx, bson.M{"material_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete nuclear material: %w", err)
	}
	slog.Info("Nuclear material deleted successfully", "user_id", ctx.Value("user_id"), "material_id", id)

	if result.DeletedCount == 0 {
		return fmt.Errorf("nuclear material not found")
	}
	slog.Info("Nuclear material deleted successfully", "user_id", ctx.Value("user_id"), "material_id", id)
	return nil
}
