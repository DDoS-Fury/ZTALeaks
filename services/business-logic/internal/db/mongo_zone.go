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

type mongoZoneRepo struct {
	collection *mongo.Collection
}

// NewMongoZoneRepository creates a new ZoneRepository
func NewMongoZoneRepository(db *mongo.Database) ZoneRepository {
	return &mongoZoneRepo{
		collection: db.Collection("zones"),
	}
}

func (r *mongoZoneRepo) computeDataIntegrityHash(z *models.Zone) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%s|%s",
		z.ZoneID,
		z.Code,
		z.Name,
		z.Type,
		z.ClassificationLevel,
		z.RadiationZone,
		z.RequiredClearance,
		z.Status,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoZoneRepo) Create(ctx context.Context, zone *models.Zone) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Creating zone record", "zone_id", zone.ZoneID, "req_id", reqID)

	zone.DataIntegrityHash = r.computeDataIntegrityHash(zone)

	_, err := r.collection.InsertOne(ctx, zone)
	if err != nil {
		slog.Error("Failed to insert zone record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to create zone record: %w", err)
	}

	return nil
}

func (r *mongoZoneRepo) GetByID(ctx context.Context, id string) (*models.Zone, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching zone record by ID", "zone_id", id, "req_id", reqID)

	var zone models.Zone
	err := r.collection.FindOne(ctx, bson.M{"zone_id": id}).Decode(&zone)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("zone record not found")
		}
		slog.Error("Failed to fetch zone record", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch zone record: %w", err)
	}

	return &zone, nil
}

func (r *mongoZoneRepo) GetAll(ctx context.Context) ([]*models.Zone, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching all zone records", "req_id", reqID)

	opts := options.Find().SetSort(bson.D{{Key: "zone_id", Value: 1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch zone records", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch zone records: %w", err)
	}
	defer cursor.Close(ctx)

	var zones []*models.Zone
	if err = cursor.All(ctx, &zones); err != nil {
		slog.Error("Cursor decode error", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to decode zone records: %w", err)
	}

	return zones, nil
}

func (r *mongoZoneRepo) Update(ctx context.Context, zone *models.Zone) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Updating zone record", "zone_id", zone.ZoneID, "req_id", reqID)

	zone.DataIntegrityHash = r.computeDataIntegrityHash(zone)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"zone_id": zone.ZoneID},
		bson.M{"$set": zone},
	)
	if err != nil {
		slog.Error("Failed to update zone record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to update zone record: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("zone record not found")
	}

	return nil
}

func (r *mongoZoneRepo) Delete(ctx context.Context, id string) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Deleting zone record", "zone_id", id, "req_id", reqID)

	result, err := r.collection.DeleteOne(ctx, bson.M{"zone_id": id})
	if err != nil {
		slog.Error("Failed to delete zone record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to delete zone record: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("zone record not found")
	}

	return nil
}
