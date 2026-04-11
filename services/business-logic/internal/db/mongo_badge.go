package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"ztaleaks/business-logic/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoBadgeRepo struct {
	collection *mongo.Collection
}

// NewMongoBadgeRepository creates a new BadgeRepository
func NewMongoBadgeRepository(db *mongo.Database) BadgeRepository {
	return &mongoBadgeRepo{
		collection: db.Collection("access_badges"),
	}
}

func (r *mongoBadgeRepo) computeDataIntegrityHash(b *models.AccessBadge) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		b.BadgeID,
		b.EmployeeID,
		b.Type,
		b.ClassificationLevel,
		b.Status,
		b.ExpiryDate.Format(time.RFC3339),
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoBadgeRepo) Create(ctx context.Context, badge *models.AccessBadge) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Creating badge record", "badge_id", badge.BadgeID, "req_id", reqID)

	badge.DataIntegrityHash = r.computeDataIntegrityHash(badge)

	_, err := r.collection.InsertOne(ctx, badge)
	if err != nil {
		slog.Error("Failed to insert badge record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to create badge record: %w", err)
	}

	return nil
}

func (r *mongoBadgeRepo) GetByID(ctx context.Context, id string) (*models.AccessBadge, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching badge record by ID", "badge_id", id, "req_id", reqID)

	var badge models.AccessBadge
	err := r.collection.FindOne(ctx, bson.M{"badge_id": id}).Decode(&badge)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("badge record not found")
		}
		slog.Error("Failed to fetch badge record", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch badge record: %w", err)
	}

	return &badge, nil
}

func (r *mongoBadgeRepo) GetAll(ctx context.Context) ([]*models.AccessBadge, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching all badge records", "req_id", reqID)

	opts := options.Find().SetSort(bson.D{{Key: "issue_date", Value: -1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch badge records", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch badge records: %w", err)
	}
	defer cursor.Close(ctx)

	var badges []*models.AccessBadge
	if err = cursor.All(ctx, &badges); err != nil {
		slog.Error("Cursor decode error", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to decode badge records: %w", err)
	}

	return badges, nil
}

func (r *mongoBadgeRepo) Update(ctx context.Context, badge *models.AccessBadge) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Updating badge record", "badge_id", badge.BadgeID, "req_id", reqID)

	badge.DataIntegrityHash = r.computeDataIntegrityHash(badge)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"badge_id": badge.BadgeID},
		bson.M{"$set": badge},
	)
	if err != nil {
		slog.Error("Failed to update badge record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to update badge record: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("badge record not found")
	}

	return nil
}

func (r *mongoBadgeRepo) Delete(ctx context.Context, id string) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Deleting badge record", "badge_id", id, "req_id", reqID)

	result, err := r.collection.DeleteOne(ctx, bson.M{"badge_id": id})
	if err != nil {
		slog.Error("Failed to delete badge record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to delete badge record: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("badge record not found")
	}

	return nil
}
