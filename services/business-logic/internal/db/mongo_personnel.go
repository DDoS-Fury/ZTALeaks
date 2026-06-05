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

type mongoPersonnelRepo struct {
	collection *mongo.Collection
}

// NewMongoPersonnelRepository creates a new PersonnelRepository
func NewMongoPersonnelRepository(connessioni *mongo.Database) PersonnelRepository {
	return &mongoPersonnelRepo{
		collection: connessioni.Collection("personnel"),
	}
}
func (r *mongoPersonnelRepo) computeDataIntegrityHash(p *models.Personnel) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		p.EmployeeID,
		p.FirstName,
		p.LastName,
		p.Role,
		p.Department,
		p.ClearanceLevel,
		p.BadgeID,
		p.Status,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoPersonnelRepo) Create(ctx context.Context, personnel *models.Personnel) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Creating personnel record", "employee_id", personnel.EmployeeID, "req_id", reqID)

	personnel.CreatedAt = time.Now()
	personnel.UpdatedAt = time.Now()
	personnel.DataIntegrityHash = r.computeDataIntegrityHash(personnel)

	_, err := r.collection.InsertOne(ctx, personnel)
	if err != nil {
		slog.Error("Failed to insert personnel record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to create personnel record: %w", err)
	}

	return nil
}

func (r *mongoPersonnelRepo) GetByID(ctx context.Context, id string) (*models.Personnel, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching personnel record by ID", "employee_id", id, "req_id", reqID)

	var personnel models.Personnel
	err := r.collection.FindOne(ctx, bson.M{"employee_id": id}).Decode(&personnel)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("personnel record not found")
		}
		slog.Error("Failed to fetch personnel record", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch personnel record: %w", err)
	}

	return &personnel, nil
}

func (r *mongoPersonnelRepo) GetAll(ctx context.Context) ([]*models.Personnel, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching all personnel records", "req_id", reqID)

	// Sort by last name
	opts := options.Find().SetSort(bson.D{{Key: "last_name", Value: 1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch personnel records", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch personnel records: %w", err)
	}
	defer cursor.Close(ctx)

	var personnel []*models.Personnel
	if err = cursor.All(ctx, &personnel); err != nil {
		slog.Error("Cursor decode error", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to decode personnel records: %w", err)
	}

	return personnel, nil
}

func (r *mongoPersonnelRepo) Update(ctx context.Context, personnel *models.Personnel) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Updating personnel record", "employee_id", personnel.EmployeeID, "req_id", reqID)

	personnel.UpdatedAt = time.Now()
	personnel.DataIntegrityHash = r.computeDataIntegrityHash(personnel)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"employee_id": personnel.EmployeeID},
		bson.M{"$set": personnel},
	)
	if err != nil {
		slog.Error("Failed to update personnel record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to update personnel record: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("personnel record not found")
	}

	return nil
}

func (r *mongoPersonnelRepo) Delete(ctx context.Context, id string) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Deleting personnel record", "employee_id", id, "req_id", reqID)

	result, err := r.collection.DeleteOne(ctx, bson.M{"employee_id": id})
	if err != nil {
		slog.Error("Failed to delete personnel record", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to delete personnel record: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("personnel record not found")
	}

	return nil
}
