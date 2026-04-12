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

type mongoMaintenanceOrderRepo struct {
	collection *mongo.Collection
}

// NewMongoMaintenanceOrderRepository creates a new MaintenanceOrderRepository
func NewMongoMaintenanceOrderRepository(db *mongo.Database) MaintenanceOrderRepository {
	return &mongoMaintenanceOrderRepo{
		collection: db.Collection("maintenance_orders"),
	}
}

func (r *mongoMaintenanceOrderRepo) computeDataIntegrityHash(o *models.MaintenanceOrder) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		o.OrderID,
		o.Title,
		o.Type,
		o.Priority,
		o.Status,
		o.SafetyClassification,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoMaintenanceOrderRepo) Create(ctx context.Context, order *models.MaintenanceOrder) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Creating maintenance order", "order_id", order.OrderID, "req_id", reqID)

	order.DataIntegrityHash = r.computeDataIntegrityHash(order)

	_, err := r.collection.InsertOne(ctx, order)
	if err != nil {
		slog.Error("Failed to insert maintenance order", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to create maintenance order: %w", err)
	}

	return nil
}

func (r *mongoMaintenanceOrderRepo) GetByID(ctx context.Context, id string) (*models.MaintenanceOrder, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching maintenance order by ID", "order_id", id, "req_id", reqID)

	var order models.MaintenanceOrder
	err := r.collection.FindOne(ctx, bson.M{"order_id": id}).Decode(&order)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("maintenance order not found")
		}
		slog.Error("Failed to fetch maintenance order", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch maintenance order: %w", err)
	}

	return &order, nil
}

func (r *mongoMaintenanceOrderRepo) GetAll(ctx context.Context) ([]*models.MaintenanceOrder, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching all maintenance orders", "req_id", reqID)

	opts := options.Find().SetSort(bson.D{{Key: "dates.created", Value: -1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch maintenance orders", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch maintenance orders: %w", err)
	}
	defer cursor.Close(ctx)

	var orders []*models.MaintenanceOrder
	if err = cursor.All(ctx, &orders); err != nil {
		slog.Error("Cursor decode error", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to decode maintenance orders: %w", err)
	}

	return orders, nil
}

func (r *mongoMaintenanceOrderRepo) Update(ctx context.Context, order *models.MaintenanceOrder) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Updating maintenance order", "order_id", order.OrderID, "req_id", reqID)

	order.DataIntegrityHash = r.computeDataIntegrityHash(order)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"order_id": order.OrderID},
		bson.M{"$set": order},
	)
	if err != nil {
		slog.Error("Failed to update maintenance order", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to update maintenance order: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("maintenance order not found")
	}

	return nil
}

func (r *mongoMaintenanceOrderRepo) Delete(ctx context.Context, id string) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Deleting maintenance order", "order_id", id, "req_id", reqID)

	result, err := r.collection.DeleteOne(ctx, bson.M{"order_id": id})
	if err != nil {
		slog.Error("Failed to delete maintenance order", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to delete maintenance order: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("maintenance order not found")
	}

	return nil
}
