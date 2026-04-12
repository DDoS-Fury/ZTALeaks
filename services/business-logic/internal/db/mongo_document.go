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

type mongoDocumentRepo struct {
	collection *mongo.Collection
}

// NewMongoDocumentRepository creates a new DocumentRepository
func NewMongoDocumentRepository(db *mongo.Database) DocumentRepository {
	return &mongoDocumentRepo{
		collection: db.Collection("documents"),
	}
}

func (r *mongoDocumentRepo) computeDataIntegrityHash(d *models.Document) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		d.DocumentID,
		d.Title,
		d.Type,
		d.Category,
		d.ClassificationLevel,
		d.Status,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (r *mongoDocumentRepo) Create(ctx context.Context, doc *models.Document) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Creating document", "document_id", doc.DocumentID, "req_id", reqID)

	now := time.Now()
	doc.CreatedAt = now
	doc.UpdatedAt = now
	doc.DataIntegrityHash = r.computeDataIntegrityHash(doc)

	_, err := r.collection.InsertOne(ctx, doc)
	if err != nil {
		slog.Error("Failed to insert document", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to create document: %w", err)
	}

	return nil
}

func (r *mongoDocumentRepo) GetByID(ctx context.Context, id string) (*models.Document, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching document by ID", "document_id", id, "req_id", reqID)

	var doc models.Document
	err := r.collection.FindOne(ctx, bson.M{"document_id": id}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("document not found")
		}
		slog.Error("Failed to fetch document", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch document: %w", err)
	}

	return &doc, nil
}

func (r *mongoDocumentRepo) GetAll(ctx context.Context) ([]*models.Document, error) {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Fetching all documents", "req_id", reqID)

	opts := options.Find().SetSort(bson.D{{Key: "document_id", Value: 1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch documents", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to fetch documents: %w", err)
	}
	defer cursor.Close(ctx)

	var docs []*models.Document
	if err = cursor.All(ctx, &docs); err != nil {
		slog.Error("Cursor decode error", "error", err, "req_id", reqID)
		return nil, fmt.Errorf("failed to decode documents: %w", err)
	}

	return docs, nil
}

func (r *mongoDocumentRepo) Update(ctx context.Context, doc *models.Document) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Updating document", "document_id", doc.DocumentID, "req_id", reqID)

	doc.UpdatedAt = time.Now()
	doc.DataIntegrityHash = r.computeDataIntegrityHash(doc)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"document_id": doc.DocumentID},
		bson.M{"$set": doc},
	)
	if err != nil {
		slog.Error("Failed to update document", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to update document: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("document not found")
	}

	return nil
}

func (r *mongoDocumentRepo) Delete(ctx context.Context, id string) error {
	reqID, _ := ctx.Value("X-Request-ID").(string)
	slog.Info("Deleting document", "document_id", id, "req_id", reqID)

	result, err := r.collection.DeleteOne(ctx, bson.M{"document_id": id})
	if err != nil {
		slog.Error("Failed to delete document", "error", err, "req_id", reqID)
		return fmt.Errorf("failed to delete document: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("document not found")
	}

	return nil
}
