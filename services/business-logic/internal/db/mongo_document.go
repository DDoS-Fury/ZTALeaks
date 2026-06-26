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

	now := time.Now()
	doc.CreatedAt = now
	doc.UpdatedAt = now
	doc.DataIntegrityHash = r.computeDataIntegrityHash(doc)

	_, err := r.collection.InsertOne(ctx, doc, cInsert(ctx))
	if err != nil {
		return fmt.Errorf("failed to create document: %w", err)
	}

	slog.Info("Document created successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "document_id", doc.DocumentID)

	return nil
}

func (r *mongoDocumentRepo) GetByID(ctx context.Context, id string) (*models.Document, error) {

	var doc models.Document
	err := r.collection.FindOne(ctx, bson.M{"document_id": id}, cFindOne(ctx)).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("document not found")
		}
		slog.Error("Failed to fetch document", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "error", err)
		return nil, fmt.Errorf("failed to fetch document: %w", err)
	}

	slog.Info("Document fetched successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "document_id", doc.DocumentID)

	return &doc, nil
}

func (r *mongoDocumentRepo) GetAll(ctx context.Context) ([]*models.Document, error) {

	opts := options.Find().SetSort(bson.D{{Key: "document_id", Value: 1}}).SetComment(commentFor(ctx))
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		slog.Error("Failed to fetch documents", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "error", err)
		return nil, fmt.Errorf("failed to fetch documents: %w", err)
	}
	defer cursor.Close(ctx)

	var docs []*models.Document
	if err = cursor.All(ctx, &docs); err != nil {
		slog.Error("Failed to decode documents", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "error", err)
		return nil, fmt.Errorf("failed to decode documents: %w", err)
	}

	slog.Info("Documents fetched successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "count", len(docs))

	return docs, nil
}

func (r *mongoDocumentRepo) Update(ctx context.Context, doc *models.Document) error {

	doc.UpdatedAt = time.Now()
	doc.DataIntegrityHash = r.computeDataIntegrityHash(doc)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"document_id": doc.DocumentID},
		bson.M{"$set": doc},
		cUpdate(ctx),
	)
	if err != nil {

		return fmt.Errorf("failed to update document: %w", err)
	}
	slog.Info("Document updated successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "document_id", doc.DocumentID)

	if result.MatchedCount == 0 {
		return fmt.Errorf("document not found")
	}

	return nil
}

func (r *mongoDocumentRepo) Delete(ctx context.Context, id string) error {

	result, err := r.collection.DeleteOne(ctx, bson.M{"document_id": id}, cDelete(ctx))
	if err != nil {

		return fmt.Errorf("failed to delete document: %w", err)
	}

	if result.DeletedCount == 0 {
		slog.Error("Document not found", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "document_id", id)
		return fmt.Errorf("document not found")
	}
	slog.Info("Document deleted successfully", "user_id", ctx.Value("user_id"), "req_id", ctx.Value("req_id"), "document_id", id)

	return nil
}
