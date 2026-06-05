package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	_, err := r.collection.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to create document: %w", err)
	}

	return nil
}

func (r *mongoDocumentRepo) GetByID(ctx context.Context, id string) (*models.Document, error) {

	var doc models.Document
	err := r.collection.FindOne(ctx, bson.M{"document_id": id}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("document not found")
		}
		return nil, fmt.Errorf("failed to fetch document: %w", err)
	}

	return &doc, nil
}

func (r *mongoDocumentRepo) GetAll(ctx context.Context) ([]*models.Document, error) {

	opts := options.Find().SetSort(bson.D{{Key: "document_id", Value: 1}})
	cursor, err := r.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch documents: %w", err)
	}
	defer cursor.Close(ctx)

	var docs []*models.Document
	if err = cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("failed to decode documents: %w", err)
	}

	return docs, nil
}

func (r *mongoDocumentRepo) Update(ctx context.Context, doc *models.Document) error {

	doc.UpdatedAt = time.Now()
	doc.DataIntegrityHash = r.computeDataIntegrityHash(doc)

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"document_id": doc.DocumentID},
		bson.M{"$set": doc},
	)
	if err != nil {

		return fmt.Errorf("failed to update document: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("document not found")
	}

	return nil
}

func (r *mongoDocumentRepo) Delete(ctx context.Context, id string) error {

	result, err := r.collection.DeleteOne(ctx, bson.M{"document_id": id})
	if err != nil {

		return fmt.Errorf("failed to delete document: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("document not found")
	}

	return nil
}
