package db

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// MongoDBClient wraps the underlying mongo.Client
type MongoDBClient struct {
	Client *mongo.Client
}

// Connect establishes a connection to the MongoDB server using the provided URI.
func Connect(ctx context.Context, uri string) (*MongoDBClient, error) {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	return &MongoDBClient{Client: client}, nil
}

// Ping checks if the MongoDB connection is alive.
func (m *MongoDBClient) Ping(ctx context.Context) error {
	return m.Client.Ping(ctx, readpref.Primary())
}

// Disconnect gracefully shuts down the MongoDB connection.
func (m *MongoDBClient) Disconnect(ctx context.Context) error {
	return m.Client.Disconnect(ctx)
}
