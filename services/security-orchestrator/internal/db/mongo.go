// =============================================================================
// MongoDB Client — connessione READ-ONLY al security DB
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Identity-service è il proprietario logico del DB; orchestrator legge solo
// device_fingerprints (per tpm_verified) e potenzialmente jwt_blocklist.
// =============================================================================

package db

import (
	"context"
	"log/slog"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Client struct {
	c  *mongo.Client
	db *mongo.Database
}

func Connect(ctx context.Context) (*Client, error) {
	uri := os.Getenv("SECURITY_DB_URI")
	if uri == "" {
		uri = "mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin"
	}
	dbName := os.Getenv("SECURITY_DB_NAME")
	if dbName == "" {
		dbName = "securitydb"
	}
	slog.Info("connessione security-db", "uri", uri, "db", dbName)

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	c, err := mongo.Connect(connectCtx, options.Client().ApplyURI(uri).SetAppName("security-orchestrator").SetMaxPoolSize(20))
	if err != nil {
		return nil, err
	}
	if err := c.Ping(connectCtx, nil); err != nil {
		return nil, err
	}
	return &Client{c: c, db: c.Database(dbName)}, nil
}

func (c *Client) DB() *mongo.Database { return c.db }

func (c *Client) Disconnect() {
	if c == nil || c.c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.c.Disconnect(ctx)
}
