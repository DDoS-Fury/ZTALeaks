// =============================================================================
// TPM Lookup — verifica enrollment WebAuthn read-only su security-db
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Il JWT issued da identity-service contiene `device_id` quando l'utente ha
// enrollato un device. L'orchestrator verifica che quel credential_id esista
// in device_fingerprints e appartenga allo stesso user_id del claim sub.
// =============================================================================

package tpm

import (
	"context"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Lookup struct {
	coll *mongo.Collection
}

func New(db *mongo.Database) *Lookup {
	return &Lookup{coll: db.Collection("device_fingerprints")}
}

// Verify restituisce true se la coppia (credentialID, userID) esiste in DB.
// userID o credentialID vuoti → false (utente "senza TPM").
func (l *Lookup) Verify(ctx context.Context, userID, credentialID string) bool {
	if userID == "" || credentialID == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	count, err := l.coll.CountDocuments(ctx, bson.M{
		"credential_id": credentialID,
		"user_id":       userID,
	})
	if err != nil {
		slog.Warn("tpm lookup error", "user_id", userID, "credential_id", credentialID, "error", err)
		return false
	}
	return count > 0
}
