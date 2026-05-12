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

type DeviceCredential map[string]any

// Verify restituisce la mappa del device se la coppia (credentialID, userID) esiste in DB.
// Se non esiste, ritorna false, nil.
func (l *Lookup) Verify(ctx context.Context, userID, credentialID string) (bool, map[string]any) {
	if userID == "" || credentialID == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var result map[string]any
	err := l.coll.FindOne(ctx, bson.M{
		"credential_id": credentialID,
		"user_id":       userID,
	}).Decode(&result)

	if err != nil {
		if err != mongo.ErrNoDocuments {
			slog.Warn("tpm lookup error", "user_id", userID, "credential_id", credentialID, "error", err)
		}
		return false, nil
	}
	return true, result
}
