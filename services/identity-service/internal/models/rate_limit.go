package models

import (
	"time"
)

// RateLimit tiene traccia dei tentativi falliti per IP per limitare attacchi brute-force.
type RateLimit struct {
	IP        string    `json:"ip" bson:"_id"` // Usiamo l'IP come ID
	Attempts  int       `json:"attempts" bson:"attempts"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
}
