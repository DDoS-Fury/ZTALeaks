// Package seed popola il Security DB con utenti di test multi-ruolo.
//
// Il seeding e' in Go (non in JS via mongo-init.js) perche' Argon2id non
// e' disponibile nello shell mongo: l'hash deve essere calcolato qui dal
// pacchetto crypto. Lasciato in un pacchetto separato cosi' il main resta
// pulito e il seeding e' facilmente disabilitabile in un futuro flag.
package seed

import (
	"context"
	"log/slog"
	"time"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/models"
)

type userSeed struct {
	username, email, role, clearance string
}

var defaultUsers = []userSeed{
	{"admin", "admin@ztaleaks.local", "plant_manager", "TOP_SECRET"},
	{"operator1", "operator1@ztaleaks.local", "operator", "CONFIDENTIAL"},
	{"maint_tech1", "maint_tech1@ztaleaks.local", "maintenance_technician", "INTERNAL"},
	{"rad_officer1", "rad_officer1@ztaleaks.local", "radiation_protection_officer", "SECRET"},
	{"sec_officer1", "sec_officer1@ztaleaks.local", "security_officer", "SECRET"},
	{"inspector1", "inspector1@ztaleaks.local", "inspector", "SECRET"},
}

const defaultPassword = "admin123"

// Users crea gli utenti di test multi-ruolo se non esistono. Idempotente:
// duplicati vengono saltati con un log debug. Non blocca il boot in caso di
// errore — il servizio puo' partire anche senza seeding (es. DB gia' popolato).
func Users(repo *db.UserRepository) {
	hash, err := crypto.GenerateFromPassword(defaultPassword)
	if err != nil {
		slog.Error("seed: hash password", "error", err)
		return
	}
	for _, s := range defaultUsers {
		u := &models.User{
			Username:     s.username,
			Email:        s.email,
			PasswordHash: hash,
			Role:         s.role,
			TwoFAEnabled: true,
			Status:       "active",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := repo.Create(ctx, u)
		cancel()
		if err != nil {
			slog.Debug("seed user skipped (probably already exists)", "username", s.username, "reason", err.Error())
			continue
		}
		slog.Info("seed user creato", "username", s.username, "role", s.role, "clearance", s.clearance)
	}
}
