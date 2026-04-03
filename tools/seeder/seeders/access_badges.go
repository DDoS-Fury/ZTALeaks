// =============================================================================
// Seeder: access_badges
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Populates the access_badges collection with badge records for all employees.
// Each badge includes access log entries with contextual information
// (device type, network segment) to support physical-digital access correlation
// in the Zero Trust model.
// =============================================================================

package seeders

import (
	"context"
	"fmt"
	"log"
	"time"

	"nuclear-zta-seed/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// SeedAccessBadges inserts badge records with access logs into the collection.
func SeedAccessBadges(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("access_badges")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		log.Println("[SEED] access_badges already populated, skipping")
		return
	}

	today := time.Now()

	badges := []interface{}{
		// Plant Manager badge - full access
		models.AccessBadge{
			BadgeID:             "BDG-00001",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0001",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-AUX-01", "ZONE-SF-01", "ZONE-ADM-01"},
			IssueDate:           time.Date(2005, 3, 15, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-2 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeWorkstation, Network: models.NetworkPlantInternal},
				},
				{
					Timestamp:   today.Add(-90 * time.Minute),
					GateID:      "GATE-ADM-01",
					Direction:   "in",
					ZoneEntered: "ZONE-ADM-01",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeWorkstation, Network: models.NetworkAdmin},
				},
			},
		},

		// Operator 1 badge
		models.AccessBadge{
			BadgeID:             "BDG-00142",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0142",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-TB-01", "ZONE-AUX-01"},
			IssueDate:           time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-3 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTerminal, Network: models.NetworkPlantInternal},
				},
				{
					Timestamp:   today.Add(-170 * time.Minute),
					GateID:      "GATE-CR-01",
					Direction:   "in",
					ZoneEntered: "ZONE-CR-01",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTerminal, Network: models.NetworkControlRoom},
				},
			},
		},

		// Operator 2 badge
		models.AccessBadge{
			BadgeID:             "BDG-00143",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0143",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-TB-01"},
			IssueDate:           time.Date(2021, 9, 1, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-4 * time.Hour),
					GateID:      "GATE-MAIN-02",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTerminal, Network: models.NetworkPlantInternal},
				},
			},
		},

		// Maintenance Technician badge
		models.AccessBadge{
			BadgeID:             "BDG-00201",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0201",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-TB-01", "ZONE-AUX-01"},
			IssueDate:           time.Date(2018, 2, 15, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2025, 8, 15, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-5 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTablet, Network: models.NetworkPlantInternal},
				},
				{
					Timestamp:   today.Add(-4 * time.Hour),
					GateID:      "GATE-TB-01",
					Direction:   "in",
					ZoneEntered: "ZONE-TB-01",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTablet, Network: models.NetworkPlantInternal},
				},
			},
		},

		// Radiation Protection Officer badge
		models.AccessBadge{
			BadgeID:             "BDG-00067",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0067",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-SF-01"},
			IssueDate:           time.Date(2017, 4, 10, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2025, 4, 10, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-6 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeWorkstation, Network: models.NetworkPlantInternal},
				},
				{
					Timestamp:   today.Add(-5 * time.Hour),
					GateID:      "GATE-RC-01",
					Direction:   "in",
					ZoneEntered: "ZONE-RC-01",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTerminal, Network: models.NetworkPlantInternal},
				},
				{
					Timestamp:   today.Add(-3 * time.Hour),
					GateID:      "GATE-RC-01",
					Direction:   "out",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTerminal, Network: models.NetworkPlantInternal},
				},
			},
		},

		// Security Officer badge
		models.AccessBadge{
			BadgeID:             "BDG-00180",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0180",
			Type:                models.BadgePermanent,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-SF-01", "ZONE-ADM-01"},
			IssueDate:           time.Date(2015, 8, 1, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-8 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeWorkstation, Network: models.NetworkPlantInternal},
				},
			},
		},

		// Inspector badge - temporary, external
		models.AccessBadge{
			BadgeID:             "BDG-00300",
			ClassificationLevel: models.ClassConfidential,
			EmployeeID:          "NP-2024-0300",
			Type:                models.BadgeTemporary,
			AuthorizedZones:     []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-SF-01", "ZONE-ADM-01"},
			IssueDate:           time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC),
			ExpiryDate:          time.Date(2025, 1, 20, 0, 0, 0, 0, time.UTC),
			Status:              "active",
			AccessLog: []models.AccessLogEntry{
				{
					Timestamp:   today.Add(-1 * time.Hour),
					GateID:      "GATE-MAIN-01",
					Direction:   "in",
					ZoneEntered: "ZONE-MAIN",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeMobile, Network: models.NetworkVPN},
				},
				{
					Timestamp:   today.Add(-30 * time.Minute),
					GateID:      "GATE-SF-01",
					Direction:   "in",
					ZoneEntered: "ZONE-SF-01",
					Status:      "granted",
					Context:     models.AccessContext{DeviceType: models.DeviceTypeTablet, Network: models.NetworkPlantInternal},
				},
			},
		},
	}

	result, err := coll.InsertMany(ctx, badges)
	if err != nil {
		log.Fatalf("[SEED] Failed to seed access_badges: %v", err)
	}
	fmt.Printf("[SEED] Inserted %d access badges\n", len(result.InsertedIDs))
}