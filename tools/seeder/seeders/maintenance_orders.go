// =============================================================================
// Seeder: maintenance_orders
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Populates the maintenance_orders collection with work orders in various
// lifecycle states (created, scheduled, in_progress, completed) and
// different priority/safety classifications to enable realistic policy testing.
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

// SeedMaintenanceOrders inserts maintenance work orders into the collection.
func SeedMaintenanceOrders(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("maintenance_orders")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		log.Println("[SEED] maintenance_orders already populated, skipping")
		return
	}

	approved := time.Date(2025, 1, 10, 14, 0, 0, 0, time.UTC)
	schedStart := time.Date(2025, 1, 15, 6, 0, 0, 0, time.UTC)
	schedEnd := time.Date(2025, 1, 15, 18, 0, 0, 0, time.UTC)
	actStart := time.Date(2025, 1, 15, 6, 30, 0, 0, time.UTC)

	preventiveDate := time.Date(2025, 2, 1, 8, 0, 0, 0, time.UTC)
	preventiveEnd := time.Date(2025, 2, 1, 16, 0, 0, 0, time.UTC)

	completedStart := time.Date(2024, 12, 10, 7, 0, 0, 0, time.UTC)
	completedEnd := time.Date(2024, 12, 10, 15, 30, 0, 0, time.UTC)

	orders := []interface{}{
		// Corrective - in progress, high priority, safety-related
		models.MaintenanceOrder{
			OrderID:              "MO-2025-0234",
			ClassificationLevel:  models.ClassInternal,
			Title:                "Sostituzione guarnizione pompa primaria P-101",
			Type:                 models.MaintCorrective,
			Priority:             models.PriorityHigh,
			System:               "primary_coolant",
			EquipmentID:          "PUMP-P-101",
			ZoneID:               "ZONE-RC-01",
			Description:          "Rilevata perdita minima dalla guarnizione meccanica della pompa P-101. Necessaria sostituzione durante prossimo outage programmato.",
			SafetyClassification: models.SafetyRelated,
			RequestedBy:          "NP-2024-0142",
			AssignedTo:           []string{"NP-2024-0201"},
			Status:               models.StatusInProgress,
			Dates: models.MaintenanceDates{
				Created:        time.Date(2025, 1, 10, 8, 0, 0, 0, time.UTC),
				Approved:       &approved,
				ScheduledStart: &schedStart,
				ScheduledEnd:   &schedEnd,
				ActualStart:    &actStart,
				ActualEnd:      nil,
			},
			PartsRequired: []models.Part{
				{PartID: "PART-GK-4521", Name: "Guarnizione meccanica tipo A", Quantity: 1, Status: "in_stock"},
				{PartID: "PART-BL-1100", Name: "Kit bulloneria alta temperatura", Quantity: 1, Status: "in_stock"},
			},
			RadiationWorkPermit: "RWP-2025-0045",
			EstimatedDoseMSV:    0.5,
			Procedures:          []string{"PROC-MNT-045", "PROC-RP-012"},
			ApprovalChain: []models.Approval{
				{
					Role:       "maintenance_supervisor",
					ApprovedBy: "NP-2024-0201",
					Date:       time.Date(2025, 1, 10, 14, 0, 0, 0, time.UTC),
					Status:     "approved",
				},
				{
					Role:       "radiation_protection",
					ApprovedBy: "NP-2024-0067",
					Date:       time.Date(2025, 1, 11, 9, 0, 0, 0, time.UTC),
					Status:     "approved",
				},
			},
		},

		// Preventive - scheduled
		models.MaintenanceOrder{
			OrderID:              "MO-2025-0240",
			ClassificationLevel:  models.ClassInternal,
			Title:                "Ispezione periodica valvole di sicurezza del pressurizzatore",
			Type:                 models.MaintPreventive,
			Priority:             models.PriorityMedium,
			System:               "reactor_protection",
			EquipmentID:          "VALVE-PSV-201A",
			ZoneID:               "ZONE-RC-01",
			Description:          "Ispezione e test periodico semestrale delle valvole di sicurezza del pressurizzatore come da programma di manutenzione preventiva.",
			SafetyClassification: models.SafetyRelated,
			RequestedBy:          "NP-2024-0001",
			AssignedTo:           []string{"NP-2024-0201"},
			Status:               models.StatusScheduled,
			Dates: models.MaintenanceDates{
				Created:        time.Date(2025, 1, 5, 10, 0, 0, 0, time.UTC),
				Approved:       &approved,
				ScheduledStart: &preventiveDate,
				ScheduledEnd:   &preventiveEnd,
			},
			PartsRequired: []models.Part{
				{PartID: "PART-TK-8800", Name: "Kit test tenuta valvola", Quantity: 1, Status: "in_stock"},
			},
			RadiationWorkPermit: "RWP-2025-0051",
			EstimatedDoseMSV:    0.3,
			Procedures:          []string{"PROC-MNT-101", "PROC-RP-012"},
			ApprovalChain: []models.Approval{
				{
					Role:       "plant_manager",
					ApprovedBy: "NP-2024-0001",
					Date:       time.Date(2025, 1, 6, 11, 0, 0, 0, time.UTC),
					Status:     "approved",
				},
			},
		},

		// Completed - low priority
		models.MaintenanceOrder{
			OrderID:              "MO-2024-0890",
			ClassificationLevel:  models.ClassInternal,
			Title:                "Sostituzione filtri sistema di ventilazione edificio ausiliario",
			Type:                 models.MaintPreventive,
			Priority:             models.PriorityLow,
			System:               "hvac",
			EquipmentID:          "AHU-AUX-03",
			ZoneID:               "ZONE-AUX-01",
			Description:          "Sostituzione programmata dei filtri HEPA del sistema di ventilazione dell'edificio ausiliario.",
			SafetyClassification: models.AugmentedQuality,
			RequestedBy:          "NP-2024-0201",
			AssignedTo:           []string{"NP-2024-0201"},
			Status:               models.StatusCompleted,
			Dates: models.MaintenanceDates{
				Created:        time.Date(2024, 12, 1, 8, 0, 0, 0, time.UTC),
				Approved:       &approved,
				ScheduledStart: &completedStart,
				ScheduledEnd:   &completedEnd,
				ActualStart:    &completedStart,
				ActualEnd:      &completedEnd,
			},
			PartsRequired: []models.Part{
				{PartID: "PART-FH-2200", Name: "Filtro HEPA H14", Quantity: 4, Status: "installed"},
			},
			EstimatedDoseMSV: 0.05,
			Procedures:       []string{"PROC-MNT-210"},
			ApprovalChain: []models.Approval{
				{
					Role:       "maintenance_supervisor",
					ApprovedBy: "NP-2024-0201",
					Date:       time.Date(2024, 12, 2, 9, 0, 0, 0, time.UTC),
					Status:     "approved",
				},
			},
		},

		// Critical - newly created, emergency ECCS repair
		models.MaintenanceOrder{
			OrderID:              "MO-2025-0250",
			ClassificationLevel:  models.ClassConfidential,
			Title:                "Riparazione urgente sistema di raffreddamento di emergenza ECCS",
			Type:                 models.MaintCorrective,
			Priority:             models.PriorityCritical,
			System:               "emergency_core_cooling",
			EquipmentID:          "PUMP-ECCS-01B",
			ZoneID:               "ZONE-RC-01",
			Description:          "Rilevato anomalo rumore cuscinetti sulla pompa ECCS-01B durante test periodico. Richiesta ispezione e sostituzione immediata cuscinetti.",
			SafetyClassification: models.SafetyRelated,
			RequestedBy:          "NP-2024-0142",
			AssignedTo:           []string{"NP-2024-0201"},
			Status:               models.StatusCreated,
			Dates: models.MaintenanceDates{
				Created: time.Date(2025, 1, 16, 10, 0, 0, 0, time.UTC),
			},
			PartsRequired: []models.Part{
				{PartID: "PART-BR-5500", Name: "Cuscinetto radiale pompa ECCS", Quantity: 2, Status: "ordered"},
			},
			RadiationWorkPermit: "",
			EstimatedDoseMSV:    0.8,
			Procedures:          []string{"PROC-MNT-050", "PROC-RP-012", "PROC-EM-ECCS"},
			ApprovalChain:       []models.Approval{},
		},
	}

	result, err := coll.InsertMany(ctx, orders)
	if err != nil {
		log.Fatalf("[SEED] Failed to seed maintenance_orders: %v", err)
	}
	fmt.Printf("[SEED] Inserted %d maintenance orders\n", len(result.InsertedIDs))
}