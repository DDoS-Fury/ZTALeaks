// =============================================================================
// Seeder: reactor_parameters
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Populates the reactor_parameters collection with time-series operational
// data including a SHA-256 data integrity hash for tamper detection.
// The hash covers critical parameter values and can be verified by the
// security orchestrator to ensure data has not been altered in transit.
// =============================================================================

package seeders

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"nuclear-zta-seed/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// computeIntegrityHash generates a SHA-256 hash of critical reactor parameters
// for tamper detection. In production, this would use HMAC with a secret key.
func computeIntegrityHash(thermalMW, electricalMW, pressureMPA, neutronFlux float64, boronPPM int, status string) string {
	data := fmt.Sprintf("%.2f|%.2f|%.3f|%.4e|%d|%s",
		thermalMW, electricalMW, pressureMPA, neutronFlux, boronPPM, status)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// SeedReactorParameters inserts reactor operational readings into the collection.
func SeedReactorParameters(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("reactor_parameters")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		log.Println("[SEED] reactor_parameters already populated, skipping")
		return
	}

	baseTime := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)

	params := []interface{}{
		// Shift A reading (06:00) - normal power operation
		models.ReactorParameters{
			ClassificationLevel: models.ClassSecret,
			Timestamp:           baseTime.Add(6 * time.Hour),
			ReactorID:           "REACTOR-01",
			ThermalPowerMW:      3200.5,
			ElectricalPowerMW:   1050.2,
			CoolantTempInletC:   291.3,
			CoolantTempOutletC:  325.7,
			CoolantPressureMPA:  15.5,
			CoolantFlowRateKgS:  18500,
			NeutronFlux:         2.5e13,
			ControlRodPositions: []models.ControlRodPosition{
				{RodGroup: "A", PositionPercent: 85.2},
				{RodGroup: "B", PositionPercent: 90.1},
				{RodGroup: "C", PositionPercent: 78.4},
				{RodGroup: "D", PositionPercent: 92.0},
			},
			BoronConcentrationPPM: 1200,
			ReactorStatus:         models.ReactorPowerOperation,
			ScramStatus:           false,
			Alerts:                []string{},
			RecordedBy:            "NP-2024-0142",
			ShiftID:               "SHIFT-2025-01-15-A",
			DataIntegrityHash:     computeIntegrityHash(3200.5, 1050.2, 15.5, 2.5e13, 1200, models.ReactorPowerOperation),
		},

		// Shift B reading (14:00) - normal power operation
		models.ReactorParameters{
			ClassificationLevel: models.ClassSecret,
			Timestamp:           baseTime.Add(14 * time.Hour),
			ReactorID:           "REACTOR-01",
			ThermalPowerMW:      3198.1,
			ElectricalPowerMW:   1049.5,
			CoolantTempInletC:   291.5,
			CoolantTempOutletC:  325.4,
			CoolantPressureMPA:  15.5,
			CoolantFlowRateKgS:  18490,
			NeutronFlux:         2.48e13,
			ControlRodPositions: []models.ControlRodPosition{
				{RodGroup: "A", PositionPercent: 85.0},
				{RodGroup: "B", PositionPercent: 90.0},
				{RodGroup: "C", PositionPercent: 78.5},
				{RodGroup: "D", PositionPercent: 91.8},
			},
			BoronConcentrationPPM: 1198,
			ReactorStatus:         models.ReactorPowerOperation,
			ScramStatus:           false,
			Alerts:                []string{},
			RecordedBy:            "NP-2024-0143",
			ShiftID:               "SHIFT-2025-01-15-B",
			DataIntegrityHash:     computeIntegrityHash(3198.1, 1049.5, 15.5, 2.48e13, 1198, models.ReactorPowerOperation),
		},

		// Shift C reading (22:00) - minor alert
		models.ReactorParameters{
			ClassificationLevel: models.ClassSecret,
			Timestamp:           baseTime.Add(22 * time.Hour),
			ReactorID:           "REACTOR-01",
			ThermalPowerMW:      3195.0,
			ElectricalPowerMW:   1048.0,
			CoolantTempInletC:   291.8,
			CoolantTempOutletC:  326.1,
			CoolantPressureMPA:  15.6,
			CoolantFlowRateKgS:  18480,
			NeutronFlux:         2.51e13,
			ControlRodPositions: []models.ControlRodPosition{
				{RodGroup: "A", PositionPercent: 84.8},
				{RodGroup: "B", PositionPercent: 89.5},
				{RodGroup: "C", PositionPercent: 78.2},
				{RodGroup: "D", PositionPercent: 91.5},
			},
			BoronConcentrationPPM: 1195,
			ReactorStatus:         models.ReactorPowerOperation,
			ScramStatus:           false,
			Alerts:                []string{"Minor coolant pressure fluctuation detected"},
			RecordedBy:            "NP-2024-0142",
			ShiftID:               "SHIFT-2025-01-15-C",
			DataIntegrityHash:     computeIntegrityHash(3195.0, 1048.0, 15.6, 2.51e13, 1195, models.ReactorPowerOperation),
		},

		// Previous day - hot standby for maintenance
		models.ReactorParameters{
			ClassificationLevel: models.ClassSecret,
			Timestamp:           baseTime.Add(-18 * time.Hour),
			ReactorID:           "REACTOR-01",
			ThermalPowerMW:      0,
			ElectricalPowerMW:   0,
			CoolantTempInletC:   285.0,
			CoolantTempOutletC:  285.5,
			CoolantPressureMPA:  15.5,
			CoolantFlowRateKgS:  5000,
			NeutronFlux:         1.0e8,
			ControlRodPositions: []models.ControlRodPosition{
				{RodGroup: "A", PositionPercent: 0},
				{RodGroup: "B", PositionPercent: 0},
				{RodGroup: "C", PositionPercent: 0},
				{RodGroup: "D", PositionPercent: 0},
			},
			BoronConcentrationPPM: 2000,
			ReactorStatus:         models.ReactorHotStandby,
			ScramStatus:           false,
			Alerts:                []string{"Reactor in hot standby for scheduled maintenance"},
			RecordedBy:            "NP-2024-0143",
			ShiftID:               "SHIFT-2025-01-14-A",
			DataIntegrityHash:     computeIntegrityHash(0, 0, 15.5, 1.0e8, 2000, models.ReactorHotStandby),
		},

		// Startup after maintenance
		models.ReactorParameters{
			ClassificationLevel: models.ClassSecret,
			Timestamp:           baseTime.Add(-6 * time.Hour),
			ReactorID:           "REACTOR-01",
			ThermalPowerMW:      800.0,
			ElectricalPowerMW:   250.0,
			CoolantTempInletC:   288.0,
			CoolantTempOutletC:  310.0,
			CoolantPressureMPA:  15.4,
			CoolantFlowRateKgS:  15000,
			NeutronFlux:         5.0e12,
			ControlRodPositions: []models.ControlRodPosition{
				{RodGroup: "A", PositionPercent: 40.0},
				{RodGroup: "B", PositionPercent: 45.0},
				{RodGroup: "C", PositionPercent: 35.0},
				{RodGroup: "D", PositionPercent: 50.0},
			},
			BoronConcentrationPPM: 1600,
			ReactorStatus:         models.ReactorStartup,
			ScramStatus:           false,
			Alerts:                []string{},
			RecordedBy:            "NP-2024-0142",
			ShiftID:               "SHIFT-2025-01-14-C",
			DataIntegrityHash:     computeIntegrityHash(800.0, 250.0, 15.4, 5.0e12, 1600, models.ReactorStartup),
		},
	}

	result, err := coll.InsertMany(ctx, params)
	if err != nil {
		log.Fatalf("[SEED] Failed to seed reactor_parameters: %v", err)
	}
	fmt.Printf("[SEED] Inserted %d reactor parameter readings\n", len(result.InsertedIDs))
}