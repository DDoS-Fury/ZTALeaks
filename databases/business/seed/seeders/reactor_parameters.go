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

func SeedReactorParameters(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("reactor_parameters")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		fmt.Println("⏭️  reactor_parameters already seeded, skipping")
		return
	}

	baseTime := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)

	params := []interface{}{
		// Lettura turno A (06:00)
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
		},

		// Lettura turno B (14:00)
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
		},

		// Lettura turno C (22:00) - con alert
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
		},

		// Giorno precedente - Hot Standby
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
		},

		// Startup dopo manutenzione
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
		},
	}

	result, err := coll.InsertMany(ctx, params)
	if err != nil {
		log.Fatal("❌ Failed to seed reactor_parameters:", err)
	}
	fmt.Printf("✅ Inserted %d reactor parameter readings\n", len(result.InsertedIDs))
}
