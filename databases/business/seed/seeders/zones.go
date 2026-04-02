package seeders

import (
	"context"
	"fmt"
	"log"

	"nuclear-zta-seed/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func strPtr(s string) *string {
	return &s
}

func SeedZones(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("zones")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		fmt.Println("⏭️  zones already seeded, skipping")
		return
	}

	zones := []interface{}{
		models.Zone{
			ZoneID:                 "ZONE-MAIN",
			ClassificationLevel:    models.ClassInternal,
			Name:                   "Main Campus",
			Code:                   "main_campus",
			Type:                   models.ZoneControlled,
			RadiationZone:          false,
			RequiredClearance:      models.ClassInternal,
			RequiredQualifications: []string{},
			RequiredPPE:            []string{"dosimeter", "safety_helmet", "safety_boots"},
			MaxOccupancy:           500,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-MAIN-01", Type: "badge_reader", Status: "active"},
				{GateID: "GATE-MAIN-02", Type: "badge_reader", Status: "active"},
			},
			ParentZone: nil,
			SubZones:   []string{"ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-AUX-01", "ZONE-SF-01", "ZONE-ADM-01"},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-CR-01",
			ClassificationLevel:    models.ClassSecret,
			Name:                   "Main Control Room",
			Code:                   "control_room",
			Type:                   models.ZoneRestricted,
			RadiationZone:          false,
			RequiredClearance:      models.ClassSecret,
			RequiredQualifications: []string{"Reactor Operator License"},
			RequiredPPE:            []string{"dosimeter"},
			MaxOccupancy:           15,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-CR-01", Type: "biometric", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-RC-01",
			ClassificationLevel:    models.ClassSecret,
			Name:                   "Reactor Containment Building",
			Code:                   "containment",
			Type:                   models.ZoneExclusion,
			RadiationZone:          true,
			MaxRadiationLevel:      "very_high",
			RequiredClearance:      models.ClassSecret,
			RequiredQualifications: []string{"Radiation Safety Training", "Reactor Operator License"},
			RequiredPPE:            []string{"dosimeter", "protective_suit", "safety_helmet", "safety_boots", "respiratory_protection"},
			MaxOccupancy:           10,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-RC-01", Type: "biometric", Status: "active"},
				{GateID: "GATE-RC-02", Type: "airlock", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{"ZONE-RC-01A", "ZONE-RC-01B"},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-RC-01A",
			ClassificationLevel:    models.ClassSecret,
			Name:                   "Reactor Containment - Lower Level",
			Code:                   "containment_lower",
			Type:                   models.ZoneExclusion,
			RadiationZone:          true,
			MaxRadiationLevel:      "very_high",
			RequiredClearance:      models.ClassSecret,
			RequiredQualifications: []string{"Radiation Safety Training", "Reactor Operator License"},
			RequiredPPE:            []string{"dosimeter", "protective_suit", "safety_helmet", "safety_boots", "respiratory_protection"},
			MaxOccupancy:           5,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-RC-01A", Type: "airlock", Status: "active"},
			},
			ParentZone: strPtr("ZONE-RC-01"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-RC-01B",
			ClassificationLevel:    models.ClassSecret,
			Name:                   "Reactor Containment - Upper Level",
			Code:                   "containment_upper",
			Type:                   models.ZoneExclusion,
			RadiationZone:          true,
			MaxRadiationLevel:      "high",
			RequiredClearance:      models.ClassSecret,
			RequiredQualifications: []string{"Radiation Safety Training", "Reactor Operator License"},
			RequiredPPE:            []string{"dosimeter", "protective_suit", "safety_helmet", "safety_boots"},
			MaxOccupancy:           5,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-RC-01B", Type: "airlock", Status: "active"},
			},
			ParentZone: strPtr("ZONE-RC-01"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-TB-01",
			ClassificationLevel:    models.ClassConfidential,
			Name:                   "Turbine Hall",
			Code:                   "turbine_hall",
			Type:                   models.ZoneRestricted,
			RadiationZone:          false,
			RequiredClearance:      models.ClassConfidential,
			RequiredQualifications: []string{"General Safety Training"},
			RequiredPPE:            []string{"safety_helmet", "safety_boots", "ear_protection"},
			MaxOccupancy:           30,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-TB-01", Type: "badge_reader", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-AUX-01",
			ClassificationLevel:    models.ClassConfidential,
			Name:                   "Auxiliary Building",
			Code:                   "auxiliary",
			Type:                   models.ZoneRestricted,
			RadiationZone:          true,
			MaxRadiationLevel:      "medium",
			RequiredClearance:      models.ClassConfidential,
			RequiredQualifications: []string{"Radiation Safety Training"},
			RequiredPPE:            []string{"dosimeter", "safety_helmet", "safety_boots"},
			MaxOccupancy:           25,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-AUX-01", Type: "badge_reader", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-SF-01",
			ClassificationLevel:    models.ClassTopSecret,
			Name:                   "Spent Fuel Storage",
			Code:                   "spent_fuel",
			Type:                   models.ZoneExclusion,
			RadiationZone:          true,
			MaxRadiationLevel:      "high",
			RequiredClearance:      models.ClassTopSecret,
			RequiredQualifications: []string{"Radiation Safety Training", "Nuclear Materials Handling"},
			RequiredPPE:            []string{"dosimeter", "protective_suit", "safety_helmet", "safety_boots"},
			MaxOccupancy:           5,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-SF-01", Type: "biometric", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{},
			Status:     "operational",
		},
		models.Zone{
			ZoneID:                 "ZONE-ADM-01",
			ClassificationLevel:    models.ClassInternal,
			Name:                   "Administration Building",
			Code:                   "admin",
			Type:                   models.ZoneControlled,
			RadiationZone:          false,
			RequiredClearance:      models.ClassInternal,
			RequiredQualifications: []string{},
			RequiredPPE:            []string{},
			MaxOccupancy:           100,
			AccessPoints: []models.AccessPoint{
				{GateID: "GATE-ADM-01", Type: "badge_reader", Status: "active"},
			},
			ParentZone: strPtr("ZONE-MAIN"),
			SubZones:   []string{},
			Status:     "operational",
		},
	}

	result, err := coll.InsertMany(ctx, zones)
	if err != nil {
		log.Fatal("❌ Failed to seed zones:", err)
	}
	fmt.Printf("✅ Inserted %d zones\n", len(result.InsertedIDs))
}
