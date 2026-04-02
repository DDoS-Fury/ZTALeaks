// =============================================================================
// Seeder: zones
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Populates the zones collection with the physical areas of the nuclear plant.
// Each zone includes ZTNA policy parameters that define the Zero Trust access
// requirements: minimum trust score, MFA enforcement, session duration limits,
// permitted device types, and allowed network segments.
//
// Zone hierarchy:
//   ZONE-MAIN (root)
//     +-- ZONE-CR-01   (control room)
//     +-- ZONE-RC-01   (reactor containment)
//     |     +-- ZONE-RC-01A (containment lower level)
//     |     +-- ZONE-RC-01B (containment upper level)
//     +-- ZONE-TB-01   (turbine hall)
//     +-- ZONE-AUX-01  (auxiliary building)
//     +-- ZONE-SF-01   (spent fuel storage)
//     +-- ZONE-ADM-01  (administration building)
// =============================================================================

package seeders

import (
	"context"
	"fmt"
	"log"

	"nuclear-zta-seed/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// strPtr returns a pointer to the given string. Used for optional fields.
func strPtr(s string) *string {
	return &s
}

// SeedZones inserts all plant zone definitions into the zones collection.
// Skips insertion if the collection already contains data (idempotent).
func SeedZones(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("zones")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		log.Println("[SEED] zones already populated, skipping")
		return
	}

	zones := []interface{}{
		// -----------------------------------------------------------------
		// ZONE-MAIN: Root zone encompassing the entire plant campus.
		// Controlled access with basic PPE requirements.
		// ZTNA: Moderate trust score, no MFA required, broad device/network access.
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.3,
				RequireMFA:                false,
				MaxSessionDurationMinutes: 480,
				AllowedDeviceTypes:        []string{models.DeviceTypeWorkstation, models.DeviceTypeMobile, models.DeviceTypeTablet},
				AllowedNetworks:           []string{models.NetworkPlantInternal, models.NetworkAdmin, models.NetworkVPN},
				ContinuousMonitoring:      false,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-CR-01: Main Control Room - restricted to licensed operators.
		// ZTNA: High trust score, MFA required, control terminals only,
		//       control room network only, continuous monitoring enabled.
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.7,
				RequireMFA:                true,
				MaxSessionDurationMinutes: 240,
				AllowedDeviceTypes:        []string{models.DeviceTypeTerminal, models.DeviceTypeWorkstation},
				AllowedNetworks:           []string{models.NetworkControlRoom, models.NetworkPlantInternal},
				ContinuousMonitoring:      true,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-RC-01: Reactor Containment Building - highest restriction.
		// ZTNA: Very high trust score, MFA mandatory, short sessions,
		//       control terminals only, plant internal network only.
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.85,
				RequireMFA:                true,
				MaxSessionDurationMinutes: 120,
				AllowedDeviceTypes:        []string{models.DeviceTypeTerminal},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      true,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-RC-01A: Reactor Containment - Lower Level
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.9,
				RequireMFA:                true,
				MaxSessionDurationMinutes: 60,
				AllowedDeviceTypes:        []string{models.DeviceTypeTerminal},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      true,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-RC-01B: Reactor Containment - Upper Level
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.85,
				RequireMFA:                true,
				MaxSessionDurationMinutes: 90,
				AllowedDeviceTypes:        []string{models.DeviceTypeTerminal},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      true,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-TB-01: Turbine Hall
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.5,
				RequireMFA:                false,
				MaxSessionDurationMinutes: 360,
				AllowedDeviceTypes:        []string{models.DeviceTypeWorkstation, models.DeviceTypeTablet},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      false,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-AUX-01: Auxiliary Building
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.5,
				RequireMFA:                false,
				MaxSessionDurationMinutes: 360,
				AllowedDeviceTypes:        []string{models.DeviceTypeWorkstation, models.DeviceTypeTablet},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      false,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-SF-01: Spent Fuel Storage - TOP_SECRET classification.
		// ZTNA: Maximum trust score, MFA mandatory, very short sessions,
		//       control terminals only, continuous monitoring.
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.9,
				RequireMFA:                true,
				MaxSessionDurationMinutes: 60,
				AllowedDeviceTypes:        []string{models.DeviceTypeTerminal},
				AllowedNetworks:           []string{models.NetworkPlantInternal},
				ContinuousMonitoring:      true,
			},
		},

		// -----------------------------------------------------------------
		// ZONE-ADM-01: Administration Building - lower restriction.
		// -----------------------------------------------------------------
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
			ZTNAPolicy: models.ZTNAPolicy{
				MinTrustScore:             0.2,
				RequireMFA:                false,
				MaxSessionDurationMinutes: 480,
				AllowedDeviceTypes:        []string{models.DeviceTypeWorkstation, models.DeviceTypeMobile, models.DeviceTypeTablet},
				AllowedNetworks:           []string{models.NetworkPlantInternal, models.NetworkAdmin, models.NetworkVPN},
				ContinuousMonitoring:      false,
			},
		},
	}

	result, err := coll.InsertMany(ctx, zones)
	if err != nil {
		log.Fatalf("[SEED] Failed to seed zones: %v", err)
	}
	log.Printf("[SEED] Inserted %d zones", len(result.InsertedIDs))
}