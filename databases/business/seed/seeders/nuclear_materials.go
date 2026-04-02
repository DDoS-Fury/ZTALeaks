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

func SeedNuclearMaterials(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("nuclear_materials")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		fmt.Println("⏭️  nuclear_materials already seeded, skipping")
		return
	}

	loaded := time.Date(2022, 9, 1, 0, 0, 0, 0, time.UTC)
	discharge := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	loaded2 := time.Date(2023, 3, 15, 0, 0, 0, 0, time.UTC)
	discharge2 := time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)

	materials := []interface{}{
		// Fuel assembly in reactor
		models.NuclearMaterial{
			MaterialID:          "NM-UO2-2022-0056",
			ClassificationLevel: models.ClassTopSecret,
			Type:                models.MatFuelAssembly,
			Description:         "Elemento di combustibile UO2 arricchito 4.5%",
			EnrichmentPercent:   4.5,
			MassKG:              461.3,
			InitialU235KG:       20.8,
			Status:              models.MatInReactor,
			Location: models.MaterialLocation{
				ZoneID:   "ZONE-RC-01",
				Position: "Core position H-7",
			},
			BurnupMWDT:  35000,
			CycleLoaded: 18,
			Dates: models.MaterialDates{
				Received:          time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
				Loaded:            &loaded,
				ExpectedDischarge: &discharge,
			},
			Supplier:     "FRAMATOME",
			SerialNumber: "FA-2022-H7-056",
			IAEASafeguards: models.IAEASafeguards{
				SealID:         "IAEA-SEAL-2022-4521",
				LastInspection: time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC),
				NextInspection: time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
			},
			Accountability: models.Accountability{
				LastInventory: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				VerifiedBy:    "NP-2024-0001",
			},
		},

		// Another fuel assembly in reactor
		models.NuclearMaterial{
			MaterialID:          "NM-UO2-2023-0012",
			ClassificationLevel: models.ClassTopSecret,
			Type:                models.MatFuelAssembly,
			Description:         "Elemento di combustibile UO2 arricchito 4.2%",
			EnrichmentPercent:   4.2,
			MassKG:              458.7,
			InitialU235KG:       19.3,
			Status:              models.MatInReactor,
			Location: models.MaterialLocation{
				ZoneID:   "ZONE-RC-01",
				Position: "Core position D-4",
			},
			BurnupMWDT:  22000,
			CycleLoaded: 19,
			Dates: models.MaterialDates{
				Received:          time.Date(2023, 1, 20, 0, 0, 0, 0, time.UTC),
				Loaded:            &loaded2,
				ExpectedDischarge: &discharge2,
			},
			Supplier:     "FRAMATOME",
			SerialNumber: "FA-2023-D4-012",
			IAEASafeguards: models.IAEASafeguards{
				SealID:         "IAEA-SEAL-2023-1102",
				LastInspection: time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC),
				NextInspection: time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
			},
			Accountability: models.Accountability{
				LastInventory: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				VerifiedBy:    "NP-2024-0001",
			},
		},

		// Spent fuel in pool
		models.NuclearMaterial{
			MaterialID:          "NM-UO2-2018-0034",
			ClassificationLevel: models.ClassTopSecret,
			Type:                models.MatSpentFuel,
			Description:         "Elemento di combustibile esausto UO2 - scaricato ciclo 15",
			EnrichmentPercent:   3.8,
			MassKG:              455.0,
			InitialU235KG:       17.3,
			Status:              models.MatSpentPool,
			Location: models.MaterialLocation{
				ZoneID:   "ZONE-SF-01",
				Position: "Spent fuel pool rack B-12",
			},
			BurnupMWDT:  55000,
			CycleLoaded: 12,
			Dates: models.MaterialDates{
				Received: time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC),
				Loaded:   &loaded,
			},
			Supplier:     "WESTINGHOUSE",
			SerialNumber: "WH-2018-B12-034",
			IAEASafeguards: models.IAEASafeguards{
				SealID:         "IAEA-SEAL-2021-0890",
				LastInspection: time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC),
				NextInspection: time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
			},
			Accountability: models.Accountability{
				LastInventory: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				VerifiedBy:    "NP-2024-0001",
			},
		},

		// Fresh fuel in storage
		models.NuclearMaterial{
			MaterialID:          "NM-UO2-2024-0001",
			ClassificationLevel: models.ClassTopSecret,
			Type:                models.MatFuelAssembly,
			Description:         "Elemento di combustibile fresco UO2 arricchito 4.95% - per ciclo 21",
			EnrichmentPercent:   4.95,
			MassKG:              463.0,
			InitialU235KG:       22.9,
			Status:              models.MatInStorage,
			Location: models.MaterialLocation{
				ZoneID:   "ZONE-SF-01",
				Position: "Fresh fuel storage rack A-1",
			},
			Dates: models.MaterialDates{
				Received: time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC),
			},
			Supplier:     "FRAMATOME",
			SerialNumber: "FA-2024-NEW-001",
			IAEASafeguards: models.IAEASafeguards{
				SealID:         "IAEA-SEAL-2024-7700",
				LastInspection: time.Date(2024, 12, 15, 0, 0, 0, 0, time.UTC),
				NextInspection: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			},
			Accountability: models.Accountability{
				LastInventory: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				VerifiedBy:    "NP-2024-0001",
			},
		},

		// Radioactive waste
		models.NuclearMaterial{
			MaterialID:          "NM-WST-2024-0100",
			ClassificationLevel: models.ClassSecret,
			Type:                models.MatWaste,
			Description:         "Rifiuto radioattivo a media attività - resine esaurite",
			MassKG:              120.0,
			Status:              models.MatInStorage,
			Location: models.MaterialLocation{
				ZoneID:   "ZONE-SF-01",
				Position: "Waste storage area W-3",
			},
			Dates: models.MaterialDates{
				Received: time.Date(2024, 9, 15, 0, 0, 0, 0, time.UTC),
			},
			Supplier:     "Internal",
			SerialNumber: "WST-RES-2024-100",
			IAEASafeguards: models.IAEASafeguards{
				SealID:         "IAEA-SEAL-2024-8801",
				LastInspection: time.Date(2024, 12, 15, 0, 0, 0, 0, time.UTC),
				NextInspection: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			},
			Accountability: models.Accountability{
				LastInventory: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				VerifiedBy:    "NP-2024-0001",
			},
		},
	}

	result, err := coll.InsertMany(ctx, materials)
	if err != nil {
		log.Fatal("❌ Failed to seed nuclear_materials:", err)
	}
	fmt.Printf("✅ Inserted %d nuclear materials\n", len(result.InsertedIDs))
}
