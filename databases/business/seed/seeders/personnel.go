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

func SeedPersonnel(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("personnel")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		fmt.Println("⏭️  personnel already seeded, skipping")
		return
	}

	now := time.Now()

	personnel := []interface{}{
		// Plant Manager - TOP_SECRET clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0001",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Giuseppe",
			LastName:            "Ferretti",
			Role:                models.RolePlantManager,
			Department:          "management",
			ClearanceLevel:      models.ClassTopSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "Senior Reactor Operator License",
					IssuedBy:   "ISIN",
					IssueDate:  time.Date(2015, 1, 10, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{
				"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01",
				"ZONE-TB-01", "ZONE-AUX-01", "ZONE-SF-01", "ZONE-ADM-01",
			},
			BadgeID: "BDG-00001",
			Contact: models.Contact{
				Email: "g.ferretti@centralenucleare.it",
				Phone: "+39 071 5551001",
				EmergencyContact: &models.EmergencyContact{
					Name: "Maria Ferretti", Phone: "+39 333 1001001", Relation: "spouse",
				},
			},
			Status:           "active",
			HireDate:         time.Date(2005, 3, 15, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 10, 5, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2005, 3, 15, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Operator 1 - SECRET clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0142",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Marco",
			LastName:            "Bianchi",
			Role:                models.RoleOperator,
			Department:          "operations",
			ClearanceLevel:      models.ClassSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "Reactor Operator License",
					IssuedBy:   "ISIN",
					IssueDate:  time.Date(2022, 3, 15, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
				{
					Name:       "Radiation Safety Training",
					IssuedBy:   "Internal",
					IssueDate:  time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-TB-01", "ZONE-AUX-01"},
			BadgeID:       "BDG-00142",
			Contact: models.Contact{
				Email: "m.bianchi@centralenucleare.it",
				Phone: "+39 071 5551142",
				EmergencyContact: &models.EmergencyContact{
					Name: "Laura Bianchi", Phone: "+39 333 5551420", Relation: "spouse",
				},
			},
			Status:           "active",
			HireDate:         time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 11, 20, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Operator 2 - SECRET clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0143",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Luca",
			LastName:            "Romano",
			Role:                models.RoleOperator,
			Department:          "operations",
			ClearanceLevel:      models.ClassSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "Reactor Operator License",
					IssuedBy:   "ISIN",
					IssueDate:  time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-TB-01"},
			BadgeID:       "BDG-00143",
			Contact: models.Contact{
				Email: "l.romano@centralenucleare.it",
				Phone: "+39 071 5551143",
			},
			Status:           "active",
			HireDate:         time.Date(2021, 9, 1, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 10, 15, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2021, 9, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Maintenance Technician - CONFIDENTIAL clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0201",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Antonio",
			LastName:            "Russo",
			Role:                models.RoleMaintTech,
			Department:          "maintenance",
			ClearanceLevel:      models.ClassConfidential,
			Qualifications: []models.Qualification{
				{
					Name:       "Mechanical Maintenance Certification",
					IssuedBy:   "Internal",
					IssueDate:  time.Date(2021, 9, 1, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
				{
					Name:       "Radiation Safety Training",
					IssuedBy:   "Internal",
					IssueDate:  time.Date(2024, 2, 15, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 2, 15, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-TB-01", "ZONE-AUX-01"},
			BadgeID:       "BDG-00201",
			Contact: models.Contact{
				Email: "a.russo@centralenucleare.it",
				Phone: "+39 071 5551201",
			},
			Status:           "active",
			HireDate:         time.Date(2018, 2, 15, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 7, 5, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2018, 2, 15, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Radiation Protection Officer - SECRET clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0067",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Laura",
			LastName:            "Martini",
			Role:                models.RoleRadProtection,
			Department:          "radiation_protection",
			ClearanceLevel:      models.ClassSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "Radiation Protection Expert",
					IssuedBy:   "ISIN",
					IssueDate:  time.Date(2019, 3, 10, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 3, 10, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-SF-01"},
			BadgeID:       "BDG-00067",
			Contact: models.Contact{
				Email: "l.martini@centralenucleare.it",
				Phone: "+39 071 5551067",
			},
			Status:           "active",
			HireDate:         time.Date(2017, 4, 10, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 9, 20, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2017, 4, 10, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Security Officer - SECRET clearance
		models.Personnel{
			EmployeeID:          "NP-2024-0180",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Francesca",
			LastName:            "Moretti",
			Role:                models.RoleSecurity,
			Department:          "security",
			ClearanceLevel:      models.ClassSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "Physical Security Certification",
					IssuedBy:   "Ministry of Interior",
					IssueDate:  time.Date(2020, 11, 1, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-TB-01", "ZONE-SF-01", "ZONE-ADM-01"},
			BadgeID:       "BDG-00180",
			Contact: models.Contact{
				Email: "f.moretti@centralenucleare.it",
				Phone: "+39 071 5551180",
			},
			Status:           "active",
			HireDate:         time.Date(2015, 8, 1, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2015, 8, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},

		// Inspector - TOP_SECRET clearance (esterno)
		models.Personnel{
			EmployeeID:          "NP-2024-0300",
			ClassificationLevel: models.ClassConfidential,
			FirstName:           "Paolo",
			LastName:            "De Luca",
			Role:                models.RoleInspector,
			Department:          "external",
			ClearanceLevel:      models.ClassTopSecret,
			Qualifications: []models.Qualification{
				{
					Name:       "IAEA Nuclear Inspector Certification",
					IssuedBy:   "IAEA",
					IssueDate:  time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
					ExpiryDate: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
					Status:     "active",
				},
			},
			AssignedZones: []string{"ZONE-MAIN", "ZONE-CR-01", "ZONE-RC-01", "ZONE-SF-01", "ZONE-ADM-01"},
			BadgeID:       "BDG-00300",
			Contact: models.Contact{
				Email: "p.deluca@isin.gov.it",
				Phone: "+39 06 5551300",
			},
			Status:           "active",
			HireDate:         time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
			LastMedicalCheck: time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC),
			CreatedAt:        time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:        now,
		},
	}

	result, err := coll.InsertMany(ctx, personnel)
	if err != nil {
		log.Fatal("❌ Failed to seed personnel:", err)
	}
	fmt.Printf("✅ Inserted %d personnel records\n", len(result.InsertedIDs))
}
