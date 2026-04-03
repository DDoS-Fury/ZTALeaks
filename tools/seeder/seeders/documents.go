// =============================================================================
// Seeder: documents
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Populates the documents collection with technical documents spanning all
// classification levels (INTERNAL through TOP_SECRET) and all document types
// (procedures, manuals, drawings, reports, analyses).
// The applicable_roles field enables role-based access decisions by the PDP.
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

// SeedDocuments inserts technical documents into the documents collection.
func SeedDocuments(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("documents")

	count, _ := coll.CountDocuments(ctx, bson.M{})
	if count > 0 {
		log.Println("[SEED] documents already populated, skipping")
		return
	}

	docs := []interface{}{
		// Emergency procedure - CONFIDENTIAL
		models.Document{
			DocumentID:          "DOC-PROC-2024-0891",
			ClassificationLevel: models.ClassConfidential,
			Title:               "Procedura di emergenza per perdita di refrigerante primario (LOCA)",
			Type:                models.DocProcedure,
			Category:            models.CatEmergency,
			Revision: models.Revision{
				Number:         5,
				Date:           time.Date(2024, 8, 15, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0001",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Aggiornamento tempi di risposta e sequenza attuatori",
			},
			ApplicableSystems: []string{"primary_coolant", "emergency_core_cooling"},
			ApplicableZones:   []string{"ZONE-RC-01", "ZONE-CR-01"},
			ApplicableRoles:   []string{models.RoleOperator, models.RolePlantManager},
			FileReference:     "/docs/procedures/emergency/PROC-EM-LOCA-R5.pdf",
			Keywords:          []string{"LOCA", "emergenza", "refrigerante", "ECCS"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-PROC-2024-0891-R4", "DOC-PROC-2024-0891-R3"},
			ReviewDate:        time.Date(2025, 8, 15, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2024, 8, 15, 10, 0, 0, 0, time.UTC),
		},

		// Operational procedure - INTERNAL
		models.Document{
			DocumentID:          "DOC-PROC-2024-0120",
			ClassificationLevel: models.ClassInternal,
			Title:               "Procedura operativa di avviamento reattore",
			Type:                models.DocProcedure,
			Category:            models.CatOperational,
			Revision: models.Revision{
				Number:         12,
				Date:           time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0142",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Aggiornamento sequenza estrazione barre di controllo",
			},
			ApplicableSystems: []string{"reactor_control", "primary_coolant"},
			ApplicableZones:   []string{"ZONE-CR-01"},
			ApplicableRoles:   []string{models.RoleOperator, models.RolePlantManager},
			FileReference:     "/docs/procedures/operational/PROC-OP-STARTUP-R12.pdf",
			Keywords:          []string{"avviamento", "startup", "barre di controllo", "criticita"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-PROC-2024-0120-R11"},
			ReviewDate:        time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2010, 1, 15, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC),
		},

		// Maintenance manual - INTERNAL
		models.Document{
			DocumentID:          "DOC-MAN-2023-0045",
			ClassificationLevel: models.ClassInternal,
			Title:               "Manuale di manutenzione pompe del circuito primario",
			Type:                models.DocManual,
			Category:            models.CatMaintenance,
			Revision: models.Revision{
				Number:         3,
				Date:           time.Date(2023, 11, 20, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0201",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Aggiunta procedura per nuova guarnizione meccanica tipo A",
			},
			ApplicableSystems: []string{"primary_coolant"},
			ApplicableZones:   []string{"ZONE-RC-01"},
			ApplicableRoles:   []string{models.RoleMaintTech, models.RolePlantManager},
			FileReference:     "/docs/manuals/MAN-MNT-PUMP-PRI-R3.pdf",
			Keywords:          []string{"pompe", "primario", "manutenzione", "guarnizione"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-MAN-2023-0045-R2"},
			ReviewDate:        time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2018, 6, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2023, 11, 20, 0, 0, 0, 0, time.UTC),
		},

		// Safety analysis - SECRET
		models.Document{
			DocumentID:          "DOC-ANL-2024-0033",
			ClassificationLevel: models.ClassSecret,
			Title:               "Analisi di sicurezza: scenari di fusione del nocciolo",
			Type:                models.DocAnalysis,
			Category:            models.CatSafety,
			Revision: models.Revision{
				Number:         2,
				Date:           time.Date(2024, 3, 10, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0001",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Integrazione nuovi scenari post-Fukushima",
			},
			ApplicableSystems: []string{"reactor_core", "containment", "emergency_core_cooling"},
			ApplicableZones:   []string{"ZONE-RC-01", "ZONE-CR-01"},
			ApplicableRoles:   []string{models.RolePlantManager, models.RoleInspector},
			FileReference:     "/docs/analysis/ANL-SAF-MELT-R2.pdf",
			Keywords:          []string{"fusione nocciolo", "core melt", "sicurezza", "LOCA", "station blackout"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-ANL-2024-0033-R1"},
			ReviewDate:        time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2024, 3, 10, 0, 0, 0, 0, time.UTC),
		},

		// Plant drawing - CONFIDENTIAL
		models.Document{
			DocumentID:          "DOC-DWG-2022-0150",
			ClassificationLevel: models.ClassConfidential,
			Title:               "Schema P&ID circuito primario di raffreddamento",
			Type:                models.DocDrawing,
			Category:            models.CatOperational,
			Revision: models.Revision{
				Number:         8,
				Date:           time.Date(2022, 7, 1, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0142",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Aggiornamento dopo sostituzione scambiatore SG-02",
			},
			ApplicableSystems: []string{"primary_coolant", "steam_generator"},
			ApplicableZones:   []string{"ZONE-RC-01", "ZONE-TB-01"},
			ApplicableRoles:   []string{models.RoleOperator, models.RoleMaintTech, models.RolePlantManager, models.RoleInspector},
			FileReference:     "/docs/drawings/DWG-PID-PRI-R8.pdf",
			Keywords:          []string{"P&ID", "primario", "circuito", "schema"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-DWG-2022-0150-R7"},
			ReviewDate:        time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2022, 7, 1, 0, 0, 0, 0, time.UTC),
		},

		// Security vulnerability report - TOP_SECRET
		models.Document{
			DocumentID:          "DOC-RPT-2024-0005",
			ClassificationLevel: models.ClassTopSecret,
			Title:               "Rapporto vulnerabilita sicurezza fisica impianto",
			Type:                models.DocReport,
			Category:            models.CatSafety,
			Revision: models.Revision{
				Number:         1,
				Date:           time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0180",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Prima emissione",
			},
			ApplicableSystems: []string{"physical_security", "access_control"},
			ApplicableZones:   []string{"ZONE-MAIN", "ZONE-SF-01"},
			ApplicableRoles:   []string{models.RolePlantManager, models.RoleInspector},
			FileReference:     "/docs/reports/RPT-SEC-VULN-R1.pdf",
			Keywords:          []string{"vulnerabilita", "sicurezza fisica", "accessi", "perimetro"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{},
			ReviewDate:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
		},

		// Radiation protection procedure - INTERNAL
		models.Document{
			DocumentID:          "DOC-PROC-2024-0300",
			ClassificationLevel: models.ClassInternal,
			Title:               "Procedura di radioprotezione per accesso zone controllate",
			Type:                models.DocProcedure,
			Category:            models.CatSafety,
			Revision: models.Revision{
				Number:         6,
				Date:           time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
				Author:         "NP-2024-0067",
				ApprovedBy:     "NP-2024-0001",
				ChangesSummary: "Aggiornamento limiti dosimetrici annuali",
			},
			ApplicableSystems: []string{"radiation_monitoring"},
			ApplicableZones:   []string{"ZONE-RC-01", "ZONE-AUX-01", "ZONE-SF-01"},
			ApplicableRoles:   []string{models.RoleOperator, models.RoleMaintTech, models.RoleRadProtection, models.RolePlantManager},
			FileReference:     "/docs/procedures/safety/PROC-RP-ACCESS-R6.pdf",
			Keywords:          []string{"radioprotezione", "dosimetria", "accesso", "zone controllate"},
			Status:            models.DocStatusApproved,
			PreviousRevisions: []string{"DOC-PROC-2024-0300-R5"},
			ReviewDate:        time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
			CreatedAt:         time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:         time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	result, err := coll.InsertMany(ctx, docs)
	if err != nil {
		log.Fatalf("[SEED] Failed to seed documents: %v", err)
	}
	fmt.Printf("[SEED] Inserted %d documents\n", len(result.InsertedIDs))
}