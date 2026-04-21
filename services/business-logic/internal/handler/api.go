package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"ztaleaks/business-logic/internal/db"
	"ztaleaks/business-logic/internal/models"
)

// APIHandler struct includes instances of our db repositories
type APIHandler struct {
	PersonnelRepo        db.PersonnelRepository
	ZoneRepo             db.ZoneRepository
	BadgeRepo            db.BadgeRepository
	ReactorRepo          db.ReactorRepository
	MaintenanceOrderRepo db.MaintenanceOrderRepository
	DocumentRepo         db.DocumentRepository
	NuclearMaterialRepo  db.NuclearMaterialRepository
}

// NewAPIHandler creates a new instance of APIHandler
func NewAPIHandler(repos *db.Repositories) *APIHandler {
	return &APIHandler{
		PersonnelRepo:        repos.Personnel,
		ZoneRepo:             repos.Zone,
		BadgeRepo:            repos.Badge,
		ReactorRepo:          repos.Reactor,
		MaintenanceOrderRepo: repos.MaintenanceOrder,
		DocumentRepo:         repos.Document,
		NuclearMaterialRepo:  repos.NuclearMaterial,
	}
}

// respondJSON writes interface data as JSON payload to ResponseWriter
func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Error encoding JSON", "error", err)
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
	}
}

// isNotFound checks if an error message indicates a "not found" condition
func isNotFound(err error) bool {
	return strings.Contains(err.Error(), "not found")
}

// =====================================================================
// PERSONNEL
// =====================================================================

func (h *APIHandler) ListPersonnel(w http.ResponseWriter, r *http.Request) {
	data, err := h.PersonnelRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching personnel", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetPersonnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.PersonnelRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreatePersonnel(w http.ResponseWriter, r *http.Request) {
	var p models.Personnel
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.PersonnelRepo.Create(r.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, p)
}

func (h *APIHandler) UpdatePersonnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p models.Personnel
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	p.EmployeeID = id
	if err := h.PersonnelRepo.Update(r.Context(), &p); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, p)
}

func (h *APIHandler) DeletePersonnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.PersonnelRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// ZONES
// =====================================================================

func (h *APIHandler) ListZones(w http.ResponseWriter, r *http.Request) {
	data, err := h.ZoneRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching zones", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.ZoneRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateZone(w http.ResponseWriter, r *http.Request) {
	var z models.Zone
	if err := json.NewDecoder(r.Body).Decode(&z); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.ZoneRepo.Create(r.Context(), &z); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, z)
}

func (h *APIHandler) UpdateZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var z models.Zone
	if err := json.NewDecoder(r.Body).Decode(&z); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	z.ZoneID = id
	if err := h.ZoneRepo.Update(r.Context(), &z); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, z)
}

func (h *APIHandler) DeleteZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.ZoneRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// ACCESS BADGES
// =====================================================================

func (h *APIHandler) ListBadges(w http.ResponseWriter, r *http.Request) {
	data, err := h.BadgeRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching badges", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetBadge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.BadgeRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateBadge(w http.ResponseWriter, r *http.Request) {
	var b models.AccessBadge
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.BadgeRepo.Create(r.Context(), &b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, b)
}

func (h *APIHandler) UpdateBadge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b models.AccessBadge
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	b.BadgeID = id
	if err := h.BadgeRepo.Update(r.Context(), &b); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, b)
}

func (h *APIHandler) DeleteBadge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.BadgeRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// REACTOR PARAMETERS
// =====================================================================

func (h *APIHandler) ListReactorParameters(w http.ResponseWriter, r *http.Request) {
	data, err := h.ReactorRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching reactor parameters", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetReactorParameter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.ReactorRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateReactorParameter(w http.ResponseWriter, r *http.Request) {
	var rp models.ReactorParameters
	if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.ReactorRepo.Create(r.Context(), &rp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, rp)
}

func (h *APIHandler) UpdateReactorParameter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rp models.ReactorParameters
	if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	rp.ReactorID = id
	if err := h.ReactorRepo.Update(r.Context(), &rp); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, rp)
}

func (h *APIHandler) DeleteReactorParameter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.ReactorRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// MAINTENANCE ORDERS
// =====================================================================

func (h *APIHandler) ListMaintenanceOrders(w http.ResponseWriter, r *http.Request) {
	data, err := h.MaintenanceOrderRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching maintenance orders", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetMaintenanceOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.MaintenanceOrderRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateMaintenanceOrder(w http.ResponseWriter, r *http.Request) {
	var o models.MaintenanceOrder
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.MaintenanceOrderRepo.Create(r.Context(), &o); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, o)
}

func (h *APIHandler) UpdateMaintenanceOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var o models.MaintenanceOrder
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	o.OrderID = id
	if err := h.MaintenanceOrderRepo.Update(r.Context(), &o); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, o)
}

func (h *APIHandler) DeleteMaintenanceOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.MaintenanceOrderRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// DOCUMENTS
// =====================================================================

func (h *APIHandler) ListDocuments(w http.ResponseWriter, r *http.Request) {
	data, err := h.DocumentRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching documents", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.DocumentRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateDocument(w http.ResponseWriter, r *http.Request) {
	var d models.Document
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.DocumentRepo.Create(r.Context(), &d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, d)
}

func (h *APIHandler) UpdateDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var d models.Document
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	d.DocumentID = id
	if err := h.DocumentRepo.Update(r.Context(), &d); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, d)
}

func (h *APIHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.DocumentRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// NUCLEAR MATERIALS
// =====================================================================

func (h *APIHandler) ListNuclearMaterials(w http.ResponseWriter, r *http.Request) {
	data, err := h.NuclearMaterialRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching nuclear materials", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) GetNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.NuclearMaterialRepo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, data)
}

func (h *APIHandler) CreateNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	var m models.NuclearMaterial
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.NuclearMaterialRepo.Create(r.Context(), &m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, m)
}

func (h *APIHandler) UpdateNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var m models.NuclearMaterial
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	m.MaterialID = id
	if err := h.NuclearMaterialRepo.Update(r.Context(), &m); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, m)
}

func (h *APIHandler) DeleteNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.NuclearMaterialRepo.Delete(r.Context(), id); err != nil {
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
