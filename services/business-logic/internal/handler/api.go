package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"ztaleaks/business-logic/internal/db"
)

// APIHandler struct includes instances of our db repositories
type APIHandler struct {
	PersonnelRepo db.PersonnelRepository
	ZoneRepo      db.ZoneRepository
	BadgeRepo     db.BadgeRepository
	ReactorRepo   db.ReactorRepository
}

// NewAPIHandler creates a new instance of APIHandler
func NewAPIHandler(p db.PersonnelRepository, z db.ZoneRepository, b db.BadgeRepository, r db.ReactorRepository) *APIHandler {
	return &APIHandler{
		PersonnelRepo: p,
		ZoneRepo:      z,
		BadgeRepo:     b,
		ReactorRepo:   r,
	}
}

// GetPersonnel handles GET requests for all personnel data
func (h *APIHandler) GetPersonnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := h.PersonnelRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching personnel", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, data)
}

// GetZones handles GET requests for all zones data
func (h *APIHandler) GetZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := h.ZoneRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching zones", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, data)
}

// GetBadges handles GET requests for all access badges data
func (h *APIHandler) GetBadges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := h.BadgeRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching badges", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, data)
}

// GetReactorParameters handles GET requests for all reactor telemetry data
func (h *APIHandler) GetReactorParameters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := h.ReactorRepo.GetAll(r.Context())
	if err != nil {
		slog.Error("Error fetching reactor parameters", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, data)
}

// respondJSON writes interface data as JSON payload to ResponseWriter
func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Error encoding JSON", "error", err)
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
	}
}
