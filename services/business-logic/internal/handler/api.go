package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"ztaleaks/business-logic/internal/db"
	"ztaleaks/business-logic/internal/models"
	"ztaleaks/business-logic/internal/validation"
)

// APIHandler struct includes instances of our db repositories
type APIHandler struct {
	PersonnelRepo       db.PersonnelRepository
	ReactorRepo         db.ReactorRepository
	DocumentRepo        db.DocumentRepository
	NuclearMaterialRepo db.NuclearMaterialRepository
}

// NewAPIHandler creates a new instance of APIHandler
func NewAPIHandler(repos *db.Repositories) *APIHandler {
	return &APIHandler{
		PersonnelRepo:       repos.Personnel,
		ReactorRepo:         repos.Reactor,
		DocumentRepo:        repos.Document,
		NuclearMaterialRepo: repos.NuclearMaterial,
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

	log_action(r, "list_personnel", "", "success", nil)
	if err != nil {
		log_action(r, "list_personnel", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "list_personnel", "", "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) GetPersonnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data, err := h.PersonnelRepo.GetByID(r.Context(), id)

	log_action(r, "get_personnel", id, "success", nil)
	if err != nil {
		log_action(r, "get_personnel", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "get_personnel", id, "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) CreatePersonnel(w http.ResponseWriter, r *http.Request) {
	p, err := validation.DecodeAndValidate[models.Personnel](r)
	if err != nil {
		log_action(r, "create_personnel", "", "failure", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.PersonnelRepo.Create(r.Context(), &p); err != nil {
		log_action(r, "create_personnel", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "create_personnel", "", "success", nil)
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, p)
}

// =====================================================================
// REACTOR PARAMETERS
// =====================================================================

func (h *APIHandler) ListReactorParameters(w http.ResponseWriter, r *http.Request) {
	data, err := h.ReactorRepo.GetAll(r.Context())

	log_action(r, "list_reactor_parameters", "", "success", nil)
	if err != nil {
		log_action(r, "list_reactor_parameters", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "list_reactor_parameters", "", "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) GetReactorParameter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	log_action(r, "get_reactor_parameter", id, "success", nil)
	data, err := h.ReactorRepo.GetByID(r.Context(), id)
	if err != nil {
		log_action(r, "get_reactor_parameter", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "get_reactor_parameter", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "get_reactor_parameter", id, "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) CreateReactorParameter(w http.ResponseWriter, r *http.Request) {
	rp, err := validation.DecodeAndValidate[models.ReactorParameters](r)
	if err != nil {
		log_action(r, "create_reactor_parameter", "", "failure", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.ReactorRepo.Create(r.Context(), &rp); err != nil {
		log_action(r, "create_reactor_parameter", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log_action(r, "create_reactor_parameter", "", "success", nil)
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, rp)
}

func (h *APIHandler) DeleteReactorParameter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	log_action(r, "delete_reactor_parameter", id, "success", nil)
	if err := h.ReactorRepo.Delete(r.Context(), id); err != nil {
		log_action(r, "delete_reactor_parameter", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "delete_reactor_parameter", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log_action(r, "delete_reactor_parameter", id, "failure", err)
		return
	}

	log_action(r, "delete_reactor_parameter", id, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// DOCUMENTS
// =====================================================================

func (h *APIHandler) ListDocuments(w http.ResponseWriter, r *http.Request) {
	data, err := h.DocumentRepo.GetAll(r.Context())
	log_action(r, "list_documents", "", "success", nil)
	if err != nil {
		log_action(r, "list_documents", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log_action(r, "list_documents", "", "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) GetDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	log_action(r, "get_document", id, "success", nil)
	data, err := h.DocumentRepo.GetByID(r.Context(), id)
	if err != nil {
		log_action(r, "get_document", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "get_document", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log_action(r, "get_document", id, "failure", err)
		return
	}
	log_action(r, "get_document", id, "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) CreateDocument(w http.ResponseWriter, r *http.Request) {
	d, err := validation.DecodeAndValidate[models.Document](r)
	if err != nil {
		log_action(r, "create_document", "", "failure", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.DocumentRepo.Create(r.Context(), &d); err != nil {
		log_action(r, "create_document", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log_action(r, "create_document", "", "success", nil)
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, d)
}

func (h *APIHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	log_action(r, "delete_document", id, "success", nil)
	if err := h.DocumentRepo.Delete(r.Context(), id); err != nil {
		log_action(r, "delete_document", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "delete_document", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log_action(r, "delete_document", id, "failure", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// NUCLEAR MATERIALS
// =====================================================================

func (h *APIHandler) ListNuclearMaterials(w http.ResponseWriter, r *http.Request) {
	data, err := h.NuclearMaterialRepo.GetAll(r.Context())
	log_action(r, "list_nuclear_materials", "", "success", nil)
	if err != nil {
		log_action(r, "list_nuclear_materials", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log_action(r, "list_nuclear_materials", "", "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) GetNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	log_action(r, "get_nuclear_material", id, "success", nil)
	data, err := h.NuclearMaterialRepo.GetByID(r.Context(), id)
	if err != nil {
		log_action(r, "get_nuclear_material", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "get_nuclear_material", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log_action(r, "get_nuclear_material", id, "failure", err)
		return
	}
	log_action(r, "get_nuclear_material", id, "success", nil)
	respondJSON(w, data)
}

func (h *APIHandler) CreateNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	m, err := validation.DecodeAndValidate[models.NuclearMaterial](r)
	if err != nil {
		log_action(r, "create_nuclear_material", "", "failure", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.NuclearMaterialRepo.Create(r.Context(), &m); err != nil {
		log_action(r, "create_nuclear_material", "", "failure", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log_action(r, "create_nuclear_material", "", "success", nil)
	w.WriteHeader(http.StatusCreated)
	respondJSON(w, m)
}

func (h *APIHandler) DeleteNuclearMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	log_action(r, "delete_nuclear_material", id, "success", nil)

	if err := h.NuclearMaterialRepo.Delete(r.Context(), id); err != nil {
		log_action(r, "delete_nuclear_material", id, "failure", err)
		if isNotFound(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			log_action(r, "delete_nuclear_material", id, "failure", err)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log_action(r, "delete_nuclear_material", id, "failure", err)
		return
	}

	log_action(r, "delete_nuclear_material", id, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// TRUSTED GUARD / SANITIZATION GATEWAY
// =====================================================================

func (h *APIHandler) TrustedGuardDeletePersonnel(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")

	// Recuperiamo l'ID dell'Admin dal token JWT
	userID := r.Header.Get("X-Current-User")

	// =====================================================================
	// 1. NON-RIPUDIO E TRACCIAMENTO (Audit Logging con slog)
	// =====================================================================
	log_action(r, "trusted_guard_delete_personnel_requested", targetID, "initiated", nil)

	// =====================================================================
	// 2. SANITIZZAZIONE TEMPORALE E JITTER (Esecuzione Asincrona)
	// =====================================================================
	// Passiamo targetID e adminID alla closure per evitare problemi di scope
	go func(idToProcess string, aID string) {
		minDelay := 2 * time.Hour
		maxDelay := 6 * time.Hour
		jitter := minDelay + time.Duration(rand.Int63n(int64(maxDelay-minDelay)))

		// Jitter temporale
		time.Sleep(jitter)

		// Usiamo un nuovo context perché r.Context() viene annullato alla fine della request
		err := h.PersonnelRepo.Delete(context.Background(), idToProcess)
		if err != nil {
			// Usiamo slog.Error per i fallimenti di sistema interni
			log_action(r, "downgrade_delete_personnel", targetID, "failure", err)
			return
		}

		log_action(r, "downgrade_delete_personnel", targetID, "success", nil)

	}(targetID, userID)

	// =====================================================================
	// 3. RISPOSTA PIATTA E IMMEDIATA
	// =====================================================================
	w.WriteHeader(http.StatusAccepted)
}

func log_action(r *http.Request, action string, target string, status string, err error) {
	userID := r.Header.Get("X-Current-User")
	reqID := r.Header.Get("X-Request-ID")

	slog.Info(
		"action", action,
		slog.String("status", status),
		slog.String("target", target),
		slog.String("user_id", userID),
		slog.String("req_id", reqID),
		slog.Any("error", err),
	)
}
