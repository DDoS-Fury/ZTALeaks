package handler

import "net/http"

// RegisterRoutes registers all API routes on the given ServeMux
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {

	//Home page
	mux.HandleFunc("/", HomeHandler)

	// Personnel
	mux.HandleFunc("GET /api/v1/personnel", h.ListPersonnel)
	mux.HandleFunc("GET /api/v1/personnel/{id}", h.GetPersonnel)
	mux.HandleFunc("POST /api/v1/personnel", h.CreatePersonnel)
	mux.HandleFunc("PUT /api/v1/personnel/{id}", h.UpdatePersonnel)
	mux.HandleFunc("DELETE /api/v1/personnel/{id}", h.DeletePersonnel)

	// Zones
	mux.HandleFunc("GET /api/v1/zones", h.ListZones)
	mux.HandleFunc("GET /api/v1/zones/{id}", h.GetZone)
	mux.HandleFunc("POST /api/v1/zones", h.CreateZone)
	mux.HandleFunc("PUT /api/v1/zones/{id}", h.UpdateZone)
	mux.HandleFunc("DELETE /api/v1/zones/{id}", h.DeleteZone)

	// Access Badges
	mux.HandleFunc("GET /api/v1/badges", h.ListBadges)
	mux.HandleFunc("GET /api/v1/badges/{id}", h.GetBadge)
	mux.HandleFunc("POST /api/v1/badges", h.CreateBadge)
	mux.HandleFunc("PUT /api/v1/badges/{id}", h.UpdateBadge)
	mux.HandleFunc("DELETE /api/v1/badges/{id}", h.DeleteBadge)

	// Reactor Parameters
	mux.HandleFunc("GET /api/v1/reactor-parameters", h.ListReactorParameters)
	mux.HandleFunc("GET /api/v1/reactor-parameters/{id}", h.GetReactorParameter)
	mux.HandleFunc("POST /api/v1/reactor-parameters", h.CreateReactorParameter)
	mux.HandleFunc("PUT /api/v1/reactor-parameters/{id}", h.UpdateReactorParameter)
	mux.HandleFunc("DELETE /api/v1/reactor-parameters/{id}", h.DeleteReactorParameter)

	// Maintenance Orders
	mux.HandleFunc("GET /api/v1/maintenance-orders", h.ListMaintenanceOrders)
	mux.HandleFunc("GET /api/v1/maintenance-orders/{id}", h.GetMaintenanceOrder)
	mux.HandleFunc("POST /api/v1/maintenance-orders", h.CreateMaintenanceOrder)
	mux.HandleFunc("PUT /api/v1/maintenance-orders/{id}", h.UpdateMaintenanceOrder)
	mux.HandleFunc("DELETE /api/v1/maintenance-orders/{id}", h.DeleteMaintenanceOrder)

	// Documents
	mux.HandleFunc("GET /api/v1/documents", h.ListDocuments)
	mux.HandleFunc("GET /api/v1/documents/{id}", h.GetDocument)
	mux.HandleFunc("POST /api/v1/documents", h.CreateDocument)
	mux.HandleFunc("PUT /api/v1/documents/{id}", h.UpdateDocument)
	mux.HandleFunc("DELETE /api/v1/documents/{id}", h.DeleteDocument)

	// Nuclear Materials
	mux.HandleFunc("GET /api/v1/nuclear-materials", h.ListNuclearMaterials)
	mux.HandleFunc("GET /api/v1/nuclear-materials/{id}", h.GetNuclearMaterial)
	mux.HandleFunc("POST /api/v1/nuclear-materials", h.CreateNuclearMaterial)
	mux.HandleFunc("PUT /api/v1/nuclear-materials/{id}", h.UpdateNuclearMaterial)
	mux.HandleFunc("DELETE /api/v1/nuclear-materials/{id}", h.DeleteNuclearMaterial)
}
