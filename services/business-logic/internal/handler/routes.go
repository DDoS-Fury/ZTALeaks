package handler

import "net/http"

// RegisterRoutes registers all API routes on the given ServeMux
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {

	// Static files (CSS, etc.)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	//Home page
	mux.HandleFunc("/", HomeHandler)
	mux.HandleFunc("/materials", MaterialsHandler)
	mux.HandleFunc("/reserved", ReservedHandler)

	// ============================================================================
	// DOMINIO 1: BUSINESS & GESTIONE (RBAC Gerarchico Standard)
	// ============================================================================

	// --- PERSONALE (Livello Base - Accessibile da Operator, Manager, Admin) ---
	// Qui usiamo la logica aziendale reale: i livelli alti gestiscono i bassi.
	mux.HandleFunc("GET /api/v1/personnel", h.ListPersonnel)
	mux.HandleFunc("GET /api/v1/personnel/{id}", h.GetPersonnel)
	mux.HandleFunc("POST /api/v1/personnel", h.CreatePersonnel)

	// --- DOCUMENTI (Livello Medio - Accessibile da Manager e Admin) ---
	mux.HandleFunc("GET /api/v1/documents", h.ListDocuments)
	mux.HandleFunc("GET /api/v1/documents/{id}", h.GetDocument)
	mux.HandleFunc("POST /api/v1/documents", h.CreateDocument)
	mux.HandleFunc("DELETE /api/v1/documents/{id}", h.DeleteDocument)

	// --- MATERIALI NUCLEARI (Livello Medio - Accessibile da Manager e Admin) ---
	mux.HandleFunc("GET /api/v1/nuclear-materials", h.ListNuclearMaterials)
	mux.HandleFunc("GET /api/v1/nuclear-materials/{id}", h.GetNuclearMaterial)
	mux.HandleFunc("POST /api/v1/nuclear-materials", h.CreateNuclearMaterial)
	mux.HandleFunc("DELETE /api/v1/nuclear-materials/{id}", h.DeleteNuclearMaterial)

	// ============================================================================
	// DOMINIO 2: REATTORE & CORE NUCLEARE (Bell-LaPadula Rigoroso)
	// ============================================================================

	// --- PARAMETRI REATTORE (Livello Massimo - SOLO Admin) ---
	// Gli operatori e i manager non possono fare "Read Up" su queste rotte.
	mux.HandleFunc("GET /api/v1/reactor-parameters", h.ListReactorParameters)
	mux.HandleFunc("GET /api/v1/reactor-parameters/{id}", h.GetReactorParameter)
	mux.HandleFunc("POST /api/v1/reactor-parameters", h.CreateReactorParameter)
	mux.HandleFunc("DELETE /api/v1/reactor-parameters/{id}", h.DeleteReactorParameter)

	// ============================================================================
	// DOMINIO 3: TRUSTED GUARD / GATEWAY DI SANITIZZAZIONE
	// ============================================================================

	// Questa rotta permette all'Admin (Livello Massimo) di effettuare una DELETE
	// verso il Personale (Livello Basso) violando formalmente il Bell-LaPadula,
	// ma facendolo passare attraverso il processo di "Bonifica/Sanitizzazione".
	mux.HandleFunc("POST /api/v1/trusted-guard/sanitized-delete-personnel/{id}", h.TrustedGuardDeletePersonnel)
}
