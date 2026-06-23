package handler

import (
	"net/http"

	"ztaleaks/iam-service/internal/crypto"
	wa "ztaleaks/iam-service/internal/webauthn"
)

// Router aggrega tutte le componenti che servono a registrare le rotte
// dell'iam-service. Il main istanzia questa struct e chiama
// RegisterRoutes su un http.ServeMux: tutto il routing vive qui, fuori dal main.
type Router struct {
	API      *IdentityAPI
	WebAuthn *wa.Handler
	JWT      *crypto.JWTManager
}

// RegisterRoutes monta su mux:
//   - /health            (liveness)
//   - JWKS               (chiave pubblica RSA per la security-orchestrator)
//   - /api/v1/auth/...   (register / login / verify-otp)
//   - /api/v1/auth/{register,login}/{begin,finish}  (cerimonie WebAuthn)
func (r *Router) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /.well-known/jwks.json", crypto.JWKSHandler(r.JWT))

	// UI Routes
	mux.HandleFunc("GET /login", ServeLoginPage)
	mux.HandleFunc("GET /register", ServeRegisterPage)

	mux.HandleFunc("POST /api/v1/auth/register", r.API.Register)
	mux.HandleFunc("POST /api/v1/auth/login", r.API.Login)
	mux.HandleFunc("POST /api/v1/auth/verify-otp", r.API.VerifyOTP)

	mux.HandleFunc("POST /api/v1/auth/register/begin", r.WebAuthn.BeginRegistration)
	mux.HandleFunc("POST /api/v1/auth/register/finish", r.WebAuthn.FinishRegistration)
	mux.HandleFunc("POST /api/v1/auth/login/begin", r.WebAuthn.BeginLogin)
	mux.HandleFunc("POST /api/v1/auth/login/finish", r.WebAuthn.FinishLogin)
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"identity"}`))
}
