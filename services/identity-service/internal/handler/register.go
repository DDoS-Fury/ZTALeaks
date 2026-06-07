package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/models"
)

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerResponse struct {
	Status string `json:"status"`
	UserID string `json:"user_id"`
}

// Register crea un nuovo utente con password Argon2id e 2FA email abilitato di default.
func (api *IdentityAPI) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	var defaultRole = "guest"

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		slog.Error("failed to decode register request", "error", err, "src_ip", r.Header.Get("x-envoy-external-address"))
		return
	}
	if req.Username == "" || req.Password == "" || req.Email == "" {
		respondError(w, "campi mancanti (username, email, password)", http.StatusBadRequest)
		slog.Warn("register fallito: campi mancanti", "src_ip", r.Header.Get("x-envoy-external-address"))
		return
	}

	hash, err := crypto.GenerateFromPassword(req.Password)
	if err != nil {
		slog.Error("register: hash password", "error", err, "src_ip", r.Header.Get("x-envoy-external-address"))
		respondError(w, "errore interno", http.StatusInternalServerError)
		return
	}

	u := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         defaultRole,
		TwoFAEnabled: true, // OTP via email è il default — direttiva mantenuta
		Status:       "active",
	}
	if err := api.Users.Create(r.Context(), u); err != nil {
		respondError(w, err.Error(), http.StatusConflict)
		return
	}
	slog.Info("utente registrato", "username", u.Username, "role", u.Role)
	respondJSON(w, http.StatusCreated, registerResponse{Status: "registered", UserID: u.ID})
}
