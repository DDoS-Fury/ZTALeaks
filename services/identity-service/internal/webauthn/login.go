package webauthn

import (
	"encoding/json"
	"net/http"

	"ztaleaks/identity-service/internal/models"
)

// ---------------------------------------------------------------------------
// /api/v1/auth/login/begin
// ---------------------------------------------------------------------------

type beginLoginReq struct {
	Username string `json:"username"`
}

type publicKeyCredentialRequestOptions struct {
	Challenge        string           `json:"challenge"`
	RPID             string           `json:"rpId"`
	Timeout          int              `json:"timeout"`
	AllowCredentials []allowCredEntry `json:"allowCredentials"`
	UserVerification string           `json:"userVerification"`
	SessionID        string           `json:"session_id"`
}

type allowCredEntry struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// BeginLogin apre una cerimonia di autenticazione per un device gia' registrato:
// genera challenge + lista delle credenziali enrollate per username.
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	var req beginLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	user, err := h.users.FindByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	creds, err := h.devices.ListByUser(r.Context(), user.ID)
	if err != nil || len(creds) == 0 {
		http.Error(w, "no enrolled devices for user", http.StatusNotFound)
		return
	}

	challenge := newChallenge()
	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		Challenge:    challenge,
		UserID:       user.ID,
		CeremonyType: "authentication",
	}); err != nil {
		http.Error(w, "failed to store challenge", http.StatusInternalServerError)
		return
	}

	allow := make([]allowCredEntry, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, allowCredEntry{Type: "public-key", ID: c.CredentialID})
	}

	opts := publicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RPID:             getenv("WEBAUTHN_RP_ID", "ztaleaks.local"),
		Timeout:          60000,
		AllowCredentials: allow,
		UserVerification: "preferred",
		SessionID:        sessionID,
	}
	respondJSON(w, http.StatusOK, opts)
}

// ---------------------------------------------------------------------------
// /api/v1/auth/login/finish
// ---------------------------------------------------------------------------

type finishLoginReq struct {
	SessionID    string `json:"session_id"`
	CredentialID string `json:"credential_id"`
	SignCount    uint32 `json:"sign_count"`
}

// FinishLogin verifica che la credential appartenga all'utente della
// challenge, aggiorna sign_count e segnala potenziale clonazione (sign_count
// che non e' strettamente crescente).
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	var req finishLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	challenge, err := h.challenges.FindBySessionID(r.Context(), req.SessionID)
	if err != nil {
		http.Error(w, "challenge not found or expired", http.StatusUnauthorized)
		return
	}
	if challenge.CeremonyType != "authentication" {
		http.Error(w, "wrong ceremony type", http.StatusBadRequest)
		return
	}

	dev, err := h.devices.FindByCredentialID(r.Context(), req.CredentialID)
	if err != nil || dev == nil {
		http.Error(w, "device not registered", http.StatusUnauthorized)
		return
	}
	if dev.UserID != challenge.UserID {
		http.Error(w, "credential does not match challenge user", http.StatusUnauthorized)
		return
	}

	// Clone detection — sign_count deve aumentare strettamente.
	cloneDetected := req.SignCount <= dev.SignCount && dev.SignCount > 0
	_ = h.devices.UpdateSignCount(r.Context(), req.CredentialID, req.SignCount)
	_ = h.challenges.Delete(r.Context(), req.SessionID)

	respondJSON(w, http.StatusOK, map[string]any{
		"status":          "authenticated",
		"credential_id":   req.CredentialID,
		"clone_suspected": cloneDetected,
	})
}
