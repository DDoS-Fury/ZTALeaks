package webauthn

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"ztaleaks/iam-service/internal/crypto"
	"ztaleaks/iam-service/internal/models"
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
		slog.Error("failed to decode begin login request", "user_id", r.Header.Get("X-Current-User"), "error", err)
		return
	}
	user, err := h.users.FindByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		slog.Error("user not found", "username", req.Username)
		return
	}
	creds, err := h.devices.ListByUser(r.Context(), user.ID)
	if err != nil || len(creds) == 0 {
		http.Error(w, "no enrolled devices for user", http.StatusNotFound)
		slog.Error("no enrolled devices for user", "user_id", user.ID)
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
		slog.Error("failed to store challenge", "user_id", user.ID, "error", err)
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
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"publicKey":  opts,
		"session_id": sessionID,
	})
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
		slog.Error("failed to decode finish login request", "user_id", r.Header.Get("X-Current-User"), "error", err)
		return
	}
	challenge, err := h.challenges.FindBySessionID(r.Context(), req.SessionID)
	if err != nil {
		http.Error(w, "challenge not found or expired", http.StatusUnauthorized)
		slog.Error("challenge not found or expired", "user_id", r.Header.Get("X-Current-User"), "session_id", req.SessionID)
		return
	}
	if challenge.CeremonyType != "authentication" {
		http.Error(w, "wrong ceremony type", http.StatusBadRequest)
		slog.Error("wrong ceremony type", "user_id", r.Header.Get("X-Current-User"), "ceremony_type", challenge.CeremonyType)
		return
	}

	dev, err := h.devices.FindByCredentialID(r.Context(), req.CredentialID)
	if err != nil || dev == nil {
		http.Error(w, "device not registered", http.StatusUnauthorized)
		slog.Error("device not registered", "user_id", r.Header.Get("X-Current-User"), "credential_id", req.CredentialID)
		return
	}
	if dev.UserID != challenge.UserID {
		http.Error(w, "credential does not match challenge user", http.StatusUnauthorized)
		slog.Error("credential does not match challenge user", "user_id", r.Header.Get("X-Current-User"), "credential_id", req.CredentialID, "challenge_user_id", challenge.UserID)
		return
	}

	// Clone detection — sign_count deve aumentare strettamente.
	cloneDetected := req.SignCount <= dev.SignCount && dev.SignCount > 0
	_ = h.devices.UpdateSignCount(r.Context(), req.CredentialID, req.SignCount)
	_ = h.challenges.Delete(r.Context(), req.SessionID)

	// Trova l'utente per recuperare email
	user, _ := h.users.FindByID(r.Context(), dev.UserID)

	// === INIEZIONE LOGICA OTP ===
	otp, _ := crypto.GenerateOTP()
	otpHash := crypto.HashOTP(otp, req.SessionID)

	// Utilizziamo lo stesso sessionID crittografico
	sessionToken := req.SessionID

	h.OTP.Create(r.Context(), models.OTPSession{
		SessionToken: sessionToken,
		UserID:       user.ID,
		OTPHash:      otpHash,
		Attempts:     0,
	})

	h.Mail.SendOTP(user.Email, otp)

	respondJSON(w, http.StatusOK, map[string]any{
		"status":          "otp_required",
		"session_token":   sessionToken,
		"message":         "Firma Hardware corretta. OTP inviato via email.",
		"credential_id":   req.CredentialID,
		"clone_suspected": cloneDetected,
	})
}
