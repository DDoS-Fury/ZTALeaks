package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/models"
)

// ---------------------------------------------------------------------------
// /api/v1/auth/register/begin
// ---------------------------------------------------------------------------

type beginRegisterReq struct {
	AccessToken string `json:"access_token"`
	DeviceName  string `json:"device_name"`
}

type publicKeyCredentialCreationOptions struct {
	Challenge        string       `json:"challenge"`
	RP               relyingParty `json:"rp"`
	User             userEntity   `json:"user"`
	PubKeyCredParams []paramEntry `json:"pubKeyCredParams"`
	Timeout          int          `json:"timeout"`
	Attestation      string       `json:"attestation"`
	SessionID        string       `json:"session_id"`
}

type relyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type paramEntry struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// BeginRegistration apre una cerimonia di enrollment: l'utente deve essere
// gia' autenticato (il JWT e' stato verificato a monte dalla security-orchestrator,
// che inietta X-Current-User come header upstream). Genera una challenge random
// e la salva in webauthn_challenges con TTL 5 min.
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	var req beginRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		slog.Error("failed to decode begin registration request", "user_id", r.Header.Get("X-Current-User"), "error", err)
		return
	}

	userID := r.Header.Get("X-Current-User")
	if userID == "" {
		http.Error(w, "missing authenticated user (X-Current-User)", http.StatusUnauthorized)
		slog.Error("missing authenticated user (X-Current-User)")
		return
	}
	user, err := h.users.FindByID(r.Context(), userID)
	if err != nil {
		slog.Error("failed to find user", "error", err)
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	challenge := newChallenge()
	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		Challenge:    challenge,
		UserID:       user.ID,
		CeremonyType: "registration",
	}); err != nil {
		slog.Error("failed to store challenge", "user_id", user.ID, "error", err)
		http.Error(w, "failed to store challenge", http.StatusInternalServerError)
		return
	}

	opts := publicKeyCredentialCreationOptions{
		Challenge: challenge,
		RP: relyingParty{
			ID:   getenv("WEBAUTHN_RP_ID", "ztaleaks.local"),
			Name: "ZTALeaks Nuclear Plant",
		},
		User: userEntity{
			ID:          user.ID,
			Name:        user.Username,
			DisplayName: user.Username,
		},
		PubKeyCredParams: []paramEntry{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		Timeout:     60000,
		Attestation: "direct",
		SessionID:   sessionID,
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"publicKey":  opts,
		"session_id": sessionID,
	})
}

// ---------------------------------------------------------------------------
// /api/v1/auth/register/finish
// ---------------------------------------------------------------------------

type finishRegisterReq struct {
	SessionID       string `json:"session_id"`
	CredentialID    string `json:"credential_id"`
	PublicKey       string `json:"public_key"`       // base64 standard
	AttestationType string `json:"attestation_type"` // es. "platform" / "cross-platform"
	AAGUID          string `json:"aaguid"`
}

// FinishRegistration chiude la cerimonia di enrollment: salva la credential
// in device_fingerprints, marca user.has_tpm=true e cancella la challenge.
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	var req finishRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		slog.Error("failed to decode finish registration request", "user_id", r.Header.Get("X-Current-User"), "error", err)
		return
	}
	if req.SessionID == "" || req.CredentialID == "" || req.PublicKey == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		slog.Error("missing fields in finish registration request")
		return
	}

	challenge, err := h.challenges.FindBySessionID(r.Context(), req.SessionID)
	if err != nil {
		if errors.Is(err, db.ErrChallengeNotFound) {
			http.Error(w, "challenge not found or expired", http.StatusUnauthorized)
			slog.Error("challenge not found or expired", "user_id", r.Header.Get("X-Current-User"), "session_id", req.SessionID)
			return
		}
		http.Error(w, "challenge lookup failed", http.StatusInternalServerError)
		slog.Error("failed to lookup challenge", "user_id", r.Header.Get("X-Current-User"), "error", err)
		return
	}
	if challenge.CeremonyType != "registration" {
		http.Error(w, "wrong ceremony type", http.StatusBadRequest)
		slog.Error("wrong ceremony type", "user_id", r.Header.Get("X-Current-User"), "ceremony_type", challenge.CeremonyType)
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid public_key encoding", http.StatusBadRequest)
		slog.Error("invalid public_key encoding", "error", err)
		return
	}

	if err := h.devices.Create(r.Context(), models.DeviceCredential{
		CredentialID:    req.CredentialID,
		UserID:          challenge.UserID,
		PublicKey:       pubKey,
		AAGUID:          req.AAGUID,
		AttestationType: req.AttestationType,
		DeviceName:      "tpm-" + truncate(req.CredentialID, 8),
		SignCount:       0,
	}); err != nil {
		http.Error(w, "credential already registered", http.StatusConflict)
		slog.Error("credential already registered", "user_id", challenge.UserID, "credential_id", req.CredentialID)
		return
	}

	if err := h.users.MarkTPMEnrolled(r.Context(), challenge.UserID, req.PublicKey); err != nil {
		http.Error(w, "failed to update user TPM flag", http.StatusInternalServerError)
		slog.Error("failed to update user TPM flag", "user_id", challenge.UserID, "error", err)
		return
	}
	_ = h.challenges.Delete(r.Context(), req.SessionID)

	respondJSON(w, http.StatusOK, map[string]string{
		"status":        "registered",
		"credential_id": req.CredentialID,
	})
}
