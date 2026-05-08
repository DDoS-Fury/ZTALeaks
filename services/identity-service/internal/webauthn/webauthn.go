// =============================================================================
// WebAuthn Package — Lab-grade FIDO2 ceremony for TPM enrollment
// Project: ZTALeaks - Identity Service
// =============================================================================
// Cerimonia semplificata:
//
//   /auth/register/begin   — l'utente è già autenticato via JWT; il server
//                            genera una challenge random e la salva in
//                            webauthn_challenges (TTL 5 min)
//   /auth/register/finish  — client posta credential_id + public_key + la
//                            challenge ricevuta; il server verifica che la
//                            challenge esista e non sia scaduta, poi salva il
//                            credential in device_fingerprints e marca
//                            user.has_tpm=true
//
//   /auth/login/begin      — opzionale: ritorna challenge + lista credenziali
//                            registrate per username
//   /auth/login/finish     — opzionale: aggiorna sign_count e last_used_at;
//                            se sign_count regredisce → segnale di clonazione
//                            (riservato per integrazione futura con OPA)
//
// In un'implementazione production-grade la /finish dovrebbe verificare:
//   - hash di clientDataJSON con la challenge attesa
//   - signature su (authenticatorData ++ clientDataHash) con la public_key
//   - attestation object CBOR-decodificato
// Per il lab consideriamo sufficiente la presenza della challenge in DB e
// lasciamo la verify cryptografica come hook futuro.
// =============================================================================

package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/models"
)

type Handler struct {
	users      *db.UserRepository
	devices    *db.DeviceRepository
	challenges *db.ChallengeRepository
	jwt        *crypto.JWTManager
}

func NewHandler(users *db.UserRepository, devices *db.DeviceRepository, challenges *db.ChallengeRepository, jwt *crypto.JWTManager) *Handler {
	return &Handler{users: users, devices: devices, challenges: challenges, jwt: jwt}
}

// ---------------------------------------------------------------------------
// Registration ceremony
// ---------------------------------------------------------------------------

type beginRegisterReq struct {
	AccessToken string `json:"access_token"`
	DeviceName  string `json:"device_name"`
}

type publicKeyCredentialCreationOptions struct {
	Challenge        string         `json:"challenge"`
	RP               relyingParty   `json:"rp"`
	User             userEntity     `json:"user"`
	PubKeyCredParams []paramEntry   `json:"pubKeyCredParams"`
	Timeout          int            `json:"timeout"`
	Attestation      string         `json:"attestation"`
	SessionID        string         `json:"session_id"`
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

func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	var req beginRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	claims, err := h.jwt.Verify(req.AccessToken)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	user, err := h.users.FindByID(r.Context(), claims.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	chBytes := make([]byte, 32)
	_, _ = rand.Read(chBytes)
	challenge := base64.RawURLEncoding.EncodeToString(chBytes)

	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		Challenge:    challenge,
		UserID:       user.ID,
		CeremonyType: "registration",
	}); err != nil {
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
	respondJSON(w, http.StatusOK, opts)
}

type finishRegisterReq struct {
	SessionID       string `json:"session_id"`
	CredentialID    string `json:"credential_id"`
	PublicKey       string `json:"public_key"`       // base64 standard
	AttestationType string `json:"attestation_type"` // es. "platform" / "cross-platform"
	AAGUID          string `json:"aaguid"`
}

func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	var req finishRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || req.CredentialID == "" || req.PublicKey == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	challenge, err := h.challenges.FindBySessionID(r.Context(), req.SessionID)
	if err != nil {
		if errors.Is(err, db.ErrChallengeNotFound) {
			http.Error(w, "challenge not found or expired", http.StatusUnauthorized)
			return
		}
		http.Error(w, "challenge lookup failed", http.StatusInternalServerError)
		return
	}
	if challenge.CeremonyType != "registration" {
		http.Error(w, "wrong ceremony type", http.StatusBadRequest)
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid public_key encoding", http.StatusBadRequest)
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
		return
	}

	if err := h.users.MarkTPMEnrolled(r.Context(), challenge.UserID, req.PublicKey); err != nil {
		http.Error(w, "failed to update user TPM flag", http.StatusInternalServerError)
		return
	}
	_ = h.challenges.Delete(r.Context(), req.SessionID)

	respondJSON(w, http.StatusOK, map[string]string{
		"status":        "registered",
		"credential_id": req.CredentialID,
	})
}

// ---------------------------------------------------------------------------
// Authentication ceremony (login con device già enrollato)
// ---------------------------------------------------------------------------

type beginLoginReq struct {
	Username string `json:"username"`
}

type publicKeyCredentialRequestOptions struct {
	Challenge        string             `json:"challenge"`
	RPID             string             `json:"rpId"`
	Timeout          int                `json:"timeout"`
	AllowCredentials []allowCredEntry   `json:"allowCredentials"`
	UserVerification string             `json:"userVerification"`
	SessionID        string             `json:"session_id"`
}

type allowCredEntry struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

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

	chBytes := make([]byte, 32)
	_, _ = rand.Read(chBytes)
	challenge := base64.RawURLEncoding.EncodeToString(chBytes)

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

type finishLoginReq struct {
	SessionID    string `json:"session_id"`
	CredentialID string `json:"credential_id"`
	SignCount    uint32 `json:"sign_count"`
}

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

	// Clone detection — sign_count deve aumentare strettamente
	cloneDetected := req.SignCount <= dev.SignCount && dev.SignCount > 0
	_ = h.devices.UpdateSignCount(r.Context(), req.CredentialID, req.SignCount)
	_ = h.challenges.Delete(r.Context(), req.SessionID)

	respondJSON(w, http.StatusOK, map[string]any{
		"status":          "authenticated",
		"credential_id":   req.CredentialID,
		"clone_suspected": cloneDetected,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

