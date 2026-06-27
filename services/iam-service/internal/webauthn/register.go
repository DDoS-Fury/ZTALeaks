package webauthn

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/models"
)

// ---------------------------------------------------------------------------
// /api/v1/auth/register/begin
// ---------------------------------------------------------------------------

// BeginRegistration apre una cerimonia di enrollment. L'utente è già
// autenticato: il middleware ha validato l'HMAC dell'header X-Current-User
// (firmato dalla security-orchestrator) e l'ha riscritto al solo userID.
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
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

	// Idrata le credenziali esistenti per escluderle (no doppio enroll dello
	// stesso authenticator) e per implementare l'interfaccia webauthn.User.
	devs, _ := h.devices.ListByUser(r.Context(), user.ID)
	exclusions := make([]protocol.CredentialDescriptor, 0, len(devs))
	for _, d := range devs {
		user.Credentials = append(user.Credentials, d.Credential)
		exclusions = append(exclusions, d.Credential.Descriptor())
	}

	creation, sessionData, err := h.wa.BeginRegistration(user,
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		http.Error(w, "failed to begin registration", http.StatusInternalServerError)
		slog.Error("failed to begin registration", "user_id", user.ID, "error", err)
		return
	}

	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		UserID:       user.ID,
		CeremonyType: "registration",
		SessionData:  *sessionData,
	}); err != nil {
		http.Error(w, "failed to store challenge", http.StatusInternalServerError)
		slog.Error("failed to store challenge", "user_id", user.ID, "error", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"publicKey":  creation.Response,
		"session_id": sessionID,
	})
}

// ---------------------------------------------------------------------------
// /api/v1/auth/register/finish
// ---------------------------------------------------------------------------

// FinishRegistration valida crittograficamente la risposta dell'authenticator
// (attestation + clientDataJSON + challenge) via go-webauthn, poi salva la
// credenziale verificata in device_fingerprints e marca user.has_tpm=true.
// Il session_id viaggia in query string così il body resta il JSON-credenziale
// standard atteso dalla libreria.
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		slog.Error("missing session_id in finish registration")
		return
	}

	ch, err := h.challenges.FindBySessionID(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, db.ErrChallengeNotFound) {
			http.Error(w, "challenge not found or expired", http.StatusUnauthorized)
			slog.Error("challenge not found or expired", "session_id", sessionID)
			return
		}
		http.Error(w, "challenge lookup failed", http.StatusInternalServerError)
		slog.Error("failed to lookup challenge", "error", err)
		return
	}
	if ch.CeremonyType != "registration" {
		http.Error(w, "wrong ceremony type", http.StatusBadRequest)
		slog.Error("wrong ceremony type", "ceremony_type", ch.CeremonyType)
		return
	}

	user, err := h.users.FindByID(r.Context(), ch.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		slog.Error("failed to find user", "user_id", ch.UserID, "error", err)
		return
	}

	cred, err := h.wa.FinishRegistration(user, ch.SessionData, r)
	if err != nil {
		http.Error(w, "registration verification failed", http.StatusBadRequest)
		slog.Error("registration verification failed", "user_id", ch.UserID, "error", err)
		return
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(cred.ID)
	if err := h.devices.Create(r.Context(), models.DeviceCredential{
		CredentialID: credIDB64,
		UserID:       ch.UserID,
		DeviceName:   "tpm-" + truncate(credIDB64, 8),
		Credential:   *cred,
	}); err != nil {
		http.Error(w, "credential already registered", http.StatusConflict)
		slog.Error("credential already registered", "user_id", ch.UserID, "credential_id", credIDB64)
		return
	}

	if err := h.users.MarkTPMEnrolled(r.Context(), ch.UserID); err != nil {
		http.Error(w, "failed to update user TPM flag", http.StatusInternalServerError)
		slog.Error("failed to update user TPM flag", "user_id", ch.UserID, "error", err)
		return
	}
	_ = h.challenges.Delete(r.Context(), sessionID)

	respondJSON(w, http.StatusOK, map[string]string{
		"status":        "registered",
		"credential_id": credIDB64,
	})
}
