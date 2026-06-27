package webauthn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"ztaleaks/iam-service/internal/crypto"
	"ztaleaks/iam-service/internal/db"
	"ztaleaks/iam-service/internal/models"
)

type beginLoginReq struct {
	Username string `json:"username"`
}

// ---------------------------------------------------------------------------
// /api/v1/auth/login/begin
// ---------------------------------------------------------------------------

// BeginLogin apre una cerimonia di autenticazione. Per non rivelare
// l'esistenza/enrollment di un account (user enumeration) la risposta è sempre
// identica nella forma: se l'utente non esiste o non ha device, si genera una
// cerimonia fittizia ma deterministica (allowCredentials derivate in HMAC dallo
// username). Mai 404 differenziati.
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if err := h.rateLimits.CheckRateLimit(r.Context(), ip); errors.Is(err, db.ErrRateLimitExceeded) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		slog.Warn("login begin rate-limited", "ip", ip)
		return
	}

	var req beginLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		slog.Error("failed to decode begin login request", "error", err)
		return
	}

	user, err := h.users.FindByUsername(r.Context(), req.Username)
	var devs []models.DeviceCredential
	if err == nil {
		devs, _ = h.devices.ListByUser(r.Context(), user.ID)
	}
	if err != nil || len(devs) == 0 {
		h.beginFakeLogin(w, r, req.Username)
		return
	}

	// === Verifica Certificato mTLS ===
	certHeader := r.Header.Get("X-Forwarded-Client-Cert")
	cn, ou, certPresent := extractCertFields(certHeader)

	if !certPresent {
		if strings.EqualFold(user.Role, "admin") || strings.EqualFold(user.Role, "manager") {
			slog.Warn("webauthn login begin fallito: certificato mancante per admin/manager", "username", user.Username, "role", user.Role)
			_ = h.rateLimits.RecordFailure(r.Context(), ip)
			h.beginFakeLogin(w, r, req.Username)
			return
		}
	} else {
		if !strings.EqualFold(cn, req.Username) {
			slog.Warn("webauthn login begin fallito: mismatch CN-Username", "cn", cn, "username", user.Username)
			_ = h.rateLimits.RecordFailure(r.Context(), ip)
			h.beginFakeLogin(w, r, req.Username)
			return
		}
		if !strings.EqualFold(ou, user.Role) {
			slog.Warn("webauthn login begin fallito: mismatch OU-Role", "ou", ou, "role", user.Role)
			_ = h.rateLimits.RecordFailure(r.Context(), ip)
			h.beginFakeLogin(w, r, req.Username)
			return
		}
	}

	for _, d := range devs {
		user.Credentials = append(user.Credentials, d.Credential)
	}
	assertion, sessionData, err := h.wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		// Non far trapelare il motivo: degrada alla cerimonia fittizia.
		slog.Error("begin login failed, returning decoy", "user_id", user.ID, "error", err)
		h.beginFakeLogin(w, r, req.Username)
		return
	}

	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		UserID:       user.ID,
		CeremonyType: "authentication",
		SessionData:  *sessionData,
	}); err != nil {
		http.Error(w, "failed to store challenge", http.StatusInternalServerError)
		slog.Error("failed to store challenge", "user_id", user.ID, "error", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"publicKey":  assertion.Response,
		"session_id": sessionID,
	})
}

// beginFakeLogin produce una cerimonia indistinguibile da quella reale per uno
// username sconosciuto o senza device. Passa per lo stesso wa.BeginLogin così
// forma, timeout e userVerification combaciano esattamente; la sessione è
// marcata Fake e il finish la rifiuterà come una firma errata.
func (h *Handler) beginFakeLogin(w http.ResponseWriter, r *http.Request, username string) {
	assertion, sessionData, err := h.wa.BeginLogin(h.fakeUser(username),
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		http.Error(w, "failed to begin login", http.StatusInternalServerError)
		slog.Error("failed to begin decoy login", "error", err)
		return
	}

	sessionID := newSessionID()
	if err := h.challenges.Create(r.Context(), models.WebAuthnChallenge{
		SessionID:    sessionID,
		CeremonyType: "authentication",
		Fake:         true,
		SessionData:  *sessionData,
	}); err != nil {
		http.Error(w, "failed to store challenge", http.StatusInternalServerError)
		slog.Error("failed to store decoy challenge", "error", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"publicKey":  assertion.Response,
		"session_id": sessionID,
	})
}

// fakeUser costruisce un webauthn.User deterministico derivato dallo username
// via HMAC(enumSecret, ...). L'ID è 12 byte (ObjectID hex valido) e c'è almeno
// una credenziale fittizia, così la cerimonia ha sempre allowCredentials.
func (h *Handler) fakeUser(username string) *models.User {
	idMAC := hmac.New(sha256.New, h.enumSecret)
	idMAC.Write([]byte("uid:" + username))
	idBytes := idMAC.Sum(nil)[:12]

	credMAC := hmac.New(sha256.New, h.enumSecret)
	credMAC.Write([]byte("cred:" + username))
	credID := credMAC.Sum(nil)

	return &models.User{
		ID:       hex.EncodeToString(idBytes),
		Username: username,
		Credentials: []webauthn.Credential{{
			ID:        credID,
			PublicKey: credID, // dummy: non serializzato nel begin
		}},
	}
}

// ---------------------------------------------------------------------------
// /api/v1/auth/login/finish
// ---------------------------------------------------------------------------

// FinishLogin verifica crittograficamente l'assertion (firma sulla chiave
// pubblica registrata, hash di clientDataJSON sulla challenge, clone-counter)
// via go-webauthn. In caso di successo aggiorna la credenziale (sign-count) e
// innesca lo step-up OTP via email. Ogni fallimento — sessione assente, utente
// fittizio, firma errata, clone sospetto — restituisce lo stesso 400 generico.
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if err := h.rateLimits.CheckRateLimit(r.Context(), ip); errors.Is(err, db.ErrRateLimitExceeded) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		slog.Warn("login finish rate-limited", "ip", ip)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.authFail(w, r.Context(), ip, "missing session_id", nil)
		return
	}

	ch, err := h.challenges.FindBySessionID(r.Context(), sessionID)
	if err != nil {
		h.authFail(w, r.Context(), ip, "session not found", err)
		return
	}
	if ch.CeremonyType != "authentication" {
		h.authFail(w, r.Context(), ip, "wrong ceremony type", nil)
		return
	}

	// Utente sconosciuto/senza device: stessa risposta di una firma errata.
	if ch.Fake || ch.UserID == "" {
		_ = h.challenges.Delete(r.Context(), sessionID)
		h.authFail(w, r.Context(), ip, "decoy session", nil)
		return
	}

	user, err := h.users.FindByID(r.Context(), ch.UserID)
	if err != nil {
		h.authFail(w, r.Context(), ip, "user not found", err)
		return
	}
	devs, _ := h.devices.ListByUser(r.Context(), user.ID)
	for _, d := range devs {
		user.Credentials = append(user.Credentials, d.Credential)
	}

	cred, err := h.wa.FinishLogin(user, ch.SessionData, r)
	if err != nil {
		h.authFail(w, r.Context(), ip, "assertion verification failed", err)
		return
	}
	if cred.Authenticator.CloneWarning {
		_ = h.challenges.Delete(r.Context(), sessionID)
		h.authFail(w, r.Context(), ip, "clone warning: sign-count non strettamente crescente", nil)
		return
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(cred.ID)
	if err := h.devices.UpdateCredential(r.Context(), credIDB64, *cred); err != nil {
		slog.Error("failed to persist updated credential", "credential_id", credIDB64, "error", err)
	}
	_ = h.challenges.Delete(r.Context(), sessionID)
	_ = h.rateLimits.ResetLimit(r.Context(), ip)

	// === STEP-UP OTP (invariato) ===
	otp, _ := crypto.GenerateOTP()
	otpHash := crypto.HashOTP(otp, sessionID)
	h.OTP.Create(r.Context(), models.OTPSession{
		SessionToken: sessionID,
		UserID:       user.ID,
		OTPHash:      otpHash,
		Attempts:     0,
	})
	h.Mail.SendOTP(user.Email, otp)

	respondJSON(w, http.StatusOK, map[string]any{
		"status":        "otp_required",
		"session_token": sessionID,
		"message":       "Firma Hardware verificata. OTP inviato via email.",
		"credential_id": credIDB64,
	})
}

// authFail registra il tentativo fallito (rate-limit) e risponde sempre con lo
// stesso 400 generico, così casi reali e fittizi sono indistinguibili.
func (h *Handler) authFail(w http.ResponseWriter, ctx context.Context, ip, reason string, err error) {
	_ = h.rateLimits.RecordFailure(ctx, ip)
	slog.Error("webauthn login failed", "reason", reason, "ip", ip, "error", err)
	http.Error(w, "authentication failed", http.StatusBadRequest)
}

// extractCertFields processa l'header 'x-forwarded-client-cert' generato da Envoy.
func extractCertFields(header string) (cn string, ou string, present bool) {
	if header == "" {
		return "", "", false
	}
	present = true
	parts := strings.Split(header, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(kv[0])) == "subject" {
			subject := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			subParts := strings.Split(subject, ",")
			for _, sp := range subParts {
				skv := strings.SplitN(strings.TrimSpace(sp), "=", 2)
				if len(skv) == 2 {
					key := strings.ToUpper(strings.TrimSpace(skv[0]))
					val := strings.TrimSpace(skv[1])
					switch key {
					case "CN":
						cn = val
					case "OU":
						ou = val
					}
				}
			}
		}
	}
	return cn, ou, present
}
