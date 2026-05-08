// =============================================================================
// Identity Service HTTP Handlers
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Tre flussi:
//   POST /api/v1/auth/register     — crea utente (Argon2id)
//   POST /api/v1/auth/login        — verifica password, genera OTP, email via MailHog
//   POST /api/v1/auth/verify-otp   — verifica OTP, rilascia JWT RS256 con device_id
// =============================================================================

package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/mailer"
	"ztaleaks/identity-service/internal/models"
)

// IdentityAPI raccoglie tutte le dipendenze degli handler.
type IdentityAPI struct {
	Users      *db.UserRepository
	OTP        *db.OTPRepository
	Devices    *db.DeviceRepository
	JWT        *crypto.JWTManager
	Mail       *mailer.SMTPMailer
}

// ---------------------------------------------------------------------------
// /api/v1/auth/register
// ---------------------------------------------------------------------------

type registerRequest struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	ClearanceLevel string `json:"clearance_level"`
}

type registerResponse struct {
	Status string `json:"status"`
	UserID string `json:"user_id"`
}

func (api *IdentityAPI) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" || req.Email == "" || req.Role == "" {
		respondError(w, "campi mancanti (username, email, password, role)", http.StatusBadRequest)
		return
	}
	if req.ClearanceLevel == "" {
		req.ClearanceLevel = "INTERNAL"
	}

	hash, err := crypto.GenerateFromPassword(req.Password)
	if err != nil {
		slog.Error("register: hash password", "error", err)
		respondError(w, "errore interno", http.StatusInternalServerError)
		return
	}

	u := &models.User{
		Username:       req.Username,
		Email:          req.Email,
		PasswordHash:   hash,
		Role:           req.Role,
		ClearanceLevel: req.ClearanceLevel,
		TwoFAEnabled:   true, // OTP via email è il default — direttiva mantenuta
		Status:         "active",
	}
	if err := api.Users.Create(r.Context(), u); err != nil {
		respondError(w, err.Error(), http.StatusConflict)
		return
	}
	slog.Info("utente registrato", "username", u.Username, "role", u.Role)
	respondJSON(w, http.StatusCreated, registerResponse{Status: "registered", UserID: u.ID})
}

// ---------------------------------------------------------------------------
// /api/v1/auth/login
// ---------------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Status       string `json:"status"`
	SessionToken string `json:"session_token,omitempty"`
	Message      string `json:"message,omitempty"`
}

func (api *IdentityAPI) Login(w http.ResponseWriter, r *http.Request) {
	slog.Info("login richiesto", "remote", r.RemoteAddr)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		respondError(w, "credenziali mancanti", http.StatusBadRequest)
		return
	}

	user, err := api.Users.FindByUsername(r.Context(), req.Username)
	if err != nil {
		// timing-attack mitigation
		dummy, _ := crypto.GenerateFromPassword("dummy")
		_, _ = crypto.ComparePasswordAndHash(req.Password, dummy)
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		return
	}

	ok, err := crypto.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil || !ok {
		respondError(w, "credenziali non valide", http.StatusUnauthorized)
		return
	}

	// OTP a 6 cifre, hash Argon2id, TTL 5 min, max 3 tentativi
	otp, err := generateOTP()
	if err != nil {
		respondError(w, "errore generazione OTP", http.StatusInternalServerError)
		return
	}
	otpHash, err := crypto.GenerateFromPassword(otp)
	if err != nil {
		respondError(w, "errore hash OTP", http.StatusInternalServerError)
		return
	}
	sessionToken := newSessionToken()

	if err := api.OTP.Create(r.Context(), models.OTPSession{
		SessionToken: sessionToken,
		UserID:       user.ID,
		OTPHash:      otpHash,
		Attempts:     0,
	}); err != nil {
		slog.Error("login: store OTP", "error", err)
		respondError(w, "errore interno", http.StatusInternalServerError)
		return
	}

	// Best-effort: anche se l'email fallisce l'OTP è in DB e l'utente può
	// ritentare. Loggare comunque.
	if err := api.Mail.SendOTP(user.Email, otp); err != nil {
		slog.Error("login: invio email OTP", "error", err, "to", user.Email)
	}

	slog.Info("OTP emesso", "user_id", user.ID, "email", user.Email)
	respondJSON(w, http.StatusOK, loginResponse{
		Status:       "otp_required",
		SessionToken: sessionToken,
		Message:      "OTP inviato all'email registrata",
	})
}

// ---------------------------------------------------------------------------
// /api/v1/auth/verify-otp
// ---------------------------------------------------------------------------

type verifyOTPRequest struct {
	SessionToken string `json:"session_token"`
	OTP          string `json:"otp"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (api *IdentityAPI) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req verifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if req.SessionToken == "" || req.OTP == "" {
		respondError(w, "session_token e otp obbligatori", http.StatusBadRequest)
		return
	}

	session, err := api.OTP.FindBySessionToken(r.Context(), req.SessionToken)
	if err != nil {
		if errors.Is(err, db.ErrSessionNotFound) {
			respondError(w, "sessione non valida o scaduta", http.StatusUnauthorized)
			return
		}
		respondError(w, "errore lookup sessione", http.StatusInternalServerError)
		return
	}

	if session.Attempts >= 3 {
		_ = api.OTP.Delete(r.Context(), req.SessionToken)
		respondError(w, "tentativi esauriti, ripeti il login", http.StatusForbidden)
		return
	}
	_ = api.OTP.IncrementAttempts(r.Context(), req.SessionToken)

	ok, err := crypto.ComparePasswordAndHash(req.OTP, session.OTPHash)
	if err != nil || !ok {
		remaining := 3 - session.Attempts - 1
		respondError(w, fmt.Sprintf("OTP non valido. %d tentativi rimasti.", remaining), http.StatusUnauthorized)
		return
	}

	// OTP corretto — pulisco e rilascio JWT
	_ = api.OTP.Delete(r.Context(), req.SessionToken)

	user, err := api.Users.FindByID(r.Context(), session.UserID)
	if err != nil {
		respondError(w, "utente non trovato", http.StatusInternalServerError)
		return
	}

	// device_id: se l'utente ha un device WebAuthn enrollato, lo iniettiamo
	// nel JWT così la security-orchestrator (in step 2) può chiedere a OPA
	// di valutare il tier "cert+tpm".
	deviceID := ""
	if dev, _ := api.Devices.FindMostRecentByUser(r.Context(), user.ID); dev != nil {
		deviceID = dev.CredentialID
	}

	ja3 := r.Header.Get("X-JA3-Fingerprint")
	tok, err := api.JWT.Issue(user.ID, user.Role, user.ClearanceLevel, deviceID, ja3, true)
	if err != nil {
		slog.Error("verify-otp: emissione JWT", "error", err)
		respondError(w, "errore emissione token", http.StatusInternalServerError)
		return
	}

	// aggiornamento last_login_info in background
	go func(userID string, info models.LoginInfo) {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := api.Users.UpdateLastLogin(bg, userID, info); err != nil {
			slog.Warn("aggiornamento last_login_info", "error", err)
		}
	}(user.ID, models.LoginInfo{
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		JA3Finger: ja3,
	})

	slog.Info("login completato", "user_id", user.ID, "device_enrolled", deviceID != "")
	respondJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok,
		ExpiresIn:   int(crypto.AccessTokenTTL.Seconds()),
		TokenType:   "Bearer",
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func generateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func newSessionToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, msg string, status int) {
	respondJSON(w, status, map[string]string{"error": msg})
}
