package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"ztaleaks/identity-service/internal/crypto"
	"ztaleaks/identity-service/internal/db"
	"ztaleaks/identity-service/internal/models"
)

const maxOTPAttempts = 3

type verifyOTPRequest struct {
	SessionToken string `json:"session_token"`
	OTP          string `json:"otp"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// VerifyOTP consuma atomicamente un tentativo sul session_token e, se
// l'OTP combacia, rilascia un JWT RS256 con device_id (se TPM enrollato)
// e fingerprint JA3.
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

	// Operazione atomica: filtra { token, attempts<MAX } + $inc attempts.
	// Cosi' non c'e' finestra di race tra check del limite e increment.
	session, err := api.OTP.ConsumeAttempt(r.Context(), req.SessionToken, maxOTPAttempts)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrSessionNotFound):
			respondError(w, "sessione non valida o scaduta", http.StatusUnauthorized)
		case errors.Is(err, db.ErrAttemptsExceeded):
			_ = api.OTP.Delete(r.Context(), req.SessionToken)
			respondError(w, "tentativi esauriti, ripeti il login", http.StatusForbidden)
		default:
			slog.Error("verify-otp: consume attempt", "error", err)
			respondError(w, "errore lookup sessione", http.StatusInternalServerError)
		}
		return
	}

	ok, err := crypto.ComparePasswordAndHash(req.OTP, session.OTPHash)
	if err != nil || !ok {
		// session.Attempts e' gia' incrementato dall'op atomica.
		remaining := maxOTPAttempts - session.Attempts
		if remaining < 0 {
			remaining = 0
		}
		respondError(w, fmt.Sprintf("OTP non valido. %d tentativi rimasti.", remaining), http.StatusUnauthorized)
		return
	}

	// OTP corretto — pulisco la sessione e rilascio il JWT.
	_ = api.OTP.Delete(r.Context(), req.SessionToken)

	user, err := api.Users.FindByID(r.Context(), session.UserID)
	if err != nil {
		respondError(w, "utente non trovato", http.StatusInternalServerError)
		return
	}

	// device_id: se l'utente ha un device WebAuthn enrollato, lo iniettiamo
	// nel JWT cosi' la security-orchestrator puo' chiedere a OPA di valutare
	// il tier "cert+tpm".
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

	// aggiornamento last_login_info in background per non bloccare la risposta
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
