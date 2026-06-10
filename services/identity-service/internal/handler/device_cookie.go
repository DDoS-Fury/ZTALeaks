package handler

import (
	"log/slog"
	"net/http"
	"os"
	"sync"

	"ztaleaks/identity-service/internal/crypto"
)

// deviceCookieMaxAge — 1 anno: il cookie identifica il *dispositivo*, non la
// sessione; deve sopravvivere ai login (la rotazione produrrebbe nodi freddi
// nel grafo del modello AI a ogni visita).
const deviceCookieMaxAge = 365 * 24 * 3600

var (
	deviceCookieSecretOnce sync.Once
	deviceCookieSecretVal  []byte
)

// deviceCookieSecret legge DEVICE_COOKIE_SECRET (condiviso con la
// security-orchestrator). Il default consente lo sviluppo locale senza .env.
func deviceCookieSecret() []byte {
	deviceCookieSecretOnce.Do(func() {
		s := os.Getenv("DEVICE_COOKIE_SECRET")
		if s == "" {
			s = "ztaleaks-dev-device-cookie-secret"
			slog.Warn("DEVICE_COOKIE_SECRET non impostato: uso il default di sviluppo")
		}
		deviceCookieSecretVal = []byte(s)
	})
	return deviceCookieSecretVal
}

// ensureDeviceCookie emette il cookie dispositivo se assente o con firma non
// valida. Idempotente: un cookie valido non viene mai ruotato. Va chiamata
// PRIMA di scrivere lo status della risposta (Set-Cookie e' un header).
func ensureDeviceCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(crypto.DeviceCookieName); err == nil {
		if _, ok := crypto.VerifyDeviceCookieValue(c.Value, deviceCookieSecret()); ok {
			return
		}
	}
	value, err := crypto.NewDeviceCookieValue(deviceCookieSecret())
	if err != nil {
		slog.Error("emissione device cookie", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     crypto.DeviceCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   deviceCookieMaxAge,
		HttpOnly: true,
		Secure:   true, // il fronte e' Envoy con TLS downstream
		SameSite: http.SameSiteLaxMode,
	})
}
