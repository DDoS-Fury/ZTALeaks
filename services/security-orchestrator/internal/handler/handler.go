package handler

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"ztaleaks/security-orchestrator/internal/aiscorer"
	"ztaleaks/security-orchestrator/internal/cert"
	jwtpkg "ztaleaks/security-orchestrator/internal/jwt"
	"ztaleaks/security-orchestrator/internal/opa"
	"ztaleaks/security-orchestrator/internal/tpm"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// OPALogsHandler processa i log decisionali di OPA e li appende al file indicato.
func OPALogsHandler(opaLogFile *os.File) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "bad gzip", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			reader = gz
		}
		var entries []json.RawMessage
		if err := json.NewDecoder(reader).Decode(&entries); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		for _, e := range entries {
			if opaLogFile != nil {
				_, _ = opaLogFile.Write(append([]byte(e), '\n'))
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// BuildEvaluateHandler costruisce l'handler ext_authz
func BuildEvaluateHandler(verifier *jwtpkg.Verifier, tpmLookup *tpm.Lookup, usersColl *mongo.Collection, opaClient *opa.Client, aiClient *aiscorer.Client) http.HandlerFunc {
	const evalPrefix = "/api/v1/evaluate"
	return func(w http.ResponseWriter, r *http.Request) {
		origPath := r.URL.Path
		if strings.HasPrefix(origPath, evalPrefix) {
			origPath = strings.TrimPrefix(origPath, evalPrefix)
			if origPath == "" {
				origPath = "/"
			}
		}
		if h := r.Header.Get("X-Original-Uri"); h != "" {
			origPath = h
		} else if h := r.Header.Get("X-Authz-Request-Path"); h != "" {
			origPath = h
		}

		method := r.Header.Get("X-Authz-Request-Method")
		if method == "" {
			method = r.Method
		}
		zoneID := r.Header.Get("X-Zone-Id")
		ja3 := r.Header.Get("X-Ja3-Fingerprint")
		clientIP := clientIPFromRequest(r)
		now := time.Now().UTC()

		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			slog.Info("ext_authz: nessun token", "path", origPath)
			ctxInput := buildContext(now, 0, clientIP)
			ok := evalOPA(r.Context(), opaClient, opa.Input{
				Request:     opa.Request{Method: method, Path: origPath},
				Claims:      nil,
				CertPresent: false,
				TPMVerified: false,
				ZoneID:      zoneID,
				Context:     ctxInput,
				JA3:         ja3Input(ja3),
			})
			respondAllow(w, ok, "")
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("JWT verify fallita", "error", err)
			http.Error(w, `{"allowed":false,"reason":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		cc := cert.Parse(r.Header.Get("X-Forwarded-Client-Cert"))
		tpmOK, tpmData := tpmLookup.Verify(r.Context(), claims.UserID, claims.DeviceID)

		evaluateStrictDeviceFingerprinting(r.Context(), cc, claims, tpmOK, tpmData, usersColl, r)

		if ja3 == "" {
			ja3 = claims.JA3
		}
		sessionAge := sessionAgeSeconds(claims, now)
		ctxInput := buildContext(now, sessionAge, clientIP)

		ai := aiClient.Evaluate(r.Context(), aiscorer.Features{
			UserID:    claims.UserID,
			Method:    method,
			Path:      origPath,
			Timestamp: ctxInput.Timestamp,
			HourOfDay: ctxInput.HourOfDay,
			DayOfWeek: ctxInput.DayOfWeek,
			JA3:       ja3,
			ClientIP:  clientIP,
		})

		input := opa.Input{
			Request:     opa.Request{Method: method, Path: origPath},
			Claims:      ClaimsToMap(claims),
			CertPresent: cc.Present,
			CertSubject: cc.Subject,
			TPMVerified: tpmOK,
			ZoneID:      zoneID,
			AI:          &opa.AI{Score: ai.Score, Confidence: ai.Confidence},
			Context:     ctxInput,
			JA3:         ja3Input(ja3),
		}
		allow := evalOPA(r.Context(), opaClient, input)
		slog.Info("decisione",
			"path", origPath, "method", method, "user", claims.UserID,
			"role", claims.Role, "clearance", claims.ClearanceLevel,
			"cert_present", cc.Present, "tpm_verified", tpmOK,
			"zone", zoneID, "ai_score", ai.Score, "ai_confidence", ai.Confidence,
			"session_age_s", sessionAge, "hour", ctxInput.HourOfDay,
			"allow", allow,
		)
		respondAllow(w, allow, claims.UserID)
	}
}

// buildContext popola la sotto-struttura context per OPA. Centralizzata cosi'
// sia il ramo "no token" sia quello autenticato producono la stessa shape.
func buildContext(now time.Time, sessionAgeSec int64, clientIP string) *opa.Context {
	return &opa.Context{
		Timestamp:         now.Format(time.RFC3339),
		HourOfDay:         now.Hour(),
		DayOfWeek:         int(now.Weekday()),
		SessionAgeSeconds: sessionAgeSec,
		ClientIP:          clientIP,
	}
}

func ja3Input(md5 string) *opa.JA3 {
	if md5 == "" {
		return nil
	}
	return &opa.JA3{MD5: md5}
}

func sessionAgeSeconds(claims *jwtpkg.ZTAClaims, now time.Time) int64 {
	if claims == nil || claims.IssuedAt == nil {
		return 0
	}
	age := now.Sub(claims.IssuedAt.Time).Seconds()
	if age < 0 {
		return 0
	}
	return int64(age)
}

func clientIPFromRequest(r *http.Request) string {
	if xfwd := r.Header.Get("X-Forwarded-For"); xfwd != "" {
		return strings.TrimSpace(strings.Split(xfwd, ",")[0])
	}
	return strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0])
}

// evaluateStrictDeviceFingerprinting analizza il payload HW (certificato/tpm/db) e logga le discrepanze in Shadow Mode
func evaluateStrictDeviceFingerprinting(ctx context.Context, cc cert.ClientCert, claims *jwtpkg.ZTAClaims, tpmOK bool, tpmData map[string]any, usersColl *mongo.Collection, r *http.Request) {
	var certCommonName string
	var certOU string

	if cc.Present {
		parts := strings.Split(cc.Subject, ",")
		for _, part := range parts {
			partT := strings.TrimSpace(part)
			if strings.HasPrefix(partT, "CN=") {
				certCommonName = strings.TrimPrefix(partT, "CN=")
			} else if strings.HasPrefix(partT, "OU=") {
				certOU = strings.TrimPrefix(partT, "OU=")
			}
		}
	}

	var ouMismatch bool
	if cc.Present && certOU != "" {
		if !strings.EqualFold(certOU, claims.Role) {
			ouMismatch = true
		}
	}

	var user map[string]any
	errQuery := usersColl.FindOne(ctx, bson.M{"_id": claims.UserID}).Decode(&user)
	var userHasTPM bool
	var username string
	if errQuery == nil && user != nil {
		if b, ok := user["has_tpm"].(bool); ok {
			userHasTPM = b
		}
		if un, ok := user["username"].(string); ok {
			username = un
		}
	}

	var tpmDevName, tpmAAGUID any
	if tpmData != nil {
		tpmDevName = tpmData["device_name"]
		tpmAAGUID = tpmData["aaguid"]
	}

	// Calcolo Network Location per il modello AI
	networkLocation := "perimeter"
	xfwd := r.Header.Get("X-Forwarded-For")
	if xfwd == "" {
		xfwd = r.RemoteAddr
	}
	ip := strings.TrimSpace(strings.Split(xfwd, ",")[0])
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "172.") {
		networkLocation = "internal"
	}

	// Estrazione info richiesta (Method, Path, Zone, JA3)
	origPath := r.Header.Get("X-Original-Uri")
	if origPath == "" {
		origPath = r.Header.Get("X-Authz-Request-Path")
	}
	if origPath == "" {
		origPath = r.URL.Path
	}

	method := r.Header.Get("X-Authz-Request-Method")
	if method == "" {
		method = r.Method
	}

	zoneID := r.Header.Get("X-Zone-Id")
	ja3 := r.Header.Get("X-Ja3-Fingerprint")
	if ja3 == "" && claims != nil {
		ja3 = claims.JA3
	}

	slog.Info("strict_device_fingerprinting_evaluation",
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"request_method", method,
		"request_path", origPath,
		"zone_id", zoneID,
		"ja3_fingerprint", ja3,
		"user_id", claims.UserID,
		"username_db", username,
		"cert_present", cc.Present,
		"cert_common_name", certCommonName,
		"cert_ou", certOU,
		"ou_mismatch", ouMismatch,
		"tpm_verified", tpmOK,
		"user_db_has_tpm", userHasTPM,
		"tpm_device_name", tpmDevName,
		"tpm_aaguid", tpmAAGUID,
		"network_location", networkLocation,
		"ip_address", ip,
		"action", "LOG_ONLY",
	)
}

func evalOPA(ctx context.Context, c *opa.Client, in opa.Input) bool {
	allow, err := c.Evaluate(ctx, in)
	if err != nil {
		slog.Error("OPA error → deny by default", "error", err)
		return false
	}
	return allow
}

func respondAllow(w http.ResponseWriter, allow bool, userID string) {
	w.Header().Set("Content-Type", "application/json")
	if allow {
		if userID != "" {
			w.Header().Set("x-current-user", userID)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":true}`))
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"allowed":false,"reason":"policy denied"}`))
}

func bearerToken(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// ClaimsToMap serializza ZTAClaims in mappa generica.
func ClaimsToMap(c *jwtpkg.ZTAClaims) map[string]any {
	m := map[string]any{
		"sub":             c.UserID,
		"role":            c.Role,
		"clearance_level": c.ClearanceLevel,
		"mfa_verified":    c.MFAVerified,
	}
	if c.DeviceID != "" {
		m["device_id"] = c.DeviceID
	}
	if c.JA3 != "" {
		m["ja3"] = c.JA3
	}
	return m
}
