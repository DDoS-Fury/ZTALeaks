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
	"ztaleaks/security-orchestrator/internal/cache"
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
func BuildEvaluateHandler(verifier *jwtpkg.Verifier, tpmLookup *tpm.Lookup, usersColl *mongo.Collection, opaClient *opa.Client, aiClient *aiscorer.Client, snortCache *cache.SnortCache) http.HandlerFunc {
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
		reqID := r.Header.Get("X-Request-Id")
		cc := cert.Parse(r.Header.Get("X-Forwarded-Client-Cert"))

		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			slog.Info("ext_authz: nessun token", "path", origPath, "request_id", reqID)

			// Chiama l'analisi fingerprint anche per richieste anonime per tracciamento
			evaluateStrictDeviceFingerprinting(r.Context(), cc, nil, false, nil, usersColl, r, reqID, snortCache)

			ctxInput := buildContext(now, 0, clientIP)
			
			// Valutazione AI per Guest
			aiEvent := buildAIEvent(r, origPath, method, now, clientIP, ja3, nil, cc, false, snortCache)
			ai := aiClient.Infer(r.Context(), aiEvent)

			ok := evalOPA(r.Context(), opaClient, opa.Input{
				Request:     opa.Request{Method: method, Path: origPath},
				Claims:      nil,
				CertPresent: false,
				TPMVerified: false,
				ZoneID:      zoneID,
				AI:          &opa.AI{Score: ai.Score, Confidence: ai.Confidence},
				Context:     ctxInput,
				JA3:         ja3Input(ja3),
			})

			if ok {
				go func() {
					_ = aiClient.Update(context.Background(), aiEvent)
				}()
			}

			respondAllow(w, ok, "", clientIP)
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("JWT verify fallita", "error", err, "request_id", reqID)

			// Chiama l'analisi fingerprint per richieste non autorizzate per tracciamento
			evaluateStrictDeviceFingerprinting(r.Context(), cc, nil, false, nil, usersColl, r, reqID, snortCache)

			http.Error(w, `{"allowed":false,"reason":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		tpmOK, tpmData := tpmLookup.Verify(r.Context(), claims.UserID, claims.DeviceID)

		evaluateStrictDeviceFingerprinting(r.Context(), cc, claims, tpmOK, tpmData, usersColl, r, reqID, snortCache)

		if ja3 == "" {
			ja3 = claims.JA3
		}
		sessionAge := sessionAgeSeconds(claims, now)
		ctxInput := buildContext(now, sessionAge, clientIP)

		aiEvent := buildAIEvent(r, origPath, method, now, clientIP, ja3, claims, cc, tpmOK, snortCache)
		ai := aiClient.Infer(r.Context(), aiEvent)

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

		if allow {
			go func() {
				_ = aiClient.Update(context.Background(), aiEvent)
			}()
		}
		slog.Info("decisione",
			"path", origPath, "method", method, "user", claims.UserID,
			"role", claims.Role, "clearance", claims.ClearanceLevel,
			"cert_present", cc.Present, "tpm_verified", tpmOK,
			"zone", zoneID, "ai_score", ai.Score, "ai_confidence", ai.Confidence,
			"session_age_s", sessionAge, "hour", ctxInput.HourOfDay,
			"allow", allow,
		)
		respondAllow(w, allow, claims.UserID, clientIP)
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

// clientIPFromRequest ricava l'IP reale del client fidandosi SOLO di ciò che
// Envoy impone, mai di header controllabili dal client. Con use_remote_address:
// true Envoy popola x-envoy-external-address con l'indirizzo che vede davvero
// sulla connessione e lo sovrascrive ad ogni richiesta: non è falsificabile.
// Il primo elemento di X-Forwarded-For invece è iniettabile dall'esterno
// (un client può dichiararsi "interno"), quindi non va usato.
func clientIPFromRequest(r *http.Request) string {
	if ext := strings.TrimSpace(r.Header.Get("X-Envoy-External-Address")); ext != "" {
		return ext
	}
	// Fallback difensivo: Envoy appende l'IP reale in CODA a X-Forwarded-For,
	// quindi l'ultimo elemento è quello attendibile (non il primo).
	if xfwd := r.Header.Get("X-Forwarded-For"); xfwd != "" {
		parts := strings.Split(xfwd, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0])
}

// evaluateStrictDeviceFingerprinting analizza il payload HW (certificato/tpm/db) e logga le discrepanze in Shadow Mode
func evaluateStrictDeviceFingerprinting(ctx context.Context, cc cert.ClientCert, claims *jwtpkg.ZTAClaims, tpmOK bool, tpmData map[string]any, usersColl *mongo.Collection, r *http.Request, reqID string, snortCache *cache.SnortCache) {
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
	if cc.Present && certOU != "" && claims != nil {
		if !strings.EqualFold(certOU, claims.Role) {
			ouMismatch = true
		}
	}

	var user map[string]any
	var userHasTPM bool
	var username string
	userID := "anonymous"

	if claims != nil {
		userID = claims.UserID
		errQuery := usersColl.FindOne(ctx, bson.M{"_id": claims.UserID}).Decode(&user)
		if errQuery == nil && user != nil {
			if b, ok := user["has_tpm"].(bool); ok {
				userHasTPM = b
			}
			if un, ok := user["username"].(string); ok {
				username = un
			}
		}
	}

	var tpmDevName, tpmAAGUID any
	if tpmData != nil {
		tpmDevName = tpmData["device_name"]
		tpmAAGUID = tpmData["aaguid"]
	}

	// Calcolo Network Location per il modello AI
	networkLocation := "perimeter"
	ip := clientIPFromRequest(r)
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

	if reqID == "" {
		reqID = "unknown_request"
	}

	var alertEdge, alertMid, alertInt bool
	if snortCache != nil {
		if alerts, valid := snortCache.GetAlerts(ip); valid {
			if alerts.AlertEdge != nil {
				alertEdge = true
			}
			if alerts.AlertMid != nil {
				alertMid = true
			}
			if alerts.AlertInternal != nil {
				alertInt = true
			}
		}

		// Fallback: snort-mid ispeziona il traffico ext_authz (Envoy -> Orchestrator).
		// Il Source IP nel pacchetto IP per questo traffico è l'IP di Envoy.
		envoyIP := strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0])
		if ip != envoyIP {
			if envoyAlerts, valid := snortCache.GetAlerts(envoyIP); valid {
				if envoyAlerts.AlertMid != nil {
					alertMid = true
				}
				if envoyAlerts.AlertEdge != nil {
					alertEdge = true
				}
				if envoyAlerts.AlertInternal != nil {
					alertInt = true
				}
			}
		}
	}

	slog.Info("strict_device_fingerprinting_evaluation",
		"request_id", reqID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"request_method", method,
		"request_path", origPath,
		"zone_id", zoneID,
		"ja3_fingerprint", ja3,
		"user_id", userID,
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
		"allert_snort_internal", alertInt,
		"allert_snort", alertEdge,
		"allert_snort_mid", alertMid,
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

func respondAllow(w http.ResponseWriter, allow bool, userID string, clientIP string) {
	w.Header().Set("Content-Type", "application/json")
	if allow {
		if userID != "" {
			w.Header().Set("x-current-user", userID)
		}
		if clientIP != "" {
			w.Header().Set("x-envoy-external-address", clientIP)
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

func buildAIEvent(r *http.Request, origPath string, method string, now time.Time, clientIP string, ja3Header string, claims *jwtpkg.ZTAClaims, cc cert.ClientCert, tpmOK bool, snortCache *cache.SnortCache) aiscorer.Event {
	ja3Float := 1.0
	if claims != nil && claims.JA3 != "" && claims.JA3 != ja3Header {
		ja3Float = 0.0
	}

	var alertEdge, alertMid, alertInt float64
	if snortCache != nil {
		if alerts, valid := snortCache.GetAlerts(clientIP); valid {
			if alerts.AlertEdge != nil {
				alertEdge = 1.0
			}
			if alerts.AlertMid != nil {
				alertMid = 1.0
			}
			if alerts.AlertInternal != nil {
				alertInt = 1.0
			}
		}
		envoyIP := strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0])
		if clientIP != envoyIP {
			if envoyAlerts, valid := snortCache.GetAlerts(envoyIP); valid {
				if envoyAlerts.AlertMid != nil {
					alertMid = 1.0
				}
				if envoyAlerts.AlertEdge != nil {
					alertEdge = 1.0
				}
				if envoyAlerts.AlertInternal != nil {
					alertInt = 1.0
				}
			}
		}
	}

	snortFloat := 0.0
	if alertEdge == 1.0 || alertMid == 1.0 || alertInt == 1.0 {
		snortFloat = 1.0
	}

	methodFloat := 0.0
	switch method {
	case "POST":
		methodFloat = 1.0
	case "PUT":
		methodFloat = 2.0
	case "DELETE":
		methodFloat = 3.0
	case "PATCH":
		methodFloat = 4.0
	}

	srcFeat := make([]float64, 16)
	// Deve restare allineato a ROLES in ai-inference/src/data/stream_synthetic.py
	roles := []string{"guest", "operator", "manager", "admin"}

	if claims != nil {
		roleIdx := -1
		for i, r := range roles {
			if r == claims.Role {
				roleIdx = i
				break
			}
		}
		if roleIdx != -1 {
			srcFeat[0] = float64(roleIdx) / float64(len(roles)-1)
		}
		
		clearances := []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}
		clrIdx := 0
		for i, c := range clearances {
			if strings.EqualFold(c, claims.ClearanceLevel) {
				clrIdx = i
				break
			}
		}
		srcFeat[1] = float64(clrIdx) / 4.0
	}

	tier := 0.0
	if cc.Present {
		if tpmOK {
			tier = 1.0
		} else {
			tier = 0.5
		}
	}
	srcFeat[2] = tier

	keySrc := clientIP
	if claims != nil {
		keySrc = claims.UserID
	}

	return aiscorer.Event{
		KeySrc:    keySrc,
		KeyDst:    normalizeAIPath(origPath),
		Timestamp: now.Unix(),
		Features:  []float64{ja3Float, snortFloat, alertEdge, alertMid, alertInt, methodFloat},
		SrcFeat:   srcFeat,
	}
}

// aiResourceBases: rotte base note al modello AI; le sottorotte con
// path-parameter (es. /api/v1/personnel/123) vengono ricondotte alla base,
// rispecchiando la risoluzione "rotta_base" di infra/opa/policy.rego.
// Deve restare allineato a RESOURCE_URIS in ai-inference/src/data/stream_synthetic.py
var aiResourceBases = []string{
	"/api/v1/trusted-guard/sanitized-delete-personnel",
	"/api/v1/personnel",
	"/api/v1/documents",
	"/api/v1/nuclear-materials",
	"/api/v1/reactor-parameters",
}

func normalizeAIPath(path string) string {
	for _, base := range aiResourceBases {
		if path == base || strings.HasPrefix(path, base+"/") {
			return base
		}
	}
	if strings.HasPrefix(path, "/static/") {
		return "/static"
	}
	return path
}
