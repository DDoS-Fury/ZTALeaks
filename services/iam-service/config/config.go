package config

import (
	"fmt"
	"log/slog"
	"os"

	"ztaleaks/iam-service/internal/db"

	"github.com/go-webauthn/webauthn/webauthn"
)

// AppConfig raccoglie i parametri di runtime dell'iam-service.
// Caricato all'avvio da LoadConfig — il main.go non legge piu' env vars.
type AppConfig struct {
	Port   string
	LogDir string
	DB     *db.MongoDB

	// WebAuthn è l'istanza Relying Party condivisa (RPID/RPOrigin/displayname),
	// costruita una sola volta qui e iniettata negli handler.
	WebAuthn *webauthn.WebAuthn

	// EnumSecret deriva le allowCredentials fittizie ma deterministiche per gli
	// utenti sconosciuti (anti user-enumeration su /login/begin).
	EnumSecret []byte

	// UserHeaderSecret valida l'HMAC dell'header X-Current-User firmato dalla
	// security-orchestrator (trust boundary: impedisce lo spoof dell'identità
	// da parte di un peer che raggiunga l'iam-service bypassando l'orchestrator).
	UserHeaderSecret []byte
}

// LoadConfig connette al Security DB e raccoglie i parametri di porta/log dir.
// In caso di failure di connessione l'errore si propaga al main che termina.
func LoadConfig() (*AppConfig, error) {
	port := getenv("IAM_SERVICE_PORT", "8082")
	logDir := getenv("LOG_DIR", "/var/log/ztaleaks/iam")

	dbURI := getenv("SECURITY_DB_URI", "mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin")
	dbName := getenv("SECURITY_DB_NAME", "securitydb")

	mongoClient, err := db.Connect(dbURI, dbName)
	if err != nil {
		return nil, fmt.Errorf("connessione security-db: %w", err)
	}

	rpID := getenv("WEBAUTHN_RP_ID", "localhost")
	rpOrigin := getenv("WEBAUTHN_RP_ORIGIN", "https://localhost:8443")
	rpName := getenv("WEBAUTHN_RP_DISPLAY_NAME", "ZTALeaks Nuclear Plant")

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn (rpid=%q origin=%q): %w", rpID, rpOrigin, err)
	}

	return &AppConfig{
		Port:             port,
		LogDir:           logDir,
		DB:               mongoClient,
		WebAuthn:         wa,
		EnumSecret:       requireSecret("WEBAUTHN_ENUM_SECRET"),
		UserHeaderSecret: requireSecret("ORCH_IAM_SHARED_SECRET"),
	}, nil
}

// requireSecret legge un secret da env. In un lab senza la variabile impostata
// usa un default deterministico ma logga un warning: senza secret condiviso
// reale le mitigazioni (anti-enumeration, trust boundary) restano dimostrative.
func requireSecret(key string) []byte {
	if v := os.Getenv(key); v != "" {
		return []byte(v)
	}
	slog.Warn("secret non impostato, uso un default da lab (NON usare in produzione)", "env", key)
	return []byte("ztaleaks-dev-" + key)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
