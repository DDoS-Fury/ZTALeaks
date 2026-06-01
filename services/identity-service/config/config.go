package config

import (
	"fmt"
	"os"

	"ztaleaks/identity-service/internal/db"
)

// AppConfig raccoglie i parametri di runtime dell'identity-service.
// Caricato all'avvio da LoadConfig — il main.go non legge piu' env vars.
type AppConfig struct {
	Port    string
	LogDir  string
	DB      *db.MongoDB
}

// LoadConfig connette al Security DB e raccoglie i parametri di porta/log dir.
// In caso di failure di connessione l'errore si propaga al main che termina.
func LoadConfig() (*AppConfig, error) {
	port := getenv("IDENTITY_SERVICE_PORT", "8082")
	logDir := getenv("LOG_DIR", "/var/log/ztaleaks/identity")

	dbURI := getenv("SECURITY_DB_URI", "mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin")
	dbName := getenv("SECURITY_DB_NAME", "securitydb")

	mongoClient, err := db.Connect(dbURI, dbName)
	if err != nil {
		return nil, fmt.Errorf("connessione security-db: %w", err)
	}

	return &AppConfig{
		Port:   port,
		LogDir: logDir,
		DB:     mongoClient,
	}, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
