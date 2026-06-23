package logger

import (
	"log/slog"
	"os"
	"path/filepath"
)

// InitLogger configura ed avvia un logger strutturato in formato JSON.
// Scrive i log in un file, che poi sarà montato come volume Docker.
func InitLogger(logDir, logFilename string) (*slog.Logger, error) {
	// Crea la directory dei log se non esiste
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	logFilePath := filepath.Join(logDir, logFilename)
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Sfruttiamo slog (Standard Library Go >1.21) per produrre JSON in maniera sicura (thread-safe inclusa nel framework)
	handler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	// Pre-popola l'attributo `service`: ogni slog.X erediter la provenienza.
	logger := slog.New(handler).With("service", "iam-service")

	// Imposta il default al nostro nuovo logger in json
	slog.SetDefault(logger)

	return logger, nil
}
