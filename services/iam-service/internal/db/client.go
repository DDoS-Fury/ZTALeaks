package db

import (
	"context"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	Client *mongo.Client
	DB     *mongo.Database
}

// Connect inizializza la connessione a MongoDB e imposta il client.
// Utilizza i thread internamente sfruttando il pool di connessioni nativo del driver.
func Connect(uri, dbName string) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	slog.Info("Connessione al Security DB", "uri", uri, "db", dbName)

	clientOptions := options.Client().ApplyURI(uri).
		SetAppName("iam-service"). // registrato nel profiler come campo `service`
		SetMaxPoolSize(50).        // Pool di connessioni per gestire richieste concorrenti
		SetMinPoolSize(10). // Pool minimo
		SetMaxConnIdleTime(time.Minute * 5)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	// Verifica della connessione
	if err = client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	slog.Info("Connessione al Security DB stabilita con successo.")
	return &MongoDB{
		Client: client,
		DB:     client.Database(dbName),
	}, nil
}

// Disconnect chiude in sicurezza la connessione al database
func (m *MongoDB) Disconnect() {
	if m.Client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Client.Disconnect(ctx); err != nil {
		slog.Error("Errore durante la chiusura locale del database", "error", err.Error())
	}
}
