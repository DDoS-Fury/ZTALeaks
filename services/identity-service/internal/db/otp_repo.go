package db

import (
	"context"
	"errors"
	"time"

	"ztaleaks/identity-service/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const otpCollection = "otp_sessions"

type OTPRepository struct {
	coll *mongo.Collection
}

func NewOTPRepository(m *MongoDB) *OTPRepository {
	return &OTPRepository{coll: m.DB.Collection(otpCollection)}
}

func (r *OTPRepository) Create(ctx context.Context, s models.OTPSession) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s.CreatedAt = time.Now()
	_, err := r.coll.InsertOne(ctx, s)
	return err
}

var (
	// ErrSessionNotFound — sessione mai esistita o gia' scaduta dal TTL.
	ErrSessionNotFound = errors.New("session non trovata o scaduta")
	// ErrAttemptsExceeded — sessione esistente ma con tentativi gia' al limite.
	ErrAttemptsExceeded = errors.New("tentativi OTP esauriti")
)

// ConsumeAttempt esegue in una sola operazione atomica sul DB:
//   - filtra per session_token con condizione attempts < maxAttempts
//   - incrementa attempts di 1
//   - restituisce il documento aggiornato
//
// Cosi' un check-then-write da due round-trip separati (race-prone) diventa
// una sola FindOneAndUpdate transazionale dentro Mongo: due richieste di
// verify-otp concorrenti sullo stesso session_token non possono entrambe
// passare il limite.
//
// Distingue inoltre i due casi d'errore (sessione assente vs limite raggiunto)
// con una FindOne di follow-up, utile per il messaggio di risposta.
func (r *OTPRepository) ConsumeAttempt(ctx context.Context, token string, maxAttempts int) (*models.OTPSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var s models.OTPSession
	err := r.coll.FindOneAndUpdate(ctx,
		bson.M{
			"session_token": token,
			"attempts":      bson.M{"$lt": maxAttempts},
		},
		bson.M{"$inc": bson.M{"attempts": 1}},
		opts,
	).Decode(&s)
	if err == nil {
		return &s, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}

	// Nessun documento aggiornato: distinguo "non esiste" da "limite raggiunto".
	var existing models.OTPSession
	if err2 := r.coll.FindOne(ctx, bson.M{"session_token": token}).Decode(&existing); err2 != nil {
		return nil, ErrSessionNotFound
	}
	return nil, ErrAttemptsExceeded
}

func (r *OTPRepository) Delete(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.coll.DeleteOne(ctx, bson.M{"session_token": token})
	return err
}
