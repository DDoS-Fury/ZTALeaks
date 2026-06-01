package db

// Repositories aggrega tutti i repository dell'identity-service in un unico
// bundle iniettabile. Stesso pattern di business-logic/internal/db/repositories.go:
// il main wira la struct, gli handler ricevono solo cio' che gli serve.
type Repositories struct {
	Users      *UserRepository
	OTP        *OTPRepository
	Devices    *DeviceRepository
	Challenges *ChallengeRepository
}

// InitRepositories costruisce tutti i repository sopra la connessione Mongo.
func InitRepositories(m *MongoDB) *Repositories {
	return &Repositories{
		Users:      NewUserRepository(m),
		OTP:        NewOTPRepository(m),
		Devices:    NewDeviceRepository(m),
		Challenges: NewChallengeRepository(m),
	}
}
