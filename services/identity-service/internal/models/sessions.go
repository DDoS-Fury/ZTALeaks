package models

import "time"

// OTPSession traccia un OTP in attesa di verifica. TTL gestito via index Mongo
// su created_at (5 min). Il campo OTPHash è un Argon2id MCF, mai plaintext.
type OTPSession struct {
	SessionToken string    `bson:"session_token"`
	UserID       string    `bson:"user_id"`
	OTPHash      string    `bson:"otp_hash"`
	Attempts     int       `bson:"attempts"`
	CreatedAt    time.Time `bson:"created_at"`
}

// DeviceCredential è una credenziale WebAuthn/FIDO2 registrata da un utente.
// Vive in security_db.device_fingerprints; la security-orchestrator la usa
// in lookup read-only per dire a OPA "tpm_verified=true" sul tier admission.
type DeviceCredential struct {
	CredentialID    string    `bson:"credential_id" json:"credential_id"`
	UserID          string    `bson:"user_id" json:"user_id"`
	PublicKey       []byte    `bson:"public_key" json:"-"`
	AAGUID          string    `bson:"aaguid" json:"aaguid"`
	SignCount       uint32    `bson:"sign_count" json:"sign_count"`
	DeviceName      string    `bson:"device_name" json:"device_name"`
	AttestationType string    `bson:"attestation_type" json:"attestation_type"`
	CreatedAt       time.Time `bson:"created_at" json:"created_at"`
	LastUsedAt      time.Time `bson:"last_used_at" json:"last_used_at"`
}

// WebAuthnChallenge è uno stato temporaneo della cerimonia (registration o
// authentication). TTL Mongo a 5 min su created_at.
type WebAuthnChallenge struct {
	SessionID    string    `bson:"session_id"`
	Challenge    string    `bson:"challenge"`
	UserID       string    `bson:"user_id"`
	CeremonyType string    `bson:"ceremony_type"` // "registration" | "authentication"
	CreatedAt    time.Time `bson:"created_at"`
}

// JWTBlocklistEntry è un JTI revocato. TTL Mongo a 25h su revoked_at.
type JWTBlocklistEntry struct {
	JTI       string    `bson:"jti"`
	UserID    string    `bson:"user_id"`
	RevokedAt time.Time `bson:"revoked_at"`
	Reason    string    `bson:"reason"`
}
