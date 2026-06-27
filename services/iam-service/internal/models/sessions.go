package models

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

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
//
// CredentialID (base64url del raw credential id) e UserID restano top-level
// perché la security-orchestrator interroga il documento solo su quella coppia
// (vedi internal/tpm/lookup.go). La verità crittografica vive interamente nel
// campo Credential (webauthn.Credential): chiave pubblica COSE, AAGUID,
// sign-count, flags e attestation provengono dall'attestation verificata, non
// più da input arbitrario del client.
type DeviceCredential struct {
	CredentialID string              `bson:"credential_id" json:"credential_id"`
	UserID       string              `bson:"user_id" json:"user_id"`
	DeviceName   string              `bson:"device_name" json:"device_name"`
	Credential   webauthn.Credential `bson:"credential" json:"-"`
	CreatedAt    time.Time           `bson:"created_at" json:"created_at"`
	LastUsedAt   time.Time           `bson:"last_used_at" json:"last_used_at"`
}

// WebAuthnChallenge è uno stato temporaneo della cerimonia (registration o
// authentication). Conserva la webauthn.SessionData prodotta da go-webauthn in
// BeginRegistration/BeginLogin, da ridare a FinishRegistration/FinishLogin.
// SessionID è il token opaco che lega /begin → /finish. Fake=true marca una
// cerimonia di login fittizia generata per un utente sconosciuto/senza device
// (anti user-enumeration): il finish la rifiuta come una firma errata.
// TTL Mongo a 5 min su created_at.
type WebAuthnChallenge struct {
	SessionID    string               `bson:"session_id"`
	UserID       string               `bson:"user_id"`
	CeremonyType string               `bson:"ceremony_type"` // "registration" | "authentication"
	Fake         bool                 `bson:"fake,omitempty"`
	SessionData  webauthn.SessionData `bson:"session_data"`
	CreatedAt    time.Time            `bson:"created_at"`
}

// JWTBlocklistEntry è un JTI revocato. TTL Mongo a 25h su revoked_at.
type JWTBlocklistEntry struct {
	JTI       string    `bson:"jti"`
	UserID    string    `bson:"user_id"`
	RevokedAt time.Time `bson:"revoked_at"`
	Reason    string    `bson:"reason"`
}
