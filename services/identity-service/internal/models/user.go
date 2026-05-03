package models

import (
	"time"
)

// User rappresenta un utente nel SecurityDB
type User struct {
	ID           string `json:"id" bson:"_id,omitempty"`
	Username     string `json:"username" bson:"username"`
	PasswordHash string `json:"-" bson:"password_hash"` // Implementeremo Argon2id o simili
	Role         string `json:"role" bson:"role"`

	// Predisposizione 2FA
	TwoFAEnabled bool   `json:"two_fa_enabled" bson:"two_fa_enabled"`
	TwoFASecret  string `json:"-" bson:"two_fa_secret,omitempty"`

	// Predisposizione TPM e Secure Enclave
	HasTPM             bool   `json:"has_tpm" bson:"has_tpm"`
	TPMPublicKey       string `json:"-" bson:"tpm_public_key,omitempty"`
	SecureEnclaveValid bool   `json:"secure_enclave_valid" bson:"secure_enclave_valid"`

	// Session e Audit
	CreatedAt     time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" bson:"updated_at"`
	LastLoginInfo LoginInfo `json:"last_login_info" bson:"last_login_info"`
}

type LoginInfo struct {
	Timestamp time.Time `json:"timestamp" bson:"timestamp"`
	IPAddress string    `json:"ip_address" bson:"ip_address"`
	JA3Finger string    `json:"ja3_finger" bson:"ja3_finger"`
}
