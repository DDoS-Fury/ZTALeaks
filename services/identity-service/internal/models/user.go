package models

import (
	"time"
)

// User rappresenta un utente nel SecurityDB (collezione identity_users).
type User struct {
	ID           string `json:"id" bson:"_id,omitempty"`
	Username     string `json:"username" bson:"username"`
	Email        string `json:"email" bson:"email"`
	PasswordHash string `json:"-" bson:"password_hash"` // Argon2id MCF

	Role           string `json:"role" bson:"role"`
	ClearanceLevel string `json:"clearance_level" bson:"clearance_level"`

	// 2FA via OTP email
	TwoFAEnabled bool   `json:"two_fa_enabled" bson:"two_fa_enabled"`
	TwoFASecret  string `json:"-" bson:"two_fa_secret,omitempty"`

	// TPM / Secure Enclave (popolato dopo enrollment WebAuthn)
	HasTPM             bool   `json:"has_tpm" bson:"has_tpm"`
	TPMPublicKey       string `json:"-" bson:"tpm_public_key,omitempty"`
	SecureEnclaveValid bool   `json:"secure_enclave_valid" bson:"secure_enclave_valid"`

	Status        string    `json:"status" bson:"status"`
	CreatedAt     time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" bson:"updated_at"`
	LastLoginInfo LoginInfo `json:"last_login_info" bson:"last_login_info"`
}

type LoginInfo struct {
	Timestamp time.Time `json:"timestamp" bson:"timestamp"`
	IPAddress string    `json:"ip_address" bson:"ip_address"`
	JA3Finger string    `json:"ja3_finger" bson:"ja3_finger"`
}
