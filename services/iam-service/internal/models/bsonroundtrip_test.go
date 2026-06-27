package models

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.mongodb.org/mongo-driver/bson"
)

func TestDeviceCredentialBSONRoundTrip(t *testing.T) {
	orig := DeviceCredential{
		CredentialID: "abc123",
		UserID:       "507f1f77bcf86cd799439011",
		DeviceName:   "tpm-abc123",
		Credential: webauthn.Credential{
			ID:                []byte{1, 2, 3, 4, 5},
			PublicKey:         []byte{0xA5, 0x01, 0x02, 0x03, 0x26, 0xFF},
			AttestationType:   "basic_full",
			AttestationFormat: "packed",
			Transport:         []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
			Flags: webauthn.CredentialFlags{
				UserPresent: true, UserVerified: true, BackupEligible: false, BackupState: false,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    []byte{0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				SignCount: 42,
			},
		},
		CreatedAt:  time.Now().Truncate(time.Millisecond),
		LastUsedAt: time.Now().Truncate(time.Millisecond),
	}

	raw, err := bson.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DeviceCredential
	if err := bson.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !bytes.Equal(got.Credential.ID, orig.Credential.ID) {
		t.Errorf("ID mismatch: %v vs %v", got.Credential.ID, orig.Credential.ID)
	}
	if !bytes.Equal(got.Credential.PublicKey, orig.Credential.PublicKey) {
		t.Errorf("PublicKey mismatch: %v vs %v", got.Credential.PublicKey, orig.Credential.PublicKey)
	}
	if got.Credential.Authenticator.SignCount != 42 {
		t.Errorf("SignCount mismatch: %d", got.Credential.Authenticator.SignCount)
	}
	if !bytes.Equal(got.Credential.Authenticator.AAGUID, orig.Credential.Authenticator.AAGUID) {
		t.Errorf("AAGUID mismatch")
	}
	if !got.Credential.Flags.UserVerified {
		t.Errorf("Flags.UserVerified lost")
	}
	if len(got.Credential.Transport) != 2 || got.Credential.Transport[0] != protocol.USB {
		t.Errorf("Transport mismatch: %v", got.Credential.Transport)
	}
	if got.Credential.AttestationFormat != "packed" {
		t.Errorf("AttestationFormat mismatch: %q", got.Credential.AttestationFormat)
	}
}

func TestWebAuthnChallengeSessionDataRoundTrip(t *testing.T) {
	orig := WebAuthnChallenge{
		SessionID:    "sess-1",
		UserID:       "507f1f77bcf86cd799439011",
		CeremonyType: "authentication",
		SessionData: webauthn.SessionData{
			Challenge:            "Y2hhbGxlbmdl",
			RelyingPartyID:       "localhost",
			UserID:               []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			AllowedCredentialIDs: [][]byte{{9, 8, 7}, {6, 5, 4}},
			Expires:              time.Now().Add(5 * time.Minute).Truncate(time.Millisecond),
			UserVerification:     protocol.VerificationRequired,
		},
		CreatedAt: time.Now().Truncate(time.Millisecond),
	}

	raw, err := bson.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got WebAuthnChallenge
	if err := bson.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.SessionData.Challenge != orig.SessionData.Challenge {
		t.Errorf("Challenge mismatch: %q", got.SessionData.Challenge)
	}
	if !bytes.Equal(got.SessionData.UserID, orig.SessionData.UserID) {
		t.Errorf("SessionData.UserID mismatch")
	}
	if len(got.SessionData.AllowedCredentialIDs) != 2 || !bytes.Equal(got.SessionData.AllowedCredentialIDs[0], []byte{9, 8, 7}) {
		t.Errorf("AllowedCredentialIDs mismatch: %v", got.SessionData.AllowedCredentialIDs)
	}
	if got.SessionData.UserVerification != protocol.VerificationRequired {
		t.Errorf("UserVerification mismatch: %q", got.SessionData.UserVerification)
	}
}
