// =============================================================================
// MongoDB Initialization Script - Security Database
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Creates collections + indexes for the security database. User documents are
// seeded by the identity-service at startup (Argon2id hashing happens in Go).
//
// Collections:
//   identity_users         employee credentials, roles, clearance, TPM flags
//   otp_sessions           ephemeral OTP state, TTL 5 min
//   jwt_blocklist          revoked JWT IDs, TTL 25 hours
//   device_fingerprints    WebAuthn/FIDO2 credentials (TPM enrollments)
//   webauthn_challenges    in-flight ceremony state, TTL 5 min
//   auth_events            immutable audit log of authentication events
//   rate_limits            tracks failed attempts for rate limiting
// =============================================================================

db = db.getSiblingDB('securitydb');

// ---------------------------------------------------------------------------
// identity_users — credentials, role, clearance, TPM enrollment flags
// ---------------------------------------------------------------------------
db.createCollection("identity_users");
db.identity_users.createIndex({ "username": 1 }, { unique: true });
db.identity_users.createIndex({ "email": 1 }, { unique: true, sparse: true });

// ---------------------------------------------------------------------------
// otp_sessions — temporary OTP verification state (TTL 5 min)
// ---------------------------------------------------------------------------
db.createCollection("otp_sessions");
db.otp_sessions.createIndex({ "session_token": 1 }, { unique: true });
db.otp_sessions.createIndex({ "created_at": 1 }, { expireAfterSeconds: 300 });

// ---------------------------------------------------------------------------
// jwt_blocklist — revoked JWT IDs (TTL 25h, longer than refresh token TTL)
// ---------------------------------------------------------------------------
db.createCollection("jwt_blocklist");
db.jwt_blocklist.createIndex({ "jti": 1 }, { unique: true });
db.jwt_blocklist.createIndex({ "revoked_at": 1 }, { expireAfterSeconds: 90000 });

// ---------------------------------------------------------------------------
// device_fingerprints — WebAuthn/FIDO2 credentials (TPM bindings)
// ---------------------------------------------------------------------------
db.createCollection("device_fingerprints");
db.device_fingerprints.createIndex({ "credential_id": 1 }, { unique: true });
db.device_fingerprints.createIndex({ "user_id": 1 });

// ---------------------------------------------------------------------------
// webauthn_challenges — in-flight ceremony state (TTL 5 min)
// ---------------------------------------------------------------------------
db.createCollection("webauthn_challenges");
db.webauthn_challenges.createIndex({ "session_id": 1 }, { unique: true });
db.webauthn_challenges.createIndex({ "created_at": 1 }, { expireAfterSeconds: 300 });

// ---------------------------------------------------------------------------
// auth_events — immutable audit log
// ---------------------------------------------------------------------------
db.createCollection("auth_events");
db.auth_events.createIndex({ "timestamp": -1 });
db.auth_events.createIndex({ "user_id": 1, "timestamp": -1 });
db.auth_events.createIndex({ "event_type": 1 });

// ---------------------------------------------------------------------------
// rate_limits — tracks failed attempts for rate limiting
// ---------------------------------------------------------------------------
db.createCollection("rate_limits");
// MongoDB automatically creates a unique index on _id (which is used for the IP)
db.rate_limits.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

print("[INIT] Security database initialized: 7 collections, indexes ready.");
