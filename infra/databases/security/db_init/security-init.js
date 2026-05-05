// =============================================================================
// MongoDB Initialization Script - Security Database
// =============================================================================
db = db.getSiblingDB('securitydb');

// Crea esplicitamente la collezione in modo che il database "securitydb" venga creato
db.createCollection("identity_users");

print("[INIT] Security database initialized.");
