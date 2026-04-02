// =============================================================================
// MongoDB Initialization Script - User Creation
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This script creates service accounts with role-based access following the
// principle of least privilege. Each component of the ZTA architecture
// receives a dedicated user with only the permissions it requires.
//
// Execution order: 01 (runs before collection creation)
// =============================================================================

db = db.getSiblingDB('nuclear_plant_db');

// ---------------------------------------------------------------------------
// Service account for the PEP (Envoy proxy).
// Requires readWrite to forward authorized CRUD operations from clients.
// In a production environment, this would be further restricted using
// collection-level privileges via custom roles.
// ---------------------------------------------------------------------------
db.createUser({
    user: "envoy_service",
    pwd: "envoyServicePass2025!",
    roles: [{ role: "readWrite", db: "nuclear_plant_db" }]
});

// ---------------------------------------------------------------------------
// Service account for the seed process.
// Requires readWrite to perform the initial data population.
// This account should be disabled or removed after initial deployment.
// ---------------------------------------------------------------------------
db.createUser({
    user: "seed_service",
    pwd: "seedServicePass2025!",
    roles: [{ role: "readWrite", db: "nuclear_plant_db" }]
});

// ---------------------------------------------------------------------------
// Read-only service account for the observability stack (Splunk).
// Restricted to read operations only, ensuring the monitoring layer
// cannot modify business data.
// ---------------------------------------------------------------------------
db.createUser({
    user: "splunk_reader",
    pwd: "splunkReaderPass2025!",
    roles: [{ role: "read", db: "nuclear_plant_db" }]
});

// ---------------------------------------------------------------------------
// Read-only service account for the Policy Decision Point (OPA/PDP).
// Used to query resource metadata (classification levels, zone requirements)
// for policy evaluation without any write capability.
// ---------------------------------------------------------------------------
db.createUser({
    user: "pdp_reader",
    pwd: "pdpReaderPass2025!",
    roles: [{ role: "read", db: "nuclear_plant_db" }]
});

print("[INIT] Database users created successfully with least-privilege roles");