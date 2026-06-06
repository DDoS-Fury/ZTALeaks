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
// 1. Creiamo un ruolo personalizzato che permette l'accesso SOLO alle collezioni 'personnel' e 'reactor_parameters'
db.createRole({
    role: "adminRole",
    privileges: [
        {
            resource: { db: "nuclear_plant_db", collection: "personnel" },
            actions: ["find", "insert", "update", "remove"]
        },
        {
            resource: { db: "nuclear_plant_db", collection: "reactor_parameters" },
            actions: ["find", "insert", "update", "remove"]
        },
        {
            resource: { db: "nuclear_plant_db", collection: "nuclear_materials" },
            actions: ["find", "insert", "update", "remove"]
        },
        {
            resource: { db: "nuclear_plant_db", collection: "documents" },
            actions: ["find", "insert", "update", "remove"]
        }
    ],
    roles: []
});
db.createRole({
    role: "managerRole",
    privileges: [
        {
            resource: { db: "nuclear_plant_db", collection: "personnel" },
            actions: ["find", "insert", "update", "remove"]
        },
        {
            resource: { db: "nuclear_plant_db", collection: "nuclear_materials" },
            actions: ["find", "insert", "update", "remove"]
        },
        {
            resource: { db: "nuclear_plant_db", collection: "documents" },
            actions: ["find", "insert", "update", "remove"]
        }
    ],
    roles: []
});
db.createRole({
    role: "operatorRole",
    privileges: [
        {
            resource: { db: "nuclear_plant_db", collection: "personnel" },
            actions: ["find", "insert", "update", "remove"]
        }
    ],
    roles: []
});
// 2. Assegniamo a ciascun client il proprio ruolo least-privilege.
//    Le password devono combaciare con i default di config.go (business-logic):
//    admin_client/adminPass2026!, manager_client/managerPass2026!, operator_client/operatorPass2026!
db.createUser({
    user: "admin_client",
    pwd: "adminPass2026!",
    roles: [{ role: "adminRole", db: "nuclear_plant_db" }]
});
db.createUser({
    user: "manager_client",
    pwd: "managerPass2026!",
    roles: [{ role: "managerRole", db: "nuclear_plant_db" }]
});
db.createUser({
    user: "operator_client",
    pwd: "operatorPass2026!",
    roles: [{ role: "operatorRole", db: "nuclear_plant_db" }]
});



// ---------------------------------------------------------------------------
// Seeder service account: popola le collezioni di business al primo avvio.
// Necessita readWrite sull'intero DB (usato da tools/seeder via SEED_MONGO_URI).
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