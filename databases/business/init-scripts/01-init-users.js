db = db.getSiblingDB('nuclear_plant_db');

// Utente per Envoy (PEP) - readWrite per inoltrare operazioni CRUD
db.createUser({
    user: "envoy_service",
    pwd: "envoyServicePass2025!",
    roles: [{ role: "readWrite", db: "nuclear_plant_db" }]
});

// Utente per il seed
db.createUser({
    user: "seed_service",
    pwd: "seedServicePass2025!",
    roles: [{ role: "readWrite", db: "nuclear_plant_db" }]
});

// Utente read-only per Splunk
db.createUser({
    user: "splunk_reader",
    pwd: "splunkReaderPass2025!",
    roles: [{ role: "read", db: "nuclear_plant_db" }]
});

print("✅ Database users created");