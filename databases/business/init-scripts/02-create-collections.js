db = db.getSiblingDB('nuclear_plant_db');

var classificationLevels = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "TOP_SECRET"];

var roles = [
    "operator",
    "maintenance_technician",
    "radiation_protection_officer",
    "security_officer",
    "plant_manager",
    "inspector"
];

// ==================== PERSONNEL ====================
db.createCollection("personnel", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "employee_id", "first_name", "last_name",
                "role", "clearance_level", "classification_level", "status"
            ],
            properties: {
                employee_id: {
                    bsonType: "string",
                    pattern: "^NP-\\d{4}-\\d{4}$"
                },
                classification_level: { enum: classificationLevels },
                role: { enum: roles },
                clearance_level: { enum: classificationLevels },
                status: { enum: ["active", "inactive", "suspended", "terminated"] }
            }
        }
    }
});
db.personnel.createIndex({ "employee_id": 1 }, { unique: true });
db.personnel.createIndex({ "role": 1, "department": 1 });
db.personnel.createIndex({ "badge_id": 1 }, { unique: true });

// ==================== ACCESS BADGES ====================
db.createCollection("access_badges", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["badge_id", "employee_id", "classification_level", "status"],
            properties: {
                badge_id: {
                    bsonType: "string",
                    pattern: "^BDG-"
                },
                classification_level: { enum: classificationLevels },
                type: { enum: ["permanent", "temporary", "visitor", "contractor"] },
                status: { enum: ["active", "inactive", "revoked", "expired"] }
            }
        }
    }
});
db.access_badges.createIndex({ "badge_id": 1 }, { unique: true });
db.access_badges.createIndex({ "employee_id": 1 });

// ==================== ZONES ====================
db.createCollection("zones", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["zone_id", "name", "type", "classification_level"],
            properties: {
                zone_id: {
                    bsonType: "string",
                    pattern: "^ZONE-"
                },
                classification_level: { enum: classificationLevels },
                type: { enum: ["public", "controlled", "restricted", "exclusion"] }
            }
        }
    }
});
db.zones.createIndex({ "zone_id": 1 }, { unique: true });

// ==================== REACTOR PARAMETERS ====================
db.createCollection("reactor_parameters", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["timestamp", "reactor_id", "classification_level"],
            properties: {
                classification_level: { enum: classificationLevels },
                reactor_status: {
                    enum: [
                        "shutdown", "startup", "power_operation",
                        "hot_standby", "emergency_shutdown"
                    ]
                }
            }
        }
    }
});
db.reactor_parameters.createIndex({ "timestamp": -1, "reactor_id": 1 });

// ==================== MAINTENANCE ORDERS ====================
db.createCollection("maintenance_orders", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["order_id", "title", "classification_level", "status"],
            properties: {
                order_id: {
                    bsonType: "string",
                    pattern: "^MO-"
                },
                classification_level: { enum: classificationLevels },
                type: { enum: ["preventive", "corrective", "predictive"] },
                priority: { enum: ["low", "medium", "high", "critical"] },
                status: {
                    enum: [
                        "created", "approved", "scheduled",
                        "in_progress", "completed", "cancelled"
                    ]
                }
            }
        }
    }
});
db.maintenance_orders.createIndex({ "order_id": 1 }, { unique: true });
db.maintenance_orders.createIndex({ "status": 1, "priority": 1 });
db.maintenance_orders.createIndex({ "assigned_to": 1 });

// ==================== DOCUMENTS ====================
db.createCollection("documents", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["document_id", "title", "classification_level", "status"],
            properties: {
                document_id: {
                    bsonType: "string",
                    pattern: "^DOC-"
                },
                classification_level: { enum: classificationLevels },
                type: { enum: ["procedure", "manual", "drawing", "report", "analysis"] },
                category: {
                    enum: [
                        "operational", "emergency", "maintenance",
                        "safety", "administrative"
                    ]
                },
                status: {
                    enum: ["draft", "under_review", "approved", "superseded", "archived"]
                }
            }
        }
    }
});
db.documents.createIndex({ "document_id": 1 }, { unique: true });
db.documents.createIndex({ "classification_level": 1, "type": 1 });
db.documents.createIndex({ "keywords": 1 });

// ==================== NUCLEAR MATERIALS ====================
db.createCollection("nuclear_materials", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["material_id", "type", "classification_level", "status"],
            properties: {
                material_id: {
                    bsonType: "string",
                    pattern: "^NM-"
                },
                classification_level: { enum: classificationLevels },
                type: { enum: ["fuel_assembly", "spent_fuel", "waste", "source"] },
                status: {
                    enum: [
                        "in_storage", "in_reactor", "spent_pool",
                        "dry_cask", "transferred"
                    ]
                }
            }
        }
    }
});
db.nuclear_materials.createIndex({ "material_id": 1 }, { unique: true });
db.nuclear_materials.createIndex({ "status": 1, "location.zone_id": 1 });

print("✅ All 7 collections, validators and indexes created");