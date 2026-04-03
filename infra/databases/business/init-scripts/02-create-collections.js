// =============================================================================
// MongoDB Initialization Script - Collection Creation with Schema Validation
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This script creates all 7 business collections with:
//   - JSON Schema validators enforcing data integrity
//   - Required field constraints
//   - Enumeration constraints for controlled vocabularies
//   - Pattern constraints for identifier formats
//   - Indexes for query performance and uniqueness enforcement
//
// The schema design supports Zero Trust policy evaluation by ensuring that
// every document carries classification metadata, ownership information,
// and zone association data that the PDP can use for access decisions.
//
// Execution order: 02 (runs after user creation)
// =============================================================================

db = db.getSiblingDB('nuclear_plant_db');

// ---------------------------------------------------------------------------
// Shared enumerations used across multiple collection validators
// ---------------------------------------------------------------------------
var classificationLevels = [
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "SECRET",
    "TOP_SECRET"
];

var roles = [
    "operator",
    "maintenance_technician",
    "radiation_protection_officer",
    "security_officer",
    "plant_manager",
    "inspector"
];

// ===========================================================================
// COLLECTION: personnel
// ===========================================================================
// Stores employee records including role, clearance level, qualifications,
// and zone assignments. This collection is central to identity-based access
// control in the ZTA model. The clearance_level field determines the maximum
// classification level a user is authorized to access.
// ===========================================================================
db.createCollection("personnel", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "employee_id",
                "first_name",
                "last_name",
                "role",
                "department",
                "clearance_level",
                "classification_level",
                "status",
                "badge_id"
            ],
            properties: {
                employee_id: {
                    bsonType: "string",
                    pattern: "^NP-\\d{4}-\\d{4}$",
                    description: "Unique employee identifier in format NP-YYYY-NNNN"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level of this personnel record"
                },
                first_name: {
                    bsonType: "string",
                    description: "Employee first name"
                },
                last_name: {
                    bsonType: "string",
                    description: "Employee last name"
                },
                role: {
                    enum: roles,
                    description: "Operational role within the plant"
                },
                department: {
                    bsonType: "string",
                    description: "Department of assignment"
                },
                clearance_level: {
                    enum: classificationLevels,
                    description: "Maximum classification level accessible by this employee"
                },
                qualifications: {
                    bsonType: "array",
                    description: "Professional certifications and training records"
                },
                assigned_zones: {
                    bsonType: "array",
                    description: "List of zone identifiers where the employee operates"
                },
                badge_id: {
                    bsonType: "string",
                    pattern: "^BDG-",
                    description: "Associated physical access badge identifier"
                },
                status: {
                    enum: ["active", "inactive", "suspended", "terminated"],
                    description: "Current employment status"
                },
                hire_date: {
                    bsonType: "date",
                    description: "Date of hire"
                },
                last_medical_check: {
                    bsonType: "date",
                    description: "Date of last medical examination"
                },
                ztna_metadata: {
                    bsonType: "object",
                    description: "Zero Trust specific metadata for policy evaluation",
                    properties: {
                        trust_score: {
                            bsonType: "double",
                            description: "Computed trust score based on behavior analytics (0.0-1.0)"
                        },
                        last_trust_evaluation: {
                            bsonType: "date",
                            description: "Timestamp of the last trust score computation"
                        },
                        risk_flags: {
                            bsonType: "array",
                            description: "Active risk indicators for this identity"
                        },
                        mfa_enrolled: {
                            bsonType: "bool",
                            description: "Whether multi-factor authentication is configured"
                        },
                        last_successful_auth: {
                            bsonType: "date",
                            description: "Timestamp of last successful authentication"
                        },
                        failed_auth_count: {
                            bsonType: "int",
                            description: "Count of failed authentication attempts in current window"
                        },
                        access_review_date: {
                            bsonType: "date",
                            description: "Date of last periodic access review"
                        }
                    }
                }
            }
        }
    }
});

db.personnel.createIndex({ "employee_id": 1 }, { unique: true });
db.personnel.createIndex({ "role": 1, "department": 1 });
db.personnel.createIndex({ "badge_id": 1 }, { unique: true });
db.personnel.createIndex({ "clearance_level": 1 });
db.personnel.createIndex({ "status": 1 });
db.personnel.createIndex({ "ztna_metadata.trust_score": 1 });

// ===========================================================================
// COLLECTION: access_badges
// ===========================================================================
// Models physical access badges and their usage logs. Each badge is linked
// to an employee and defines authorized physical zones. The access_log
// array provides an audit trail of physical movements that can be correlated
// with digital access patterns for anomaly detection.
// ===========================================================================
db.createCollection("access_badges", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "badge_id",
                "employee_id",
                "classification_level",
                "type",
                "status"
            ],
            properties: {
                badge_id: {
                    bsonType: "string",
                    pattern: "^BDG-",
                    description: "Unique badge identifier"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level of this badge record"
                },
                employee_id: {
                    bsonType: "string",
                    pattern: "^NP-",
                    description: "Associated employee identifier"
                },
                type: {
                    enum: ["permanent", "temporary", "visitor", "contractor"],
                    description: "Badge type determining access scope and duration"
                },
                authorized_zones: {
                    bsonType: "array",
                    description: "Zones accessible with this badge"
                },
                issue_date: {
                    bsonType: "date",
                    description: "Date of badge issuance"
                },
                expiry_date: {
                    bsonType: "date",
                    description: "Date of badge expiration"
                },
                status: {
                    enum: ["active", "inactive", "revoked", "expired"],
                    description: "Current badge status"
                },
                access_log: {
                    bsonType: "array",
                    description: "Chronological log of physical access events"
                }
            }
        }
    }
});

db.access_badges.createIndex({ "badge_id": 1 }, { unique: true });
db.access_badges.createIndex({ "employee_id": 1 });
db.access_badges.createIndex({ "status": 1, "type": 1 });
db.access_badges.createIndex({ "expiry_date": 1 });

// ===========================================================================
// COLLECTION: zones
// ===========================================================================
// Represents physical areas of the nuclear plant with their security
// requirements. Each zone specifies required clearance, qualifications,
// and PPE. This data is consumed by the PDP to evaluate whether a subject
// meets all prerequisites for zone access.
// ===========================================================================
db.createCollection("zones", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "zone_id",
                "name",
                "code",
                "type",
                "classification_level",
                "required_clearance",
                "status"
            ],
            properties: {
                zone_id: {
                    bsonType: "string",
                    pattern: "^ZONE-",
                    description: "Unique zone identifier"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level of zone information"
                },
                name: {
                    bsonType: "string",
                    description: "Human-readable zone name"
                },
                code: {
                    bsonType: "string",
                    description: "Machine-readable zone code"
                },
                type: {
                    enum: ["public", "controlled", "restricted", "exclusion"],
                    description: "Zone access category"
                },
                radiation_zone: {
                    bsonType: "bool",
                    description: "Whether radiological hazard is present"
                },
                required_clearance: {
                    enum: classificationLevels,
                    description: "Minimum clearance level required for entry"
                },
                required_qualifications: {
                    bsonType: "array",
                    description: "Mandatory qualifications for zone access"
                },
                required_ppe: {
                    bsonType: "array",
                    description: "Required personal protective equipment"
                },
                max_occupancy: {
                    bsonType: "int",
                    description: "Maximum simultaneous occupants"
                },
                status: {
                    bsonType: "string",
                    description: "Current operational status of the zone"
                },
                ztna_policy: {
                    bsonType: "object",
                    description: "Zone-specific Zero Trust policy parameters",
                    properties: {
                        min_trust_score: {
                            bsonType: "double",
                            description: "Minimum trust score required for access (0.0-1.0)"
                        },
                        require_mfa: {
                            bsonType: "bool",
                            description: "Whether MFA is mandatory for this zone"
                        },
                        max_session_duration_minutes: {
                            bsonType: "int",
                            description: "Maximum allowed session duration before re-authentication"
                        },
                        allowed_device_types: {
                            bsonType: "array",
                            description: "Device types permitted to access zone resources"
                        },
                        allowed_networks: {
                            bsonType: "array",
                            description: "Network segments from which access is permitted"
                        },
                        continuous_monitoring: {
                            bsonType: "bool",
                            description: "Whether continuous behavior monitoring is enabled"
                        }
                    }
                }
            }
        }
    }
});

db.zones.createIndex({ "zone_id": 1 }, { unique: true });
db.zones.createIndex({ "type": 1, "classification_level": 1 });
db.zones.createIndex({ "required_clearance": 1 });

// ===========================================================================
// COLLECTION: reactor_parameters
// ===========================================================================
// Contains time-series operational data from the reactor instrumentation.
// This is among the most sensitive data in the plant. Access is restricted
// to operators with SECRET clearance or higher. Each reading includes
// provenance information (recorded_by, shift_id) for accountability.
// ===========================================================================
db.createCollection("reactor_parameters", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "timestamp",
                "reactor_id",
                "classification_level",
                "reactor_status",
                "recorded_by",
                "shift_id"
            ],
            properties: {
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level - typically SECRET for reactor data"
                },
                timestamp: {
                    bsonType: "date",
                    description: "Measurement timestamp"
                },
                reactor_id: {
                    bsonType: "string",
                    description: "Reactor unit identifier"
                },
                reactor_status: {
                    enum: [
                        "shutdown",
                        "startup",
                        "power_operation",
                        "hot_standby",
                        "emergency_shutdown"
                    ],
                    description: "Current reactor operating mode"
                },
                recorded_by: {
                    bsonType: "string",
                    pattern: "^NP-",
                    description: "Employee who recorded the measurement"
                },
                shift_id: {
                    bsonType: "string",
                    description: "Shift identifier for operational context"
                },
                scram_status: {
                    bsonType: "bool",
                    description: "Whether emergency shutdown (SCRAM) is active"
                },
                data_integrity_hash: {
                    bsonType: "string",
                    description: "SHA-256 hash of critical parameter values for tamper detection"
                }
            }
        }
    }
});

db.reactor_parameters.createIndex({ "timestamp": -1, "reactor_id": 1 });
db.reactor_parameters.createIndex({ "reactor_status": 1 });
db.reactor_parameters.createIndex({ "recorded_by": 1 });
db.reactor_parameters.createIndex({ "shift_id": 1 });

// ===========================================================================
// COLLECTION: maintenance_orders
// ===========================================================================
// Models work orders for maintenance activities. Supports the full lifecycle
// from creation through approval, scheduling, execution, and completion.
// The approval_chain provides an auditable record of authorization decisions.
// ===========================================================================
db.createCollection("maintenance_orders", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "order_id",
                "title",
                "type",
                "priority",
                "classification_level",
                "status",
                "safety_classification",
                "requested_by"
            ],
            properties: {
                order_id: {
                    bsonType: "string",
                    pattern: "^MO-",
                    description: "Unique maintenance order identifier"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level of this work order"
                },
                title: {
                    bsonType: "string",
                    description: "Descriptive title of the maintenance activity"
                },
                type: {
                    enum: ["preventive", "corrective", "predictive"],
                    description: "Category of maintenance activity"
                },
                priority: {
                    enum: ["low", "medium", "high", "critical"],
                    description: "Urgency level of the work order"
                },
                safety_classification: {
                    enum: ["safety_related", "non_safety", "augmented_quality"],
                    description: "Nuclear safety classification of the affected system"
                },
                status: {
                    enum: [
                        "created",
                        "approved",
                        "scheduled",
                        "in_progress",
                        "completed",
                        "cancelled"
                    ],
                    description: "Current lifecycle status of the work order"
                },
                requested_by: {
                    bsonType: "string",
                    pattern: "^NP-",
                    description: "Employee who created the work order"
                },
                zone_id: {
                    bsonType: "string",
                    pattern: "^ZONE-",
                    description: "Zone where the maintenance will be performed"
                }
            }
        }
    }
});

db.maintenance_orders.createIndex({ "order_id": 1 }, { unique: true });
db.maintenance_orders.createIndex({ "status": 1, "priority": 1 });
db.maintenance_orders.createIndex({ "assigned_to": 1 });
db.maintenance_orders.createIndex({ "zone_id": 1 });
db.maintenance_orders.createIndex({ "requested_by": 1 });
db.maintenance_orders.createIndex({ "safety_classification": 1 });

// ===========================================================================
// COLLECTION: documents
// ===========================================================================
// Stores metadata for technical documents, procedures, and reports.
// The applicable_roles field enables role-based document access control,
// while classification_level determines the minimum clearance required.
// ===========================================================================
db.createCollection("documents", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "document_id",
                "title",
                "type",
                "category",
                "classification_level",
                "status"
            ],
            properties: {
                document_id: {
                    bsonType: "string",
                    pattern: "^DOC-",
                    description: "Unique document identifier"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level of this document"
                },
                title: {
                    bsonType: "string",
                    description: "Document title"
                },
                type: {
                    enum: ["procedure", "manual", "drawing", "report", "analysis"],
                    description: "Document type category"
                },
                category: {
                    enum: [
                        "operational",
                        "emergency",
                        "maintenance",
                        "safety",
                        "administrative"
                    ],
                    description: "Functional category of the document"
                },
                status: {
                    enum: [
                        "draft",
                        "under_review",
                        "approved",
                        "superseded",
                        "archived"
                    ],
                    description: "Current document lifecycle status"
                },
                applicable_roles: {
                    bsonType: "array",
                    description: "Roles authorized to access this document"
                },
                applicable_zones: {
                    bsonType: "array",
                    description: "Zones to which this document applies"
                }
            }
        }
    }
});

db.documents.createIndex({ "document_id": 1 }, { unique: true });
db.documents.createIndex({ "classification_level": 1, "type": 1 });
db.documents.createIndex({ "category": 1, "status": 1 });
db.documents.createIndex({ "applicable_roles": 1 });
db.documents.createIndex({ "keywords": 1 });

// ===========================================================================
// COLLECTION: nuclear_materials
// ===========================================================================
// Inventories nuclear and radioactive materials. This is the most critical
// collection in terms of security classification. Access requires TOP_SECRET
// clearance. IAEA safeguards data and accountability records support
// international non-proliferation obligations.
// ===========================================================================
db.createCollection("nuclear_materials", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: [
                "material_id",
                "type",
                "classification_level",
                "status",
                "serial_number",
                "location"
            ],
            properties: {
                material_id: {
                    bsonType: "string",
                    pattern: "^NM-",
                    description: "Unique material identifier"
                },
                classification_level: {
                    enum: classificationLevels,
                    description: "Sensitivity level - typically SECRET or TOP_SECRET"
                },
                type: {
                    enum: ["fuel_assembly", "spent_fuel", "waste", "source"],
                    description: "Category of nuclear material"
                },
                status: {
                    enum: [
                        "in_storage",
                        "in_reactor",
                        "spent_pool",
                        "dry_cask",
                        "transferred"
                    ],
                    description: "Current disposition of the material"
                },
                serial_number: {
                    bsonType: "string",
                    description: "Manufacturer serial number"
                },
                location: {
                    bsonType: "object",
                    required: ["zone_id", "position"],
                    properties: {
                        zone_id: {
                            bsonType: "string",
                            pattern: "^ZONE-",
                            description: "Zone where the material is located"
                        },
                        position: {
                            bsonType: "string",
                            description: "Specific position within the zone"
                        }
                    },
                    description: "Physical location of the material"
                }
            }
        }
    }
});

db.nuclear_materials.createIndex({ "material_id": 1 }, { unique: true });
db.nuclear_materials.createIndex({ "status": 1, "location.zone_id": 1 });
db.nuclear_materials.createIndex({ "type": 1, "status": 1 });
db.nuclear_materials.createIndex({ "serial_number": 1 }, { unique: true });
db.nuclear_materials.createIndex({ "iaea_safeguards.next_inspection": 1 });

print("[INIT] All 7 collections created with schema validators and indexes");