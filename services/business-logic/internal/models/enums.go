// =============================================================================
// Business Database Models - Enumeration Constants
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This file defines all enumeration constants used across the seed data.
// Using typed constants avoids hardcoded strings scattered throughout the
// codebase, reduces the risk of typos, and makes schema changes traceable.
//
// The constants are organized by domain concept and match the enumeration
// values defined in the MongoDB JSON Schema validators.
// =============================================================================

package models

// ---------------------------------------------------------------------------
// Classification levels - aligned with the data sensitivity model.
// These values determine access control decisions in the ZTA policy engine.
// The hierarchy is: PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET
// ---------------------------------------------------------------------------

const (
	ClassPublic       = "PUBLIC"
	ClassInternal     = "INTERNAL"
	ClassConfidential = "CONFIDENTIAL"
	ClassSecret       = "SECRET"
	ClassTopSecret    = "TOP_SECRET"
)

// ---------------------------------------------------------------------------
// Operational roles - represent functional positions within the plant.
// Each role maps to a set of permitted operations and accessible resources
// in the Zero Trust policy definitions.
// ---------------------------------------------------------------------------

const (
	RoleOperator      = "operator"
	RoleMaintTech     = "maintenance_technician"
	RoleRadProtection = "radiation_protection_officer"
	RoleSecurity      = "security_officer"
	RolePlantManager  = "plant_manager"
	RoleInspector     = "inspector"
)

// ---------------------------------------------------------------------------
// Zone types - categorize areas by access restriction level.
// The PDP uses zone type in conjunction with clearance level and
// qualifications to evaluate physical access requests.
// ---------------------------------------------------------------------------

const (
	ZonePublic     = "public"
	ZoneControlled = "controlled"
	ZoneRestricted = "restricted"
	ZoneExclusion  = "exclusion"
)

// ---------------------------------------------------------------------------
// Reactor operational states
// ---------------------------------------------------------------------------

const (
	ReactorShutdown          = "shutdown"
	ReactorStartup           = "startup"
	ReactorPowerOperation    = "power_operation"
	ReactorHotStandby        = "hot_standby"
	ReactorEmergencyShutdown = "emergency_shutdown"
)

// ---------------------------------------------------------------------------
// Maintenance work order types and lifecycle states
// ---------------------------------------------------------------------------

const (
	MaintPreventive = "preventive"
	MaintCorrective = "corrective"
	MaintPredictive = "predictive"
)

const (
	PriorityLow      = "low"
	PriorityMedium   = "medium"
	PriorityHigh     = "high"
	PriorityCritical = "critical"
)

const (
	StatusCreated    = "created"
	StatusApproved   = "approved"
	StatusScheduled  = "scheduled"
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusCancelled  = "cancelled"
)

// ---------------------------------------------------------------------------
// Document types and categories
// ---------------------------------------------------------------------------

const (
	DocProcedure = "procedure"
	DocManual    = "manual"
	DocDrawing   = "drawing"
	DocReport    = "report"
	DocAnalysis  = "analysis"
)

const (
	CatOperational    = "operational"
	CatEmergency      = "emergency"
	CatMaintenance    = "maintenance"
	CatSafety         = "safety"
	CatAdministrative = "administrative"
)

const (
	DocStatusDraft       = "draft"
	DocStatusUnderReview = "under_review"
	DocStatusApproved    = "approved"
	DocStatusSuperseded  = "superseded"
	DocStatusArchived    = "archived"
)

// ---------------------------------------------------------------------------
// Badge types
// ---------------------------------------------------------------------------

const (
	BadgePermanent  = "permanent"
	BadgeTemporary  = "temporary"
	BadgeVisitor    = "visitor"
	BadgeContractor = "contractor"
)

// ---------------------------------------------------------------------------
// Nuclear material types and disposition states
// ---------------------------------------------------------------------------

const (
	MatFuelAssembly = "fuel_assembly"
	MatSpentFuel    = "spent_fuel"
	MatWaste        = "waste"
	MatSource       = "source"
)

const (
	MatInStorage   = "in_storage"
	MatInReactor   = "in_reactor"
	MatSpentPool   = "spent_pool"
	MatDryCask     = "dry_cask"
	MatTransferred = "transferred"
)

// ---------------------------------------------------------------------------
// Safety classification for systems and components
// ---------------------------------------------------------------------------

const (
	SafetyRelated    = "safety_related"
	NonSafety        = "non_safety"
	AugmentedQuality = "augmented_quality"
)

// ---------------------------------------------------------------------------
// ZTNA-specific constants
// ---------------------------------------------------------------------------

const (
	DeviceTypeWorkstation = "workstation"
	DeviceTypeMobile      = "mobile"
	DeviceTypeTerminal    = "control_terminal"
	DeviceTypeTablet      = "tablet"
)

const (
	NetworkPlantInternal = "plant_internal"
	NetworkControlRoom   = "control_room_net"
	NetworkAdmin         = "admin_net"
	NetworkVPN           = "vpn"
	NetworkExternal      = "external"
)
