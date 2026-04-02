package models

// Classification levels
const (
	ClassPublic       = "PUBLIC"
	ClassInternal     = "INTERNAL"
	ClassConfidential = "CONFIDENTIAL"
	ClassSecret       = "SECRET"
	ClassTopSecret    = "TOP_SECRET"
)

// Roles
const (
	RoleOperator      = "operator"
	RoleMaintTech     = "maintenance_technician"
	RoleRadProtection = "radiation_protection_officer"
	RoleSecurity      = "security_officer"
	RolePlantManager  = "plant_manager"
	RoleInspector     = "inspector"
)

// Zone types
const (
	ZonePublic     = "public"
	ZoneControlled = "controlled"
	ZoneRestricted = "restricted"
	ZoneExclusion  = "exclusion"
)

// Reactor status
const (
	ReactorShutdown          = "shutdown"
	ReactorStartup           = "startup"
	ReactorPowerOperation    = "power_operation"
	ReactorHotStandby        = "hot_standby"
	ReactorEmergencyShutdown = "emergency_shutdown"
)

// Maintenance types
const (
	MaintPreventive = "preventive"
	MaintCorrective = "corrective"
	MaintPredictive = "predictive"
)

// Priority
const (
	PriorityLow      = "low"
	PriorityMedium   = "medium"
	PriorityHigh     = "high"
	PriorityCritical = "critical"
)

// Maintenance status
const (
	StatusCreated    = "created"
	StatusApproved   = "approved"
	StatusScheduled  = "scheduled"
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusCancelled  = "cancelled"
)

// Document types
const (
	DocProcedure = "procedure"
	DocManual    = "manual"
	DocDrawing   = "drawing"
	DocReport    = "report"
	DocAnalysis  = "analysis"
)

// Document categories
const (
	CatOperational    = "operational"
	CatEmergency      = "emergency"
	CatMaintenance    = "maintenance"
	CatSafety         = "safety"
	CatAdministrative = "administrative"
)

// Document status
const (
	DocStatusDraft       = "draft"
	DocStatusUnderReview = "under_review"
	DocStatusApproved    = "approved"
	DocStatusSuperseded  = "superseded"
	DocStatusArchived    = "archived"
)

// Badge types
const (
	BadgePermanent  = "permanent"
	BadgeTemporary  = "temporary"
	BadgeVisitor    = "visitor"
	BadgeContractor = "contractor"
)

// Nuclear material types
const (
	MatFuelAssembly = "fuel_assembly"
	MatSpentFuel    = "spent_fuel"
	MatWaste        = "waste"
	MatSource       = "source"
)

// Nuclear material status
const (
	MatInStorage   = "in_storage"
	MatInReactor   = "in_reactor"
	MatSpentPool   = "spent_pool"
	MatDryCask     = "dry_cask"
	MatTransferred = "transferred"
)

// Safety classification
const (
	SafetyRelated    = "safety_related"
	NonSafety        = "non_safety"
	AugmentedQuality = "augmented_quality"
)
