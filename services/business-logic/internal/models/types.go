// =============================================================================
// Business Database Models - Go Struct Definitions
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This file defines the Go structs that map to MongoDB documents for each
// of the seven business collections. All structs use bson tags for correct
// serialization to MongoDB and matching json tags so REST responses expose
// the same snake_case field names used by the frontend.
//
// ZTNA Enhancement: Several structs include additional fields for Zero Trust
// policy support, including:
//   - ZTNAMetadata on personnel (trust scores, risk flags, auth state)
//   - ZTNAPolicy on zones (minimum trust score, MFA requirements, session limits)
//   - DataIntegrityHash on reactor parameters (tamper detection)
//   - AccessContext on access badges (device and network context)
//
// These fields are designed to be consumed by the PDP (OPA) during policy
// evaluation to implement continuous, context-aware access control.
// =============================================================================

package models

import "time"

// ===========================================================================
// PERSONNEL
// ===========================================================================

type Qualification struct {
	Name       string    `bson:"name" json:"name"`
	IssuedBy   string    `bson:"issued_by" json:"issued_by"`
	IssueDate  time.Time `bson:"issue_date" json:"issue_date"`
	ExpiryDate time.Time `bson:"expiry_date" json:"expiry_date"`
	Status     string    `bson:"status" json:"status"`
}

type EmergencyContact struct {
	Name     string `bson:"name" json:"name"`
	Phone    string `bson:"phone" json:"phone"`
	Relation string `bson:"relation" json:"relation"`
}

type Contact struct {
	Email            string            `bson:"email" json:"email"`
	Phone            string            `bson:"phone" json:"phone"`
	EmergencyContact *EmergencyContact `bson:"emergency_contact,omitempty" json:"emergency_contact,omitempty"`
}

type ZTNAMetadata struct {
	TrustScore          float64   `bson:"trust_score" json:"trust_score"`
	LastTrustEvaluation time.Time `bson:"last_trust_evaluation" json:"last_trust_evaluation"`
	RiskFlags           []string  `bson:"risk_flags" json:"risk_flags"`
	MFAEnrolled         bool      `bson:"mfa_enrolled" json:"mfa_enrolled"`
	LastSuccessfulAuth  time.Time `bson:"last_successful_auth" json:"last_successful_auth"`
	FailedAuthCount     int       `bson:"failed_auth_count" json:"failed_auth_count"`
	AccessReviewDate    time.Time `bson:"access_review_date" json:"access_review_date"`
}

type Personnel struct {
	EmployeeID          string          `bson:"employee_id" json:"employee_id" validate:"required"`
	ClassificationLevel string          `bson:"classification_level" json:"classification_level" validate:"required,oneof=PUBLIC INTERNAL CONFIDENTIAL SECRET TOP_SECRET"`
	FirstName           string          `bson:"first_name" json:"first_name" validate:"required"`
	LastName            string          `bson:"last_name" json:"last_name" validate:"required"`
	Role                string          `bson:"role" json:"role" validate:"required,oneof=operator maintenance_technician radiation_protection_officer security_officer plant_manager inspector"`
	Department          string          `bson:"department" json:"department" validate:"required"`
	ClearanceLevel      string          `bson:"clearance_level" json:"clearance_level" validate:"required,oneof=PUBLIC INTERNAL CONFIDENTIAL SECRET TOP_SECRET"`
	Qualifications      []Qualification `bson:"qualifications" json:"qualifications"`
	AssignedZones       []string        `bson:"assigned_zones" json:"assigned_zones"`
	BadgeID             string          `bson:"badge_id" json:"badge_id"`
	Contact             Contact         `bson:"contact" json:"contact"`
	Status              string          `bson:"status" json:"status" validate:"required"`
	HireDate            time.Time       `bson:"hire_date" json:"hire_date"`
	LastMedicalCheck    time.Time       `bson:"last_medical_check" json:"last_medical_check"`
	ZTNAMetadata        ZTNAMetadata    `bson:"ztna_metadata" json:"ztna_metadata"`
	DataIntegrityHash   string          `bson:"data_integrity_hash" json:"data_integrity_hash"`
	CreatedAt           time.Time       `bson:"created_at" json:"created_at"`
	UpdatedAt           time.Time       `bson:"updated_at" json:"updated_at"`
}

// ===========================================================================
// ACCESS BADGES
// ===========================================================================

type AccessContext struct {
	DeviceType string `bson:"device_type,omitempty" json:"device_type,omitempty"`
	Network    string `bson:"network,omitempty" json:"network,omitempty"`
	IPAddress  string `bson:"ip_address,omitempty" json:"ip_address,omitempty"`
}

type AccessLogEntry struct {
	Timestamp   time.Time     `bson:"timestamp" json:"timestamp"`
	GateID      string        `bson:"gate_id" json:"gate_id"`
	Direction   string        `bson:"direction" json:"direction"`
	ZoneEntered string        `bson:"zone_entered" json:"zone_entered"`
	Status      string        `bson:"status" json:"status"`
	Context     AccessContext `bson:"context,omitempty" json:"context,omitempty"`
}

type AccessBadge struct {
	BadgeID             string           `bson:"badge_id" json:"badge_id"`
	ClassificationLevel string           `bson:"classification_level" json:"classification_level"`
	EmployeeID          string           `bson:"employee_id" json:"employee_id"`
	Type                string           `bson:"type" json:"type"`
	AuthorizedZones     []string         `bson:"authorized_zones" json:"authorized_zones"`
	IssueDate           time.Time        `bson:"issue_date" json:"issue_date"`
	ExpiryDate          time.Time        `bson:"expiry_date" json:"expiry_date"`
	Status              string           `bson:"status" json:"status"`
	AccessLog           []AccessLogEntry `bson:"access_log" json:"access_log"`
	DataIntegrityHash   string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// ZONES
// ===========================================================================

type AccessPoint struct {
	GateID string `bson:"gate_id" json:"gate_id"`
	Type   string `bson:"type" json:"type"`
	Status string `bson:"status" json:"status"`
}

type ZTNAPolicy struct {
	MinTrustScore             float64  `bson:"min_trust_score" json:"min_trust_score"`
	RequireMFA                bool     `bson:"require_mfa" json:"require_mfa"`
	MaxSessionDurationMinutes int      `bson:"max_session_duration_minutes" json:"max_session_duration_minutes"`
	AllowedDeviceTypes        []string `bson:"allowed_device_types" json:"allowed_device_types"`
	AllowedNetworks           []string `bson:"allowed_networks" json:"allowed_networks"`
	ContinuousMonitoring      bool     `bson:"continuous_monitoring" json:"continuous_monitoring"`
}

type Zone struct {
	ZoneID                 string        `bson:"zone_id" json:"zone_id"`
	ClassificationLevel    string        `bson:"classification_level" json:"classification_level"`
	Name                   string        `bson:"name" json:"name"`
	Code                   string        `bson:"code" json:"code"`
	Type                   string        `bson:"type" json:"type"`
	RadiationZone          bool          `bson:"radiation_zone" json:"radiation_zone"`
	MaxRadiationLevel      string        `bson:"max_radiation_level,omitempty" json:"max_radiation_level,omitempty"`
	RequiredClearance      string        `bson:"required_clearance" json:"required_clearance"`
	RequiredQualifications []string      `bson:"required_qualifications" json:"required_qualifications"`
	RequiredPPE            []string      `bson:"required_ppe" json:"required_ppe"`
	MaxOccupancy           int           `bson:"max_occupancy" json:"max_occupancy"`
	AccessPoints           []AccessPoint `bson:"access_points" json:"access_points"`
	ParentZone             *string       `bson:"parent_zone" json:"parent_zone"`
	SubZones               []string      `bson:"sub_zones" json:"sub_zones"`
	Status                 string        `bson:"status" json:"status"`
	ZTNAPolicy             ZTNAPolicy    `bson:"ztna_policy" json:"ztna_policy"`
	DataIntegrityHash      string        `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// REACTOR PARAMETERS
// ===========================================================================

type ControlRodPosition struct {
	RodGroup        string  `bson:"rod_group" json:"rod_group" validate:"required"`
	PositionPercent float64 `bson:"position_percent" json:"position_percent" validate:"gte=0,lte=100"`
}

type ReactorParameters struct {
	ClassificationLevel   string               `bson:"classification_level" json:"classification_level" validate:"required,oneof=PUBLIC INTERNAL CONFIDENTIAL SECRET TOP_SECRET"`
	Timestamp             time.Time            `bson:"timestamp" json:"timestamp"`
	ReactorID             string               `bson:"reactor_id" json:"reactor_id" validate:"required"`
	ThermalPowerMW        float64              `bson:"thermal_power_mw" json:"thermal_power_mw" validate:"gte=0"`
	ElectricalPowerMW     float64              `bson:"electrical_power_mw" json:"electrical_power_mw" validate:"gte=0"`
	CoolantTempInletC     float64              `bson:"coolant_temperature_inlet_c" json:"coolant_temperature_inlet_c"`
	CoolantTempOutletC    float64              `bson:"coolant_temperature_outlet_c" json:"coolant_temperature_outlet_c"`
	CoolantPressureMPA    float64              `bson:"coolant_pressure_mpa" json:"coolant_pressure_mpa" validate:"gte=0"`
	CoolantFlowRateKgS    float64              `bson:"coolant_flow_rate_kg_s" json:"coolant_flow_rate_kg_s" validate:"gte=0"`
	NeutronFlux           float64              `bson:"neutron_flux" json:"neutron_flux" validate:"gte=0"`
	ControlRodPositions   []ControlRodPosition `bson:"control_rod_positions" json:"control_rod_positions" validate:"dive"`
	BoronConcentrationPPM int                  `bson:"boron_concentration_ppm" json:"boron_concentration_ppm" validate:"gte=0"`
	ReactorStatus         string               `bson:"reactor_status" json:"reactor_status" validate:"required,oneof=shutdown startup power_operation hot_standby emergency_shutdown"`
	ScramStatus           bool                 `bson:"scram_status" json:"scram_status"`
	Alerts                []string             `bson:"alerts" json:"alerts"`
	RecordedBy            string               `bson:"recorded_by" json:"recorded_by" validate:"required"`
	ShiftID               string               `bson:"shift_id" json:"shift_id"`
	DataIntegrityHash     string               `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// MAINTENANCE ORDERS
// ===========================================================================

type MaintenanceDates struct {
	Created        time.Time  `bson:"created" json:"created"`
	Approved       *time.Time `bson:"approved,omitempty" json:"approved,omitempty"`
	ScheduledStart *time.Time `bson:"scheduled_start,omitempty" json:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time `bson:"scheduled_end,omitempty" json:"scheduled_end,omitempty"`
	ActualStart    *time.Time `bson:"actual_start,omitempty" json:"actual_start,omitempty"`
	ActualEnd      *time.Time `bson:"actual_end,omitempty" json:"actual_end,omitempty"`
}

type Part struct {
	PartID   string `bson:"part_id" json:"part_id"`
	Name     string `bson:"name" json:"name"`
	Quantity int    `bson:"quantity" json:"quantity"`
	Status   string `bson:"status" json:"status"`
}

type Approval struct {
	Role       string    `bson:"role" json:"role"`
	ApprovedBy string    `bson:"approved_by" json:"approved_by"`
	Date       time.Time `bson:"date" json:"date"`
	Status     string    `bson:"status" json:"status"`
}

type MaintenanceOrder struct {
	OrderID              string           `bson:"order_id" json:"order_id"`
	ClassificationLevel  string           `bson:"classification_level" json:"classification_level"`
	Title                string           `bson:"title" json:"title"`
	Type                 string           `bson:"type" json:"type"`
	Priority             string           `bson:"priority" json:"priority"`
	System               string           `bson:"system" json:"system"`
	EquipmentID          string           `bson:"equipment_id" json:"equipment_id"`
	ZoneID               string           `bson:"zone_id" json:"zone_id"`
	Description          string           `bson:"description" json:"description"`
	SafetyClassification string           `bson:"safety_classification" json:"safety_classification"`
	RequestedBy          string           `bson:"requested_by" json:"requested_by"`
	AssignedTo           []string         `bson:"assigned_to" json:"assigned_to"`
	Status               string           `bson:"status" json:"status"`
	Dates                MaintenanceDates `bson:"dates" json:"dates"`
	PartsRequired        []Part           `bson:"parts_required" json:"parts_required"`
	RadiationWorkPermit  string           `bson:"radiation_work_permit,omitempty" json:"radiation_work_permit,omitempty"`
	EstimatedDoseMSV     float64          `bson:"estimated_dose_msv" json:"estimated_dose_msv"`
	Procedures           []string         `bson:"procedures" json:"procedures"`
	ApprovalChain        []Approval       `bson:"approval_chain" json:"approval_chain"`
	DataIntegrityHash    string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// DOCUMENTS
// ===========================================================================

type Revision struct {
	Number         int       `bson:"number" json:"number"`
	Date           time.Time `bson:"date" json:"date"`
	Author         string    `bson:"author" json:"author"`
	ApprovedBy     string    `bson:"approved_by" json:"approved_by"`
	ChangesSummary string    `bson:"changes_summary" json:"changes_summary"`
}

type Document struct {
	DocumentID          string    `bson:"document_id" json:"document_id" validate:"required"`
	ClassificationLevel string    `bson:"classification_level" json:"classification_level" validate:"required,oneof=PUBLIC INTERNAL CONFIDENTIAL SECRET TOP_SECRET"`
	Title               string    `bson:"title" json:"title" validate:"required"`
	Type                string    `bson:"type" json:"type" validate:"required,oneof=procedure manual drawing report analysis"`
	Category            string    `bson:"category" json:"category" validate:"required,oneof=operational emergency maintenance safety administrative"`
	Revision            Revision  `bson:"revision" json:"revision"`
	ApplicableSystems   []string  `bson:"applicable_systems" json:"applicable_systems"`
	ApplicableZones     []string  `bson:"applicable_zones" json:"applicable_zones"`
	ApplicableRoles     []string  `bson:"applicable_roles" json:"applicable_roles"`
	FileReference       string    `bson:"file_reference" json:"file_reference"`
	Keywords            []string  `bson:"keywords" json:"keywords"`
	Status              string    `bson:"status" json:"status" validate:"required,oneof=draft under_review approved superseded archived"`
	PreviousRevisions   []string  `bson:"previous_revisions" json:"previous_revisions"`
	ReviewDate          time.Time `bson:"review_date" json:"review_date"`
	CreatedAt           time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt           time.Time `bson:"updated_at" json:"updated_at"`
	DataIntegrityHash   string    `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// NUCLEAR MATERIALS
// ===========================================================================

type MaterialLocation struct {
	ZoneID      string  `bson:"zone_id" json:"zone_id"`
	Position    string  `bson:"position" json:"position"`
	StorageRack *string `bson:"storage_rack,omitempty" json:"storage_rack,omitempty"`
}

type MaterialDates struct {
	Received          time.Time  `bson:"received" json:"received"`
	Loaded            *time.Time `bson:"loaded,omitempty" json:"loaded,omitempty"`
	ExpectedDischarge *time.Time `bson:"expected_discharge,omitempty" json:"expected_discharge,omitempty"`
}

type IAEASafeguards struct {
	SealID         string    `bson:"seal_id" json:"seal_id"`
	LastInspection time.Time `bson:"last_inspection" json:"last_inspection"`
	NextInspection time.Time `bson:"next_inspection" json:"next_inspection"`
}

type Accountability struct {
	LastInventory time.Time `bson:"last_inventory" json:"last_inventory"`
	VerifiedBy    string    `bson:"verified_by" json:"verified_by"`
}

type NuclearMaterial struct {
	MaterialID          string           `bson:"material_id" json:"material_id" validate:"required"`
	ClassificationLevel string           `bson:"classification_level" json:"classification_level" validate:"required,oneof=PUBLIC INTERNAL CONFIDENTIAL SECRET TOP_SECRET"`
	Type                string           `bson:"type" json:"type" validate:"required,oneof=fuel_assembly spent_fuel waste source"`
	Description         string           `bson:"description" json:"description" validate:"required"`
	EnrichmentPercent   float64          `bson:"enrichment_percent,omitempty" json:"enrichment_percent,omitempty" validate:"omitempty,gte=0,lte=100"`
	MassKG              float64          `bson:"mass_kg" json:"mass_kg" validate:"gt=0"`
	InitialU235KG       float64          `bson:"initial_u235_kg,omitempty" json:"initial_u235_kg,omitempty" validate:"omitempty,gte=0"`
	Status              string           `bson:"status" json:"status" validate:"required,oneof=in_storage in_reactor spent_pool dry_cask transferred"`
	Location            MaterialLocation `bson:"location" json:"location"`
	BurnupMWDT          float64          `bson:"burnup_mwd_t,omitempty" json:"burnup_mwd_t,omitempty"`
	CycleLoaded         int              `bson:"cycle_loaded,omitempty" json:"cycle_loaded,omitempty"`
	Dates               MaterialDates    `bson:"dates" json:"dates"`
	Supplier            string           `bson:"supplier" json:"supplier"`
	SerialNumber        string           `bson:"serial_number" json:"serial_number"`
	IAEASafeguards      IAEASafeguards   `bson:"iaea_safeguards" json:"iaea_safeguards"`
	Accountability      Accountability   `bson:"accountability" json:"accountability"`
	DataIntegrityHash   string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}
