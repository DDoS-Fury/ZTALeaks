// =============================================================================
// Business Database Models - Go Struct Definitions
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// This file defines the Go structs that map to MongoDB documents for each
// of the seven business collections. All structs use bson tags for correct
// serialization to MongoDB.
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

// Qualification represents a professional certification or training record
// held by an employee. Qualifications have validity periods and are checked
// against zone access requirements.
type Qualification struct {
	Name       string    `bson:"name"`
	IssuedBy   string    `bson:"issued_by"`
	IssueDate  time.Time `bson:"issue_date"`
	ExpiryDate time.Time `bson:"expiry_date"`
	Status     string    `bson:"status"`
}

// EmergencyContact stores contact information for employee emergency situations.
type EmergencyContact struct {
	Name     string `bson:"name"`
	Phone    string `bson:"phone"`
	Relation string `bson:"relation"`
}

// Contact holds employee contact information including an optional emergency contact.
type Contact struct {
	Email            string            `bson:"email"`
	Phone            string            `bson:"phone"`
	EmergencyContact *EmergencyContact `bson:"emergency_contact,omitempty"`
}

// ZTNAMetadata contains Zero Trust specific attributes for identity-based
// policy evaluation. These fields are updated by the security orchestrator
// and consumed by the PDP during access decisions.
type ZTNAMetadata struct {
	// TrustScore is a computed value between 0.0 and 1.0 reflecting the
	// current trustworthiness of the identity based on behavior analytics.
	TrustScore float64 `bson:"trust_score"`

	// LastTrustEvaluation records when the trust score was last computed.
	LastTrustEvaluation time.Time `bson:"last_trust_evaluation"`

	// RiskFlags contains active risk indicators (e.g., "expired_qualification",
	// "anomalous_access_pattern", "failed_auth_threshold").
	RiskFlags []string `bson:"risk_flags"`

	// MFAEnrolled indicates whether the employee has configured MFA.
	MFAEnrolled bool `bson:"mfa_enrolled"`

	// LastSuccessfulAuth records the timestamp of the last successful authentication.
	LastSuccessfulAuth time.Time `bson:"last_successful_auth"`

	// FailedAuthCount tracks failed authentication attempts in the current window.
	FailedAuthCount int `bson:"failed_auth_count"`

	// AccessReviewDate records when the employee's access was last reviewed
	// as part of periodic access certification.
	AccessReviewDate time.Time `bson:"access_review_date"`
}

// Personnel represents an employee record in the nuclear plant.
type Personnel struct {
	EmployeeID          string          `bson:"employee_id"`
	ClassificationLevel string          `bson:"classification_level"`
	FirstName           string          `bson:"first_name"`
	LastName            string          `bson:"last_name"`
	Role                string          `bson:"role"`
	Department          string          `bson:"department"`
	ClearanceLevel      string          `bson:"clearance_level"`
	Qualifications      []Qualification `bson:"qualifications"`
	AssignedZones       []string        `bson:"assigned_zones"`
	BadgeID             string          `bson:"badge_id"`
	Contact             Contact         `bson:"contact"`
	Status              string          `bson:"status"`
	HireDate            time.Time       `bson:"hire_date"`
	LastMedicalCheck    time.Time       `bson:"last_medical_check"`
	ZTNAMetadata        ZTNAMetadata    `bson:"ztna_metadata"`
	DataIntegrityHash   string          `bson:"data_integrity_hash" json:"data_integrity_hash"`
	CreatedAt           time.Time       `bson:"created_at"`
	UpdatedAt           time.Time       `bson:"updated_at"`
}

// ===========================================================================
// ACCESS BADGES
// ===========================================================================

// AccessContext captures the device and network context at the time of a
// physical access event. This information supports correlation between
// physical and digital access patterns in the ZTA model.
type AccessContext struct {
	DeviceType string `bson:"device_type,omitempty"`
	Network    string `bson:"network,omitempty"`
	IPAddress  string `bson:"ip_address,omitempty"`
}

// AccessLogEntry records a single physical access event at a gate.
type AccessLogEntry struct {
	Timestamp   time.Time     `bson:"timestamp"`
	GateID      string        `bson:"gate_id"`
	Direction   string        `bson:"direction"` // "in" or "out"
	ZoneEntered string        `bson:"zone_entered"`
	Status      string        `bson:"status"` // "granted" or "denied"
	Context     AccessContext `bson:"context,omitempty"`
}

// AccessBadge represents a physical access badge assigned to an employee.
type AccessBadge struct {
	BadgeID             string           `bson:"badge_id"`
	ClassificationLevel string           `bson:"classification_level"`
	EmployeeID          string           `bson:"employee_id"`
	Type                string           `bson:"type"`
	AuthorizedZones     []string         `bson:"authorized_zones"`
	IssueDate           time.Time        `bson:"issue_date"`
	ExpiryDate          time.Time        `bson:"expiry_date"`
	Status              string           `bson:"status"`
	AccessLog           []AccessLogEntry `bson:"access_log"`
	DataIntegrityHash   string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// ZONES
// ===========================================================================

// AccessPoint describes a physical entry point to a zone.
type AccessPoint struct {
	GateID string `bson:"gate_id"`
	Type   string `bson:"type"`   // "badge_reader", "biometric", "airlock"
	Status string `bson:"status"` // "active", "inactive", "maintenance"
}

// ZTNAPolicy defines zone-specific Zero Trust policy parameters that the
// PDP evaluates when processing access requests for zone resources.
type ZTNAPolicy struct {
	// MinTrustScore is the minimum identity trust score required for zone access.
	MinTrustScore float64 `bson:"min_trust_score"`

	// RequireMFA indicates whether multi-factor authentication is mandatory.
	RequireMFA bool `bson:"require_mfa"`

	// MaxSessionDurationMinutes defines the maximum session length before
	// the subject must re-authenticate.
	MaxSessionDurationMinutes int `bson:"max_session_duration_minutes"`

	// AllowedDeviceTypes lists the device categories permitted to access
	// zone resources (e.g., "workstation", "control_terminal").
	AllowedDeviceTypes []string `bson:"allowed_device_types"`

	// AllowedNetworks lists the network segments from which zone access
	// is permitted (e.g., "plant_internal", "control_room_net").
	AllowedNetworks []string `bson:"allowed_networks"`

	// ContinuousMonitoring indicates whether ongoing behavior analysis
	// is required during the access session.
	ContinuousMonitoring bool `bson:"continuous_monitoring"`
}

// Zone represents a physical area of the nuclear plant with its security requirements.
type Zone struct {
	ZoneID                 string        `bson:"zone_id"`
	ClassificationLevel    string        `bson:"classification_level"`
	Name                   string        `bson:"name"`
	Code                   string        `bson:"code"`
	Type                   string        `bson:"type"`
	RadiationZone          bool          `bson:"radiation_zone"`
	MaxRadiationLevel      string        `bson:"max_radiation_level,omitempty"`
	RequiredClearance      string        `bson:"required_clearance"`
	RequiredQualifications []string      `bson:"required_qualifications"`
	RequiredPPE            []string      `bson:"required_ppe"`
	MaxOccupancy           int           `bson:"max_occupancy"`
	AccessPoints           []AccessPoint `bson:"access_points"`
	ParentZone             *string       `bson:"parent_zone"`
	SubZones               []string      `bson:"sub_zones"`
	Status                 string        `bson:"status"`
	ZTNAPolicy             ZTNAPolicy    `bson:"ztna_policy"`
	DataIntegrityHash      string        `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// REACTOR PARAMETERS
// ===========================================================================

// ControlRodPosition records the insertion percentage of a control rod group.
type ControlRodPosition struct {
	RodGroup        string  `bson:"rod_group"`
	PositionPercent float64 `bson:"position_percent"`
}

// ReactorParameters represents a time-series measurement of reactor operating conditions.
type ReactorParameters struct {
	ClassificationLevel   string               `bson:"classification_level"`
	Timestamp             time.Time            `bson:"timestamp"`
	ReactorID             string               `bson:"reactor_id"`
	ThermalPowerMW        float64              `bson:"thermal_power_mw"`
	ElectricalPowerMW     float64              `bson:"electrical_power_mw"`
	CoolantTempInletC     float64              `bson:"coolant_temperature_inlet_c"`
	CoolantTempOutletC    float64              `bson:"coolant_temperature_outlet_c"`
	CoolantPressureMPA    float64              `bson:"coolant_pressure_mpa"`
	CoolantFlowRateKgS    float64              `bson:"coolant_flow_rate_kg_s"`
	NeutronFlux           float64              `bson:"neutron_flux"`
	ControlRodPositions   []ControlRodPosition `bson:"control_rod_positions"`
	BoronConcentrationPPM int                  `bson:"boron_concentration_ppm"`
	ReactorStatus         string               `bson:"reactor_status"`
	ScramStatus           bool                 `bson:"scram_status"`
	Alerts                []string             `bson:"alerts"`
	RecordedBy            string               `bson:"recorded_by"`
	ShiftID               string               `bson:"shift_id"`
	DataIntegrityHash     string               `bson:"data_integrity_hash"`
}

// ===========================================================================
// MAINTENANCE ORDERS
// ===========================================================================

// MaintenanceDates tracks lifecycle timestamps for a maintenance order.
type MaintenanceDates struct {
	Created        time.Time  `bson:"created"`
	Approved       *time.Time `bson:"approved,omitempty"`
	ScheduledStart *time.Time `bson:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time `bson:"scheduled_end,omitempty"`
	ActualStart    *time.Time `bson:"actual_start,omitempty"`
	ActualEnd      *time.Time `bson:"actual_end,omitempty"`
}

// Part represents a component required for a maintenance activity.
type Part struct {
	PartID   string `bson:"part_id"`
	Name     string `bson:"name"`
	Quantity int    `bson:"quantity"`
	Status   string `bson:"status"`
}

// Approval records a single authorization decision in the approval chain.
type Approval struct {
	Role       string    `bson:"role"`
	ApprovedBy string    `bson:"approved_by"`
	Date       time.Time `bson:"date"`
	Status     string    `bson:"status"`
}

// MaintenanceOrder represents a work order for plant maintenance activities.
type MaintenanceOrder struct {
	OrderID              string           `bson:"order_id"`
	ClassificationLevel  string           `bson:"classification_level"`
	Title                string           `bson:"title"`
	Type                 string           `bson:"type"`
	Priority             string           `bson:"priority"`
	System               string           `bson:"system"`
	EquipmentID          string           `bson:"equipment_id"`
	ZoneID               string           `bson:"zone_id"`
	Description          string           `bson:"description"`
	SafetyClassification string           `bson:"safety_classification"`
	RequestedBy          string           `bson:"requested_by"`
	AssignedTo           []string         `bson:"assigned_to"`
	Status               string           `bson:"status"`
	Dates                MaintenanceDates `bson:"dates"`
	PartsRequired        []Part           `bson:"parts_required"`
	RadiationWorkPermit  string           `bson:"radiation_work_permit,omitempty"`
	EstimatedDoseMSV     float64          `bson:"estimated_dose_msv"`
	Procedures           []string         `bson:"procedures"`
	ApprovalChain        []Approval       `bson:"approval_chain"`
	DataIntegrityHash    string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// DOCUMENTS
// ===========================================================================

// Revision records document version information including authorship and approval.
type Revision struct {
	Number         int       `bson:"number"`
	Date           time.Time `bson:"date"`
	Author         string    `bson:"author"`
	ApprovedBy     string    `bson:"approved_by"`
	ChangesSummary string    `bson:"changes_summary"`
}

// Document represents a technical document, procedure, or report.
type Document struct {
	DocumentID          string    `bson:"document_id"`
	ClassificationLevel string    `bson:"classification_level"`
	Title               string    `bson:"title"`
	Type                string    `bson:"type"`
	Category            string    `bson:"category"`
	Revision            Revision  `bson:"revision"`
	ApplicableSystems   []string  `bson:"applicable_systems"`
	ApplicableZones     []string  `bson:"applicable_zones"`
	ApplicableRoles     []string  `bson:"applicable_roles"`
	FileReference       string    `bson:"file_reference"`
	Keywords            []string  `bson:"keywords"`
	Status              string    `bson:"status"`
	PreviousRevisions   []string  `bson:"previous_revisions"`
	ReviewDate          time.Time `bson:"review_date"`
	CreatedAt           time.Time `bson:"created_at"`
	UpdatedAt           time.Time `bson:"updated_at"`
	DataIntegrityHash   string    `bson:"data_integrity_hash" json:"data_integrity_hash"`
}

// ===========================================================================
// NUCLEAR MATERIALS
// ===========================================================================

// MaterialLocation describes the physical location of nuclear material.
type MaterialLocation struct {
	ZoneID      string  `bson:"zone_id"`
	Position    string  `bson:"position"`
	StorageRack *string `bson:"storage_rack,omitempty"`
}

// MaterialDates records key lifecycle dates for nuclear material.
type MaterialDates struct {
	Received          time.Time  `bson:"received"`
	Loaded            *time.Time `bson:"loaded,omitempty"`
	ExpectedDischarge *time.Time `bson:"expected_discharge,omitempty"`
}

// IAEASafeguards contains International Atomic Energy Agency safeguards data.
type IAEASafeguards struct {
	SealID         string    `bson:"seal_id"`
	LastInspection time.Time `bson:"last_inspection"`
	NextInspection time.Time `bson:"next_inspection"`
}

// Accountability records material inventory verification data.
type Accountability struct {
	LastInventory time.Time `bson:"last_inventory"`
	VerifiedBy    string    `bson:"verified_by"`
}

// NuclearMaterial represents a nuclear or radioactive material inventory item.
type NuclearMaterial struct {
	MaterialID          string           `bson:"material_id"`
	ClassificationLevel string           `bson:"classification_level"`
	Type                string           `bson:"type"`
	Description         string           `bson:"description"`
	EnrichmentPercent   float64          `bson:"enrichment_percent,omitempty"`
	MassKG              float64          `bson:"mass_kg"`
	InitialU235KG       float64          `bson:"initial_u235_kg,omitempty"`
	Status              string           `bson:"status"`
	Location            MaterialLocation `bson:"location"`
	BurnupMWDT          float64          `bson:"burnup_mwd_t,omitempty"`
	CycleLoaded         int              `bson:"cycle_loaded,omitempty"`
	Dates               MaterialDates    `bson:"dates"`
	Supplier            string           `bson:"supplier"`
	SerialNumber        string           `bson:"serial_number"`
	IAEASafeguards      IAEASafeguards   `bson:"iaea_safeguards"`
	Accountability      Accountability   `bson:"accountability"`
	DataIntegrityHash   string           `bson:"data_integrity_hash" json:"data_integrity_hash"`
}
