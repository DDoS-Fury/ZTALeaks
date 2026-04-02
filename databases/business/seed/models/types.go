package models

import "time"

// ==================== PERSONNEL ====================

type Qualification struct {
	Name       string    `bson:"name"`
	IssuedBy   string    `bson:"issued_by"`
	IssueDate  time.Time `bson:"issue_date"`
	ExpiryDate time.Time `bson:"expiry_date"`
	Status     string    `bson:"status"`
}

type EmergencyContact struct {
	Name     string `bson:"name"`
	Phone    string `bson:"phone"`
	Relation string `bson:"relation"`
}

type Contact struct {
	Email            string            `bson:"email"`
	Phone            string            `bson:"phone"`
	EmergencyContact *EmergencyContact `bson:"emergency_contact,omitempty"`
}

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
	CreatedAt           time.Time       `bson:"created_at"`
	UpdatedAt           time.Time       `bson:"updated_at"`
}

// ==================== ACCESS BADGES ====================

type AccessLogEntry struct {
	Timestamp   time.Time `bson:"timestamp"`
	GateID      string    `bson:"gate_id"`
	Direction   string    `bson:"direction"`
	ZoneEntered string    `bson:"zone_entered"`
	Status      string    `bson:"status"`
}

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
}

// ==================== ZONES ====================

type AccessPoint struct {
	GateID string `bson:"gate_id"`
	Type   string `bson:"type"`
	Status string `bson:"status"`
}

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
}

// ==================== REACTOR PARAMETERS ====================

type ControlRodPosition struct {
	RodGroup        string  `bson:"rod_group"`
	PositionPercent float64 `bson:"position_percent"`
}

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
}

// ==================== MAINTENANCE ORDERS ====================

type MaintenanceDates struct {
	Created        time.Time  `bson:"created"`
	Approved       *time.Time `bson:"approved,omitempty"`
	ScheduledStart *time.Time `bson:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time `bson:"scheduled_end,omitempty"`
	ActualStart    *time.Time `bson:"actual_start,omitempty"`
	ActualEnd      *time.Time `bson:"actual_end,omitempty"`
}

type Part struct {
	PartID   string `bson:"part_id"`
	Name     string `bson:"name"`
	Quantity int    `bson:"quantity"`
	Status   string `bson:"status"`
}

type Approval struct {
	Role       string    `bson:"role"`
	ApprovedBy string    `bson:"approved_by"`
	Date       time.Time `bson:"date"`
	Status     string    `bson:"status"`
}

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
}

// ==================== DOCUMENTS ====================

type Revision struct {
	Number         int       `bson:"number"`
	Date           time.Time `bson:"date"`
	Author         string    `bson:"author"`
	ApprovedBy     string    `bson:"approved_by"`
	ChangesSummary string    `bson:"changes_summary"`
}

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
}

// ==================== NUCLEAR MATERIALS ====================

type MaterialLocation struct {
	ZoneID      string  `bson:"zone_id"`
	Position    string  `bson:"position"`
	StorageRack *string `bson:"storage_rack"`
}

type MaterialDates struct {
	Received          time.Time  `bson:"received"`
	Loaded            *time.Time `bson:"loaded,omitempty"`
	ExpectedDischarge *time.Time `bson:"expected_discharge,omitempty"`
}

type IAEASafeguards struct {
	SealID         string    `bson:"seal_id"`
	LastInspection time.Time `bson:"last_inspection"`
	NextInspection time.Time `bson:"next_inspection"`
}

type Accountability struct {
	LastInventory time.Time `bson:"last_inventory"`
	VerifiedBy    string    `bson:"verified_by"`
}

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
}
