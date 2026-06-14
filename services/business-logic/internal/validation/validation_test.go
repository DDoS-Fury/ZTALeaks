package validation

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"ztaleaks/business-logic/internal/models"
)

// decode incapsula la costruzione di una POST con il body JSON dato e il
// passaggio per DecodeAndValidate, come avverrebbe in un handler di scrittura.
func decode(body string) (models.Personnel, error) {
	r := httptest.NewRequest("POST", "/api/v1/personnel", strings.NewReader(body))
	return DecodeAndValidate[models.Personnel](r)
}

func TestDecodeAndValidate_Valid(t *testing.T) {
	body := `{
		"employee_id": "EMP-001",
		"classification_level": "SECRET",
		"first_name": "Mara",
		"last_name": "Rossi",
		"role": "operator",
		"department": "Operations",
		"clearance_level": "SECRET",
		"status": "active"
	}`
	p, err := decode(body)
	if err != nil {
		t.Fatalf("payload valido rifiutato: %v", err)
	}
	if p.EmployeeID != "EMP-001" {
		t.Fatalf("decode errato: employee_id = %q", p.EmployeeID)
	}
}

func TestDecodeAndValidate_MissingRequired(t *testing.T) {
	// Manca first_name (required).
	body := `{
		"employee_id": "EMP-002",
		"classification_level": "SECRET",
		"last_name": "Rossi",
		"role": "operator",
		"department": "Operations",
		"clearance_level": "SECRET",
		"status": "active"
	}`
	_, err := decode(body)
	if err == nil {
		t.Fatal("payload senza first_name accettato, atteso errore")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("atteso *ValidationError, ottenuto %T", err)
	}
}

func TestDecodeAndValidate_BadEnum(t *testing.T) {
	// role fuori dal dominio oneof.
	body := `{
		"employee_id": "EMP-003",
		"classification_level": "SECRET",
		"first_name": "Mara",
		"last_name": "Rossi",
		"role": "supreme_leader",
		"department": "Operations",
		"clearance_level": "SECRET",
		"status": "active"
	}`
	_, err := decode(body)
	if err == nil {
		t.Fatal("role non valido accettato, atteso errore")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("atteso *ValidationError, ottenuto %T", err)
	}
}

func TestDecodeAndValidate_MalformedJSON(t *testing.T) {
	_, err := decode(`{"employee_id": `)
	if err == nil {
		t.Fatal("JSON malformato accettato, atteso errore")
	}
	// Un JSON malformato non è un ValidationError ma un errore di decode.
	var ve *ValidationError
	if errors.As(err, &ve) {
		t.Fatal("JSON malformato classificato come ValidationError")
	}
}

func TestDecodeAndValidate_UnknownField(t *testing.T) {
	body := `{
		"employee_id": "EMP-004",
		"classification_level": "SECRET",
		"first_name": "Mara",
		"last_name": "Rossi",
		"role": "operator",
		"department": "Operations",
		"clearance_level": "SECRET",
		"status": "active",
		"is_admin": true
	}`
	if _, err := decode(body); err == nil {
		t.Fatal("campo sconosciuto (is_admin) accettato, atteso errore")
	}
}
