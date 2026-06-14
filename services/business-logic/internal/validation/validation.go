// Package validation centralizza la validazione dei payload in ingresso al
// backend business-logic. Sostituisce il pattern "json.Decode + nessun
// controllo" che lasciava entrare in MongoDB record con campi vuoti o valori
// fuori dominio.
//
// L'integrazione richiesta dal team ("una libreria di validazione come
// middleware" → go-validator) è realizzata con un helper generico,
// DecodeAndValidate[T]: una sola fonte di verità, type-safe, da chiamare come
// prima riga di ogni handler di scrittura. Le regole sono dichiarate via tag
// `validate:"..."` direttamente sugli struct del package models.
package validation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
)

// validate è l'istanza singleton del validatore. È sicura per l'uso
// concorrente (la libreria fa caching interno della reflection sui tipi) e va
// quindi creata una sola volta, non per ogni richiesta.
var validate = validator.New(validator.WithRequiredStructEnabled())

// ValidationError rappresenta un payload che ha superato il parsing JSON ma ha
// violato una o più regole di validazione. È distinto da un errore di decode
// così che il chiamante possa, volendo, differenziare i due casi; entrambi
// mappano comunque su un 400 Bad Request lato HTTP.
type ValidationError struct {
	Fields []string
}

func (e *ValidationError) Error() string {
	return "validazione fallita sui campi: " + strings.Join(e.Fields, ", ")
}

// DecodeAndValidate legge il body JSON della richiesta in un valore di tipo T e
// ne verifica i vincoli dichiarati con i tag `validate`. Restituisce:
//   - un errore di decode se il JSON è malformato o ha tipi incompatibili;
//   - un *ValidationError con l'elenco dei campi non validi in caso di
//     violazione delle regole.
//
// In entrambi i casi il chiamante risponde con 400 Bad Request. Il body viene
// limitato per evitare letture illimitate, e i campi sconosciuti vengono
// rifiutati per non accettare silenziosamente payload sporchi.
func DecodeAndValidate[T any](r *http.Request) (T, error) {
	var v T

	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)) // 1 MiB
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("body JSON non valido: %w", err)
	}

	if err := validate.Struct(v); err != nil {
		var invalid validator.ValidationErrors
		if errorsAs(err, &invalid) {
			fields := make([]string, 0, len(invalid))
			for _, fe := range invalid {
				fields = append(fields, fmt.Sprintf("%s (regola: %s)", fe.Field(), fe.Tag()))
			}
			return v, &ValidationError{Fields: fields}
		}
		return v, err
	}

	return v, nil
}

// errorsAs è un piccolo wrapper su errors.As tenuto locale per non importare il
// package errors nell'interfaccia pubblica del file; mantiene DecodeAndValidate
// leggibile.
func errorsAs(err error, target *validator.ValidationErrors) bool {
	if ve, ok := err.(validator.ValidationErrors); ok {
		*target = ve
		return true
	}
	return false
}
