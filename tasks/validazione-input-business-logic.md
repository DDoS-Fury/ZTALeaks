# Validazione input sul backend `business-logic`

**Branch:** `model_v2`
**Data:** 2026-06-14
**Libreria:** `github.com/go-playground/validator/v10` (il "go-validator" discusso in chat)

## Contesto / problema

Gli endpoint POST `Create*` di `business-logic` facevano solo:

```go
json.NewDecoder(r.Body).Decode(&p)
```

Nessun controllo sul contenuto: un payload con campi obbligatori vuoti, enum
fuori dominio (es. `role: "supreme_leader"`) o valori numerici assurdi
(masse negative, percentuali > 100) finiva **dritto in MongoDB**. Richiesta del
team: *"correggere la validazione dei dati sul backend"* usando una libreria
("un middleware") invece di `if` scritti a mano in ogni handler.

## Decisioni progettuali

### Scope: solo `business-logic`
È l'unico servizio con `json.Decode` + zero validazione che scrive input
utente in Mongo. `iam-service` ha già validazione propria fatta dai
colleghi (rate-limit, OTP, WebAuthn) → non toccato per non sovrapporsi.
`security-orchestrator` riceve metadati da Envoy, non input utente → fuori scope.

### Approccio: helper generico, non middleware HTTP classico
La libreria è integrata con una funzione generica `DecodeAndValidate[T]`
(Go generics), chiamata come prima riga di ogni handler di scrittura.

Perché **non** un middleware `http.Handler → http.Handler`: quel pattern non
conosce il tipo dello struct di destinazione, quindi richiederebbe di passarlo
via `context.Value` con type-assertion → si perde la sicurezza dei tipi
(anti-pattern noto). L'helper generico dà lo stesso vantaggio ("validazione
centralizzata e dichiarativa") con **diff minimo** (sostituisce la riga di
decode già esistente) e mantenendo le firme standard degli handler.

## Modifiche

### File nuovi
- `internal/validation/validation.go`
  - istanza singleton `*validator.Validate` (thread-safe, creata una volta)
  - `DecodeAndValidate[T any](r) (T, error)`:
    - limita il body a 1 MiB (`http.MaxBytesReader`)
    - rifiuta campi JSON sconosciuti (`DisallowUnknownFields`)
    - su violazione delle regole restituisce un `*ValidationError` con
      l'elenco dei campi e della regola violata
  - tipo `ValidationError` per distinguere "JSON malformato" da "regole non
    rispettate" (entrambi → HTTP 400)
- `internal/validation/validation_test.go`
  - 5 test: payload valido, campo required mancante, enum non valido,
    JSON malformato, campo sconosciuto

### File modificati
- `internal/models/types.go` — tag `validate:"..."` sui 4 struct di input
  (solo campi forniti dal client; **esclusi** i campi impostati dal server:
  `CreatedAt`, `UpdatedAt`, `DataIntegrityHash`):
  - `Personnel`: `required` su id/nome/dipartimento; `oneof` su
    `classification_level`, `clearance_level`, `role`
  - `ReactorParameters`: `oneof` su `classification_level` e `reactor_status`;
    range fisici (`gte=0` su potenze/pressione/flusso/flusso neutronico,
    `position_percent` 0–100 con `dive` sulle barre di controllo)
  - `Document`: `oneof` su `classification_level`, `type`, `category`, `status`
  - `NuclearMaterial`: `oneof` su `classification_level`, `type`, `status`;
    `enrichment_percent` 0–100, `mass_kg > 0`
  - Gli enum riusano i valori già definiti in `internal/models/enums.go`
- `internal/handler/api.go` — i 4 handler `Create*` ora usano
  `validation.DecodeAndValidate[...]` al posto del decode manuale
- `go.mod` / `go.sum` — aggiunta dipendenza validator

## Verifica (senza avviare stack/container/immagini)

```
go build ./...   → OK
go vet ./...     → OK
go test ./...    → ok internal/validation (5/5), nessun altro test rotto
```

## Note per i colleghi
- Comportamento nuovo: un POST non valido ora risponde **400 Bad Request** con
  il dettaglio del campo, invece di scrivere il record. I client/test che
  inviavano payload incompleti vanno aggiornati di conseguenza.
- `DisallowUnknownFields` è volutamente strict: se il frontend invia campi extra
  non presenti nello struct, il create viene rifiutato. Valutare se allentarlo
  in caso emergano falsi positivi.
- Estensione naturale (non fatta qui): applicare lo stesso helper agli endpoint
  di update quando verranno aggiunti, e valutare un dominio enum esplicito per
  `Personnel.Status` (oggi solo `required`, manca la costante in `enums.go`).
