# Secure WebAuthn Implementation

Il piano descrive il refactoring completo delle rotte di registrazione e login WebAuthn per eliminare le vulnerabilità crittografiche (mancata verifica della firma in login e mancata verifica dell'attestazione in registrazione). 
Utilizzeremo la libreria standard e affidabile `github.com/go-webauthn/webauthn`.

## User Review Required

> [!WARNING]
> **Breaking Changes nel Database:** La modifica al formato di archiviazione delle credenziali WebAuthn renderà le chiavi di test attualmente registrate non più compatibili (dovranno essere ri-registrate). Nel contesto di un laboratorio/applicativo, è sufficiente cancellare le collection mongo `device_fingerprints` e `webauthn_challenges`.
>
> Inoltre, l'interfaccia frontend richiederà di essere allineata allo standard atteso dalla libreria, quindi anche i flussi Javascript cambieranno.

## Proposed Changes

### Backend Dependencies

Aggiunta del modulo Go necessario per parsare CBOR e validare la crittografia.
- **[MODIFY] `services/iam-service/go.mod`**: Aggiungere `github.com/go-webauthn/webauthn`

### Backend Models & Interfaces

Per poter usare `go-webauthn`, i modelli devono implementare le interfacce `webauthn.User` e fornire il modo di recuperare/salvare le `webauthn.Credential`.
- **[MODIFY] `services/iam-service/internal/models/user.go`**:
  - Implementare l'interfaccia `webauthn.User` sul receiver `User` (metodi: `WebAuthnID`, `WebAuthnName`, `WebAuthnDisplayName`, `WebAuthnIcon`, `WebAuthnCredentials`).
- **[MODIFY] `services/iam-service/internal/models/sessions.go`**:
  - Modificare `DeviceCredential` per mappare in modo pulito il tipo `webauthn.Credential` (es. inglobando direttamente la struct o convertendo i campi necessari come `Transport` e `Flags`).
  - Aggiornare `WebAuthnChallenge` per usare il campo in cui `go-webauthn` si aspetta la sessione crittografica temporanea (la libreria fornisce un oggetto `webauthn.SessionData` da salvare nel DB o in cache).

### Backend Handlers

Riscrivere interamente l'autenticazione manuale con l'API robusta della libreria.
- **[MODIFY] `services/iam-service/internal/webauthn/handler.go`**:
  - Aggiungere il costruttore per `*webauthn.WebAuthn` all'interno della struct `Handler`, definendo il `RPDisplayName`, `RPID`, e `RPOrigin`.
- **[MODIFY] `services/iam-service/internal/webauthn/register.go`**:
  - `BeginRegistration`: Sostituire la costruzione manuale con `webauthn.BeginRegistration(user, ...)`. Salvare l'oggetto restituito `SessionData` nel database al posto del challenge generato a mano.
  - `FinishRegistration`: Sostituire la validazione manuale (e debole) con `webauthn.FinishRegistration(user, sessionData, r)`. Il framework leggerà automaticamente l'`attestationObject` e `clientDataJSON` dal corpo della request e li validerà. In caso di successo, salveremo la nuova credenziale generata.
- **[MODIFY] `services/iam-service/internal/webauthn/login.go`**:
  - `BeginLogin`: Sostituire la generazione manuale con `webauthn.BeginLogin(user, ...)`. Salvare il `SessionData`.
  - `FinishLogin`: Sostituire l'inutile update del `sign_count` manuale con `webauthn.FinishLogin(user, sessionData, r)`. Questa funzione riceverà la firma (`signature`), la verificherà con la chiave pubblica registrata, controllerà il clone-counter e restituirà il successo crittografico reale.

### Frontend Javascript

Il backend usando la libreria standard si aspetterà un payload JSON specifico che codifica i buffer binari. È pratica comune e consigliabile usare un wrapper o implementare le funzioni base per formattare la risposta del browser nel JSON atteso dal backend.
- **[MODIFY] `services/iam-service/templates/login.html`**:
  - Modificare la `fetch` per `/auth/login/finish`. Inviare tutti i parametri standard: `id`, `rawId`, `type`, e `response` (che deve contenere `authenticatorData`, `clientDataJSON`, `signature`, e facoltativamente `userHandle`).
- **[MODIFY] `services/business-logic/templates/reserved.html`**:
  - Modificare la `fetch` per `/auth/register/finish`. Inviare `id`, `rawId`, `type`, e `response` (che deve contenere `attestationObject` e `clientDataJSON` veri, decodificati dal browser).

## Verification Plan

### Test Manuali
1. Eliminare i dati correnti di test per WebAuthn e Device dal database MongoDB.
2. Registrare un nuovo utente e provare l'enrollment di un Security Key. Verificare che l'`attestationObject` venga accettato.
3. Fare il logout e provare il login tramite WebAuthn:
   - Verificare che inserendo credenziali fasulle o bypassando la firma Javascript, il server respinga la chiamata 400 Bad Request.
   - Verificare che il login reale funzioni e inneschi il fallback alla mail OTP, dimostrando che la crittografia ha funzionato correttamente.
