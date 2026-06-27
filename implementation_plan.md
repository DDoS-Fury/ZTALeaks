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

### Hardening Aggiuntivo

Oltre alla verifica crittografica (core), restano alcune debolezze non risolte dal solo switch a `go-webauthn`. Vanno affrontate per non lasciare residuo di attacco.

- **[MODIFY] `services/iam-service/internal/webauthn/login.go` — User enumeration in `BeginLogin`**:
  - Attualmente `begin` distingue `404 "user not found"` da `404 "no enrolled devices"`, rivelando esistenza/enrollment di un account. Restituire una risposta uniforme: per utenti sconosciuti o senza device, generare una `allowCredentials` **fittizia ma deterministica** (derivata in HMAC da username + secret server) e una challenge valida, così la risposta è indistinguibile dal caso reale. Mai 404 differenziati su `begin`.

- **[MODIFY] `services/iam-service/internal/webauthn/login.go` / `register.go` — `UserVerification`**:
  - Impostare `UserVerification: "required"` (non `"preferred"`) sia in login sia in registrazione: contesto centrale nucleare ZTA, il PIN/biometria sull'authenticator deve essere obbligatorio. Con `go-webauthn` si configura via `protocol.VerificationRequired` nelle opzioni della cerimonia.

- **[VERIFY] Trust boundary su `X-Current-User` (`register/begin`)**:
  - `BeginRegistration` si fida dell'header `X-Current-User` iniettato dalla security-orchestrator. Garantire a livello di network policy (k8s NetworkPolicy / config Envoy) che l'iam-service **non sia mai raggiungibile bypassando l'orchestrator**: altrimenti un attaccante spoofa l'header ed enrolla un device su un account arbitrario. Documentare/forzare il vincolo; in alternativa far validare all'iam-service un token interno firmato dall'orchestrator invece del semplice header.

- **[MODIFY] Rate limiting su `login/{begin,finish}`**:
  - Le rotte di login non hanno rate-limit (esiste la collection `rate_limits` con TTL ma non è usata in questo path). Aggiungere un limite per IP/username sulle cerimonie di login per impedire enumerazione e abuso scriptato.

- **[MODIFY] `services/iam-service/internal/db/user_repo.go` — `MarkTPMEnrolled`**:
  - Oggi salva sull'utente la **stringa base64** della public key mentre `devices.Create` salva i byte decodificati: incoerenza. Con il refactor a `go-webauthn` la public key vive nella `webauthn.Credential` dentro `device_fingerprints`; ridurre `MarkTPMEnrolled` al solo flag booleano `has_tpm=true` (niente duplicazione della chiave sull'utente) o allineare il formato.

- **[NOTE] `AAGUID` / `attestation_type`**:
  - Con la verifica dell'attestation reale, `AAGUID` e `attestation_type` provengono dall'`attestationObject` validato e non più da campi JSON arbitrari del client. Se in futuro si vuole una allowlist di modelli di authenticator, basarla solo sull'AAGUID estratto dall'attestation verificata, mai su input del client.

## Verification Plan

### Test Manuali
1. Eliminare i dati correnti di test per WebAuthn e Device dal database MongoDB.
2. Registrare un nuovo utente e provare l'enrollment di un Security Key. Verificare che l'`attestationObject` venga accettato.
3. Fare il logout e provare il login tramite WebAuthn:
   - Verificare che inserendo credenziali fasulle o bypassando la firma Javascript, il server respinga la chiamata 400 Bad Request.
   - Verificare che il login reale funzioni e inneschi il fallback alla mail OTP, dimostrando che la crittografia ha funzionato correttamente.

### Test Hardening Aggiuntivo
4. **User enumeration:** chiamare `/login/begin` con uno username inesistente e uno esistente-ma-senza-device; verificare che le risposte (status code, presenza/forma di `allowCredentials`, timing) siano indistinguibili dal caso reale.
5. **User Verification:** verificare che una cerimonia senza UV (authenticator senza PIN/biometria) venga rifiutata dal backend.
6. **Trust boundary:** confermare che una richiesta diretta a `register/begin` con `X-Current-User` arbitrario (bypassando l'orchestrator) venga bloccata a livello di rete / token interno.
7. **Rate limiting:** verificare che ripetute `login/begin` oltre soglia per IP/username vengano limitate (429).
