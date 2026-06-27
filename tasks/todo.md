# Secure WebAuthn Refactor — Todo

Refactoring delle cerimonie WebAuthn dell'iam-service per introdurre verifica
crittografica reale (go-webauthn) + hardening. Vedi `implementation_plan.md`.

## Checklist

- [x] Aggiungere `github.com/go-webauthn/webauthn` (v0.17.4) a iam-service
- [x] `config.go`: caricare RP config + secret, costruire `*webauthn.WebAuthn`
- [x] `models/user.go`: implementare l'interfaccia `webauthn.User`
- [x] `models/sessions.go`: `DeviceCredential` → `webauthn.Credential`; `WebAuthnChallenge` → `SessionData`
- [x] `db/device_repo.go`: `UpdateSignCount` → `UpdateCredential` (persiste la credenziale verificata)
- [x] `db/user_repo.go`: `MarkTPMEnrolled` solo flag booleano (niente `tpm_public_key`)
- [x] `webauthn/handler.go`: struct + costruttore con wa/rateLimits/enumSecret
- [x] `webauthn/register.go`: `BeginRegistration`/`FinishRegistration` via libreria, UV required, exclusions
- [x] `webauthn/login.go`: `BeginLogin`/`FinishLogin` via libreria, UV required, rate-limit, clone-reject
- [x] Anti user-enumeration: cerimonia fittizia deterministica (HMAC) per utenti sconosciuti
- [x] Trust boundary: header `X-Current-User` firmato HMAC (orchestrator) + validato (iam middleware)
- [x] `business-logic`: middleware che valida+strippa `X-Current-User`
- [x] Frontend `login.html`: assertion standard (id/rawId/type/response.*), session_id in query
- [x] Frontend `reserved.html`: attestation standard (attestationObject/clientDataJSON), session_id in query
- [x] `.env`/`.env.example`: documentare `WEBAUTHN_ENUM_SECRET`, `ORCH_IAM_SHARED_SECRET`, display name
- [x] Build + vet + test su iam-service, security-orchestrator, business-logic

## Review

### Cosa è cambiato
- **Core crypto**: registrazione e login ora delegano a go-webauthn la verifica di
  attestation/assertion. La chiave pubblica registrata viene effettivamente usata per
  verificare la firma; il sign-count è derivato dall'authenticator (non più auto-dichiarato)
  e un `CloneWarning` rifiuta il login.
- **Storage**: la verità crittografica vive in `device_fingerprints.credential`
  (`webauthn.Credential` completa). `credential_id`/`user_id` restano top-level perché la
  security-orchestrator interroga solo quella coppia (`tpm/lookup.go`). `MarkTPMEnrolled`
  non duplica più la chiave sull'utente.
- **Hardening**: `UserVerification: required` in entrambe le cerimonie; rate-limit per IP su
  login/{begin,finish} (riuso `RateLimitRepository`); risposta uniforme anti-enumeration con
  `allowCredentials` fittizie deterministiche; tutti i fallimenti di login → 400 generico.
- **Trust boundary**: `X-Current-User` firmato in HMAC dall'orchestrator (secret condiviso),
  validato dall'iam-service sulle rotte di enrollment e da business-logic. Nessuna modifica a
  Envoy (riusa l'header già inoltrato).

### Verifica eseguita
- `go build ./...` + `go vet ./...` OK sui tre moduli.
- Test BSON round-trip di `webauthn.Credential` e `SessionData` (PublicKey/ID/AAGUID/SignCount/
  AllowedCredentialIDs preservati): PASS — `internal/models/bsonroundtrip_test.go`.
- Test HMAC `X-Current-User` (accetta firma valida, rifiuta assente/manomessa/secret diverso):
  PASS — `internal/handler/usersig_test.go`.

### Da fare a runtime (test manuali, vedi implementation_plan.md §Verification)
- Svuotare `device_fingerprints` e `webauthn_challenges` (breaking change formato).
- Enroll reale, login reale → step-up OTP; firma fasulla → 400.
- Enumeration: `/login/begin` username inesistente vs senza-device indistinguibili.
- Richiesta diretta a `register/begin` con `X-Current-User` arbitrario → 401.
- Rate-limit: login ripetuti oltre soglia → 429.

### Note / raccomandazioni non implementate (fuori scope: solo Go+frontend)
- Isolamento L3/L4: la NetworkPolicy k8s per iam-service e l'isolamento compose su `auth-net`
  restano raccomandazioni documentate. Il secret HMAC è la mitigazione applicativa equivalente.
- In produzione impostare `ORCH_IAM_SHARED_SECRET` e `WEBAUTHN_ENUM_SECRET` (stesso valore del
  primo nei tre servizi); senza env si usano default da lab con warning.
