# Trasposizione `zta-core` → `mix-master-zta-core`

> **Branch**: `mix-master-zta-core` (cut da `master` 2026-05-09)
> **Scopo**: portare l'implementazione Zero Trust della branch `zta-core` su `master`, ma seguendo le direttive architetturali ricevute (split identity-service / security-orchestrator, OPA come unico decisore ruolo↔rotta, ammissione a 3 tier) e preservando ciò che master aveva già di buono (Splunk, IDS, Argon2id).
> **Stato**: 7 step su 7 completati + 3 commit di follow-up post-review (refactor 2026-05-10) tutti pushati.

---

## Indice

1. [Sommario](#1-sommario)
2. [Direttive del compagno (testo originale)](#2-direttive-del-compagno-testo-originale)
3. [Decisioni architetturali](#3-decisioni-architetturali)
4. [Architettura risultante](#4-architettura-risultante)
5. [Step 0 — Schema Security DB + .env](#5-step-0--schema-security-db--env)
6. [Step 1 — Identity Service](#6-step-1--identity-service)
7. [Step 2 — Security Orchestrator](#7-step-2--security-orchestrator)
8. [Step 3 — OPA Policy](#8-step-3--opa-policy)
9. [Step 4 — Envoy](#9-step-4--envoy)
10. [Step 5 — Business Logic (verifica)](#10-step-5--business-logic-verifica)
11. [Step 6 — Suite E2E](#11-step-6--suite-e2e)
12. [Step 7 — CI](#12-step-7--ci)
13. [Mappa file modificati / aggiunti](#13-mappa-file-modificati--aggiunti)
14. [Come eseguire localmente](#14-come-eseguire-localmente)
15. [Open items e lavoro futuro](#15-open-items-e-lavoro-futuro)
16. [Riferimento commit](#16-riferimento-commit)

---

## 1. Sommario

`zta-core` aveva implementato uno stack ZTA completo ma in un unico monolite (`security-orchestrator` con dentro auth + JWT + WebAuthn + ext_authz), con HS256 di identity-service deprecato e cancellato. `master` aveva mantenuto identity-service vivo e aggiunto IDS + Splunk, ma con `policy.rego` stub (`allow if true`) e `security-orchestrator` placeholder che restituiva `risk_score = 0.2`. Le due branch erano divergenti, mai mergiate.

La trasposizione su `mix-master-zta-core` ha ricostruito lo stack ZTA seguendo lo split richiesto dal compagno:

- **identity-service** — emette JWT, gestisce registrazione/login/OTP/WebAuthn enrollment.
- **security-orchestrator** — verifica il token, controlla il certificato, fa il lookup del TPM e passa l'input a OPA.
- **OPA** — unico decisore ruolo↔rotta, clearance, e tier di ammissione.
- **business-logic** — invariata: master non aveva role check, in linea con la direttiva "OPA decide".

Tutto il resto del master (Splunk, IDS, Argon2id, schema User con campi TPM) è stato preservato.

Risultato: pipeline `client → firewall+nftables → Envoy (mTLS opzionale, JA3) → ext_authz → security-orchestrator (JWT verify + cert parse + TPM lookup) → OPA (decisione) → upstream (identity-service o business-logic)` end-to-end funzionante. Suite E2E con 26 scenari verdi e CI con 3 job (`opa-tests` → `build-images` → `e2e-tests`).

---

## 2. Direttive del compagno (testo originale)

> Allora di base per autenticazione, autorizzazione, token jwt, tpm con webauth vanno divise tra security orchestrator e identity service che condividono il security db.
> Le regole tra risorse/rotte e ruoli va controllata in opa.
> Il security orchestrator si occupa di:
> - verificare il token ed estrarne le info
> - verificare il tpm usando il db e dare le info ad opa
> - controllo del certificato
>
> Mentre l'identity:
> - gestire le rotte di registrazione e login
> - rilasciare i token dopo il login
> - memorizzare le info tpm dopo la registrazione
>
> Noi ammettiamo utenti con:
> - certificato e tpm
> - solo certificato
> - senza niente.

Tutto ciò che segue è derivato da queste 13 righe.

---

## 3. Decisioni architetturali

Nove punti risolti prima di scrivere codice (con il compagno via "non prendere iniziative, chiedi"):

| # | Punto | Scelta | Motivazione |
|---|-------|--------|-------------|
| 1 | Algoritmo JWT | **RS256 + JWKS** | Permette a security-orchestrator di verificare con la sola public key esposta da identity-service su `/.well-known/jwks.json`. Niente shared secret. |
| 2 | "TPM con WebAuth" | **WebAuthn / FIDO2** vero, con `device_fingerprints` collection | Letteralmente quello che la direttiva intendeva; identity gestisce begin/finish e popola la collection, orchestrator fa solo lookup read-only. |
| 3 | Tier "senza niente" | **Username + password + OTP, senza cert e senza TPM** | "Senza niente" si riferisce ai due fattori hardware (cert e TPM); l'autenticazione di base resta obbligatoria. Non utenti anonimi. |
| 4 | OTP via email | **Mantenuto** (MailHog in dev) | La direttiva non lo nominava esplicitamente, ma il flusso pwd → OTP → JWT era già su `zta-core` e aggiunge un fattore di MFA al tier "niente". |
| 5 | Clearance vs document filtering | **(A) clearance dentro, (B) doc filtering fuori** | Clearance è ortogonale ai 3 tier ed è naturale ABAC. Document filtering per `applicable_roles` rimette logica in business-logic, contro la direttiva "OPA decide". |
| 6 | Nomi DB | **`securitydb` / `identity_users`** (master) | Meno modifiche, allineato a quanto identity-service master già usa. zta-core usava `security_db` / `users`. |
| 7 | Chiave RSA JWT | **Ephemeral a startup di identity-service** | Semplice, dev-friendly. Trade-off: i token vengono invalidati a ogni restart. In produzione: Vault/KMS. |
| 8 | Granularità commit | **1 commit locale per step**, no push fino a fine | Storia leggibile, rollback chiaro. Rispetto alla mega-commit `4a400ab` di zta-core. |
| 9 | MailHog | **Nuovo servizio in compose**, su `auth-net` | Web UI 8025 per ispezionare gli OTP durante i test. |

Cosa **abbiamo preservato di master** (non rinegoziato):

- Splunk + splunk-uf + `infra/splunk-uf/{inputs,outputs}.conf` — observability.
- Argon2id come hash password (più moderno di bcrypt di zta-core).
- Schema `User` con `HasTPM`, `TPMPublicKey`, `SecureEnclaveValid` già pronti.
- Snort + snort-internal + nftables firewall.
- ext_authz **HTTP** (non gRPC come zta-core) verso orchestrator — meno invasivo, già rodato.

---

## 4. Architettura risultante

### 4.1 Componenti

| Componente | Ruolo ZTA | Tecnologia | Porta |
|------------|-----------|------------|-------|
| **firewall** | Network filtering pre-Envoy | nftables | shares 8443 |
| **envoy** | PEP — TLS termination + JA3 + ext_authz dispatch | Envoy proxy | 8443 (via firewall) |
| **snort / snort-internal** | NIDS passive monitoring | Snort | shared netns |
| **identity-service** | Issuer JWT — register, login, OTP, WebAuthn, JWKS | Go 1.25 | 8082 |
| **security-orchestrator** | PDP coordinator — JWT verify, cert parse, TPM lookup, OPA call | Go 1.26 | 8081 (HTTP), [9090 reserved gRPC] |
| **opa** | PDP — Rego policy engine | OPA `latest-envoy` | 8181 |
| **security-db** | Storage credenziali, OTP, JWT blocklist, device fingerprints, audit | MongoDB 7 | 27017 (auth-net only) |
| **business-logic** | CRUD risorse plant nucleare | Go | 8080 (back-net) |
| **business-db** | Dati di business | MongoDB 6 | 27017 (back-net only) |
| **mailhog** | SMTP dev + UI per ispezionare OTP | MailHog | 1025 SMTP, 8025 UI |
| **splunk + splunk-uf** | Centralized log forwarding | Splunk | 8000 UI, 8088 HEC, 9997 |
| **seeder** | Popola business-db con dati di test | Go (one-shot) | n/a |

### 4.2 Reti Docker

Tre network isolate enforce la microsegmentazione NIST 800-207:

- **front-net** — Envoy (via firewall) e security-orchestrator. Esterna verso il client.
- **auth-net** — security-orchestrator, identity-service, security-db, opa, mailhog. Privata.
- **back-net** — business-logic, business-db, seeder, Splunk. La business-db **non** è raggiungibile dall'esterno né dalla auth-net.

Il `firewall` joina sia front-net che back-net (per logging anche del traffico verso business-db). Envoy gira in `network_mode: service:firewall` e quindi condivide il namespace di rete con il firewall.

### 4.3 Flusso di una richiesta protetta

```
[client] ─https-mTLS opt.→ [firewall:8443] → [Envoy]
                                                │
                                                │ (TLS Inspector → JA3)
                                                │ (TLS termination, set XFCC se cert)
                                                │
                            ┌─── /api/v1/auth/* ──────→ [identity-service]
                            ├─── /.well-known/* ──────→ [identity-service]
                            │
                            └─── /api/v1/* (else) ──→ ext_authz HTTP service
                                                          │
                                                          ▼
                                                 [security-orchestrator]
                                                  ├─ Verify JWT (JWKS cache)
                                                  ├─ Parse XFCC header
                                                  ├─ Lookup device_fingerprints
                                                  └─ POST OPA con input arricchito
                                                          │
                                                          ▼
                                                       [OPA]
                                                  data.envoy.authz.allow
                                                          │
                                              ┌───────────┴───────────┐
                                              ▼                       ▼
                                          allow=true             allow=false
                                              │                       │
                                              ▼                       ▼
                                  Envoy → [business-logic]      403 al client
                                              │
                                              ▼
                                       Risposta al client
```

### 4.4 Ammissione a 3 tier

L'orchestrator passa a OPA due booleani: `cert_present` e `tpm_verified`. La policy li combina:

```
cert_present  tpm_verified  →  user_tier
─────────────────────────────────────────
    false          *         →     0      "senza niente"
    true         false       →     1      "solo certificato"
    true          true       →     2      "certificato + TPM"
```

Ogni rotta della matrice dichiara `min_tier`. La regola di allow include `user_tier >= rule.min_tier` come una delle 4 condizioni AND.

---

## 5. Step 0 — Schema Security DB + .env

**Commit**: `ba91c84 feat(security-db): schema for OTP, JWT blocklist, WebAuthn, audit`

### 5.1 Cosa è cambiato in `infra/databases/security/db_init/security-init.js`

Da una sola collezione vuota (`identity_users`) a sei collezioni con indici e TTL Mongo:

| Collezione | Index | TTL |
|------------|-------|-----|
| `identity_users` | unique `username`, unique sparse `email` | – |
| `otp_sessions` | unique `session_token`, TTL su `created_at` | 300s (5 min) |
| `jwt_blocklist` | unique `jti`, TTL su `revoked_at` | 90000s (25h) |
| `device_fingerprints` | unique `credential_id`, index `user_id` | – |
| `webauthn_challenges` | unique `session_id`, TTL su `created_at` | 300s |
| `auth_events` | desc `timestamp`, compound `(user_id, timestamp)`, `event_type` | – |

I TTL Mongo (`expireAfterSeconds`) garantiscono auto-cleanup degli OTP scaduti, dei JWT revocati e delle challenge WebAuthn senza bisogno di un job esterno.

Le collezioni sono create vuote: gli utenti seed sono inseriti dal **identity-service** in Go, perché Argon2id non è disponibile nello shell `mongosh`.

### 5.2 Cosa è cambiato in `.env`

Aggiunte 12 variabili per i nuovi servizi:

```env
SECURITY_ORCHESTRATOR_PORT=8081
SECURITY_DB_URI=mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin
SECURITY_DB_NAME=securitydb
IDENTITY_SERVICE_PORT=8082
IDENTITY_JWKS_URL=http://identity-service:8082/.well-known/jwks.json
SMTP_HOST=mailhog
SMTP_PORT=1025
SMTP_FROM=noreply@ztaleaks.local
WEBAUTHN_RP_ID=ztaleaks.local
WEBAUTHN_RP_ORIGIN=https://ztaleaks.local:8443
```

### 5.3 Caveat

Durante lo step 0 il volume `docker_security-db-data` conteneva dati lasciati da una vecchia run di `zta-core` (DB chiamato `security_db` con underscore). Dato che il volume non era vuoto, l'entrypoint mongo ha saltato la creazione del root user → auth fail. Risoluzione: drop volumetrico solo di `docker_security-db-data` (non `down -v` per preservare Splunk e business-db). Da quel momento il volume parte fresh con il nostro init.

---

## 6. Step 1 — Identity Service

**Commit**: `cd57fab feat(identity): RS256 JWT, JWKS, OTP via MailHog, WebAuthn ceremony, multi-role seed`

### 6.1 Cambio JWT da HS256 a RS256

Master firmava con HS256 e secret hardcoded `"ZTA-Secrets-Should-Be-Isolated"`. Inutilizzabile per uno split: l'orchestrator dovrebbe condividere il secret. Sostituito con RS256 + chiave RSA-2048 ephemeral generata a startup.

`internal/crypto/jwt.go` espone:

```go
type JWTManager struct {
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
    keyID      string  // SHA-256 dei primi 8 byte del modulo
}

type ZTAClaims struct {
    UserID         string `json:"sub"`
    Role           string `json:"role"`
    ClearanceLevel string `json:"clearance_level"`
    MFAVerified    bool   `json:"mfa_verified"`
    DeviceID       string `json:"device_id,omitempty"`
    JA3            string `json:"ja3,omitempty"`
    jwt.RegisteredClaims
}

const AccessTokenTTL = 15 * time.Minute
const Issuer = "identity-service.ztaleaks.local"
```

Il `kid` viene messo nell'header del JWT e serve all'orchestrator per scegliere la chiave giusta dal JWKS quando ne ricicliamo più di una in futuro.

### 6.2 JWKS endpoint

`internal/crypto/jwks.go` espone `GET /.well-known/jwks.json` con format RFC 7517:

```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "b5ca23f7d1e70188",
    "n": "<modulus base64url>",
    "e": "AQAB"
  }]
}
```

Cache header `max-age=300` per 5 min lato client.

### 6.3 Repository split

Master aveva un solo `repository.go` con `UserRepository`. Ora ci sono 4 repository, uno per collezione, ognuno nel suo file:

- `db/user_repo.go` — `FindByUsername`, `FindByID`, `Create`, `UpdateLastLogin`, `MarkTPMEnrolled`
- `db/otp_repo.go` — `Create`, `ConsumeAttempt` (atomic FindOneAndUpdate), `Delete`
- `db/device_repo.go` — `Create`, `FindMostRecentByUser`, `FindByCredentialID`, `UpdateSignCount`, `ListByUser`
- `db/challenges_repo.go` — `Create`, `FindBySessionID`, `Delete`
- `db/repositories.go` — `Repositories` bundle + `InitRepositories(*MongoDB)` (refactor 2026-05-10, allinea pattern business-logic)

`FindMostRecentByUser` è il punto cardine: al verify-otp, identity guarda se l'utente ha un device WebAuthn enrollato e ne mette il `credential_id` nel claim `device_id` del JWT. Sarà l'orchestrator a verificare poi che quel device esista ancora in DB.

### 6.4 Auth flow (handler/{register,login,verify_otp}.go)

> Nota refactor 2026-05-10: il monolite `handler/api.go` e' stato splittato
> in `handler.go` (struct `IdentityAPI` + helpers condivisi), `register.go`,
> `login.go`, `verify_otp.go`. Le rotte sono ora montate da `Router` in
> `handler/routes.go` (pattern allineato a `business-logic`).

Tre endpoint:

#### `POST /api/v1/auth/register`
```json
Request: {"username", "email", "password", "role", "clearance_level"}
Response 201: {"status":"registered","user_id":"<ObjectId hex>"}
```

Hash Argon2id (master), inserimento in `identity_users`. Idempotenza tramite check su `username` (unique index).

#### `POST /api/v1/auth/login` (step 1 di 2)
```json
Request: {"username","password"}
Response 200: {"status":"otp_required","session_token":"<48 hex>","message":"OTP inviato all'email registrata"}
```

1. Lookup user, fallback a hash dummy se non trovato (anti-timing).
2. `crypto.ComparePasswordAndHash` con Argon2id.
3. Genera OTP a 6 cifre via `crypto/rand`.
4. Hash dell'OTP con Argon2id e salva in `otp_sessions` con `attempts=0`.
5. `mailer.SendOTP(user.Email, otp)` → MailHog.
6. Ritorna `session_token` (cleartext OTP non lascia mai memoria/email).

#### `POST /api/v1/auth/verify-otp` (step 2 di 2)
```json
Request: {"session_token","otp"}
Response 200: {"access_token":"<JWT RS256>","expires_in":900,"token_type":"Bearer"}
```

1. **`ConsumeAttempt`** (refactor 2026-05-10): unica `FindOneAndUpdate` con
   filtro `{session_token, attempts: {$lt: 3}}` + update `$inc:{attempts:1}`.
   Restituisce il documento aggiornato. Sentinel: `ErrSessionNotFound`
   (sessione assente o scaduta dal TTL) e `ErrAttemptsExceeded` (limite
   raggiunto). Cosi' check del limite e increment sono **una sola
   operazione atomica sul DB** — niente race window come nella precedente
   versione che faceva `FindBySessionToken` + `IncrementAttempts` separate.
2. `crypto.ComparePasswordAndHash(otp, session.OTPHash)`.
3. Se match: cancella session, lookup user, lookup `device_fingerprints` per ottenere `device_id` se enrollato, emette JWT con tutti i claim.
4. Update last_login_info in goroutine background.

### 6.5 WebAuthn ceremony (lab-grade)

> Nota refactor 2026-05-10: il monolite `internal/webauthn/webauthn.go` e'
> stato splittato in `handler.go` (struct `Handler` + helpers condivisi),
> `register.go` (cerimonia di enrollment TPM) e `login.go` (cerimonia di
> autenticazione con device gia' registrato). Il `Handler` non ha piu'
> `JWTManager` come dipendenza — la verifica del JWT vive solo
> nell'orchestrator.

I due file espongono cerimonia di registrazione e di authentication. Versione semplificata per lab — non fa CBOR-decoding completo dell'attestation object. Ciò che fanno:

#### `POST /api/v1/auth/register/begin`
```json
Request: {"device_name":"laptop-tpm"}
Header:  Authorization: Bearer <JWT>
Response: PublicKeyCredentialCreationOptions (challenge 32B random, rp, user, pubKeyCredParams ES256+RS256, session_id)
```

L'identità dell'utente e' letta dall'header `X-Current-User` iniettato dalla
security-orchestrator dopo la verifica del JWT (refactor 2026-05-10:
prima il JWT veniva passato in body e verificato in identity con un
`JWTManager.Verify` locale, ora rimosso). Salva una `WebAuthnChallenge`
in DB per validare il `finish`.

#### `POST /api/v1/auth/register/finish`
```json
Request: {"session_id","credential_id","public_key" (b64),"attestation_type","aaguid"}
Response 200: {"status":"registered","credential_id":"..."}
```

1. Risolve la challenge dal session_id (TTL 5 min).
2. Inserisce `DeviceCredential` in `device_fingerprints`.
3. Marca `user.has_tpm=true` e salva la public_key.
4. Cancella la challenge.

#### `POST /api/v1/auth/login/begin` e `/finish`
Cerimonia di authentication classica con clone detection: il finish legge `sign_count` dal client, lo confronta col valore salvato e segnala `clone_suspected: true` se regredisce. Update `last_used_at`. Out of scope OPA per ora — il flag è disponibile come hook futuro.

### 6.6 Mailer

`internal/mailer/mailer.go` è un wrapper minimal su `net/smtp`. Niente auth, niente TLS (MailHog non li richiede). Email in HTML con il codice in span ingrandito:

```html
<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px; padding: 16px;
          background:#f5f5f5; border-radius:8px; text-align:center;">123456</p>
```

I 6 caratteri tra `>` e `<` sono il pattern che lo script E2E usa per estrarre l'OTP via regex.

### 6.7 Multi-role seed (internal/seed/users.go)

> Nota refactor 2026-05-10: la funzione `seedUsers` viveva in `cmd/identity/main.go`.
> Spostata in `internal/seed/users.go` come funzione `seed.Users(*db.UserRepository)`.
> Il main ora si limita a chiamarla. Hash Argon2id resta in Go (impossibile
> calcolarlo nello shell mongo).

Loop che inserisce 6 utenti, uno per ogni role del dominio nucleare:

| username | role | clearance |
|----------|------|-----------|
| `admin` | plant_manager | TOP_SECRET |
| `operator1` | operator | CONFIDENTIAL |
| `maint_tech1` | maintenance_technician | INTERNAL |
| `rad_officer1` | radiation_protection_officer | SECRET |
| `sec_officer1` | security_officer | SECRET |
| `inspector1` | inspector | SECRET |

Tutti con password `admin123` hashata Argon2id. Idempotente tramite unique index su username (i seed succede silenziosamente se l'utente esiste).

### 6.8 docker-compose: nuovo servizio mailhog

```yaml
mailhog:
  image: mailhog/mailhog:latest
  container_name: ztaleaks_mailhog
  ports:
    - "8025:8025"   # Web UI
  restart: unless-stopped
  networks:
    - auth-net
```

`identity-service` dipende ora da mailhog: `condition: service_started`. La porta 8082 è esposta sull'host **temporaneamente** per i test diretti — in produzione le richieste passano solo via Envoy.

### 6.9 Refactor 2026-05-10 — pulizia main + atomic OTP + drop JWT verify

Tre commit di follow-up applicati dopo la review del compagno (i 7 punti del
messaggio originale di review). Riepilogo strutturale, dettagli sparsi nelle
sotto-sezioni precedenti:

| Punto review | Modifica |
|---|---|
| seed in file dedicato (Go) | `internal/seed/users.go` (vedi §6.7) |
| pulizia `main.go` come business-logic | nuovo `config/config.go` (env vars + connect Security DB) e `internal/db/repositories.go` (bundle `Repositories` + `InitRepositories`); `main.go` ridotto a ~85 righe — solo wiring |
| split handler in 3 file | `handler/api.go` → `handler.go`/`register.go`/`login.go`/`verify_otp.go` (vedi §6.4) |
| split webauthn login/register | `webauthn/webauthn.go` → `handler.go`/`register.go`/`login.go` (vedi §6.5) |
| routing fuori dal main | `handler/routes.go` con `Router{API, WebAuthn, JWT}.RegisterRoutes(mux)` |
| OTP verify atomico | `OTPRepository.ConsumeAttempt` con `FindOneAndUpdate` (vedi §6.4) |
| rimuovere JWT verify da identity | `JWTManager.Verify` cancellato da `internal/crypto/jwt.go`; `BeginRegistration` ora legge `X-Current-User` (vedi §6.5) |

Effetti collaterali in altri componenti:
- **OPA policy** — `/api/v1/auth/register/begin` rimosso da `public_paths`
  e aggiunto in `route_rules` con `min_tier=0`/`min_clearance=PUBLIC`/tutti
  i 6 ruoli ammessi (perche' richiede ora `X-Current-User`, header che
  l'orchestrator inietta solo dopo verifica JWT). Vedi §8.1.
- **security-orchestrator** — eliminato il bypass `publicPaths` locale
  (vedi §7.7), ora la decisione vive solo in OPA.

### 6.10 Test end-to-end (12 scenari)

```bash
# JWKS shape
curl http://localhost:8082/.well-known/jwks.json | jq .keys[0].kid

# Login → MailHog → verify-otp → JWT decode
curl -X POST .../auth/login -d '{"username":"admin","password":"admin123"}'
# → {"status":"otp_required","session_token":"..."}
curl http://localhost:8025/api/v2/messages  # estrai OTP a 6 cifre dal body
curl -X POST .../auth/verify-otp -d '{"session_token":"...","otp":"123456"}'
# → access_token RS256 con sub/role/clearance/mfa_verified/iss

# WebAuthn register (con JWT come access_token)
curl -X POST .../auth/register/begin -d '{"access_token":"<JWT>","device_name":"x"}'
curl -X POST .../auth/register/finish -d '{"session_id":"...","credential_id":"...","public_key":"..."}'

# Login successivo: il JWT contiene device_id
```

Tutti i 12 scenari (positivi e negativi: OTP errato, password errata, register nuovo) verdi.

---

## 7. Step 2 — Security Orchestrator

**Commit**: `5770078 feat(orchestrator): JWT verify (JWKS), cert parse, TPM lookup, OPA call`

### 7.1 Cosa c'era prima

Master aveva un placeholder con:
- `getAIRiskScore()` che restituiva `0.2` fisso.
- `/api/v1/evaluate` che mandava `{risk_score, request:{path,method}}` a OPA.
- `/api/v1/opa/logs` per ricevere decision logs gzipped da OPA.
- `/health`.

Niente JWT, niente DB, niente cert, niente TPM. `go.mod` letteralmente solo `module ... go 1.26`.

### 7.2 Cosa c'è ora

5 pacchetti interni cablati nel main:

```
services/security-orchestrator/
├── cmd/orchestrator/main.go        # wiring + 3 endpoint HTTP
└── internal/
    ├── jwt/verifier.go             # JWKS fetch + RS256 verify
    ├── cert/cert.go                # parse x-forwarded-client-cert
    ├── db/mongo.go                 # client securitydb read-only
    ├── tpm/lookup.go               # device_fingerprints lookup
    └── opa/client.go               # POST OPA con input arricchito
```

### 7.3 JWT Verifier (internal/jwt/verifier.go)

```go
type Verifier struct {
    jwksURL    string
    httpClient *http.Client
    mu         sync.RWMutex
    keysByKID  map[string]*rsa.PublicKey
    cachedAt   time.Time
}
```

- **JWKS fetch**: `GET ${IDENTITY_JWKS_URL}` (default `http://identity-service:8082/.well-known/jwks.json`). Parsing del JSON Web Key Set, conversione `n` (base64url) → `big.Int` e `e` → `int`, costruzione `rsa.PublicKey`.
- **Cache 5 min**: se `time.Since(cachedAt) < 5min` riusa la chiave già caricata, altrimenti refresh.
- **kid-based lookup**: l'header del JWT contiene `kid`, il verifier cerca quel `kid` nella mappa.
- **Verify**: usa `golang-jwt/jwt/v5` con `WithValidMethods([]string{"RS256"})`. Errori JWT → 401 immediato (no OPA call).

### 7.4 Cert parser (internal/cert/cert.go)

Envoy con `forward_client_cert_details: SANITIZE_SET` inietta l'header `x-forwarded-client-cert` quando il client presenta un certificato durante l'handshake. Il formato è:
```
By=spiffe://...;Hash=abc123;Subject="CN=admin,O=ZTALeaks";URI=...;DNS=...
```

Il parser è un semplice splitter su `;` che estrae i campi key=value. Restituisce:

```go
type ClientCert struct {
    Present bool    // header non vuoto
    Subject string  // valore di Subject= (rimosse virgolette)
    Hash    string  // valore di Hash=
}
```

Per il tier admission basta `Present`. `Subject` e `Hash` finiscono in audit log.

### 7.5 TPM Lookup (internal/tpm/lookup.go)

```go
func (l *Lookup) Verify(ctx context.Context, userID, credentialID string) bool {
    if userID == "" || credentialID == "" { return false }
    count, err := l.coll.CountDocuments(ctx, bson.M{
        "credential_id": credentialID,
        "user_id":       userID,
    })
    return count > 0
}
```

`tpm_verified=true` sse esiste un documento in `device_fingerprints` con la coppia `(credential_id, user_id)` corrispondente al claim del JWT. La verifica include il `user_id` per evitare che un attacker possa rivendicare un device altrui mettendolo nel claim.

### 7.6 OPA client (internal/opa/client.go)

```go
type Input struct {
    Request      Request          `json:"request"`
    Claims       map[string]any   `json:"claims"`
    CertPresent  bool             `json:"cert_present"`
    CertSubject  string           `json:"cert_subject,omitempty"`
    TPMVerified  bool             `json:"tpm_verified"`
    ZoneID       string           `json:"zone_id,omitempty"`
}
```

`POST http://opa:8181/v1/data/envoy/authz/allow` con `{"input": <Input>}`. Risposta `{"result": bool}`. Timeout 2s. **Default deny**: ogni errore HTTP/parse → l'orchestrator nega.

### 7.7 Handler ext_authz (cmd/orchestrator/main.go)

```go
mux.HandleFunc("/api/v1/evaluate", evaluate)
mux.HandleFunc("/api/v1/evaluate/", evaluate)
mux.HandleFunc("/", evaluate)  // catch-all per gestire path_prefix di Envoy
```

Pipeline interno (refactor 2026-05-10: rimosso il bypass `publicPaths`
locale — la decisione su quali rotte siano pubbliche e' interamente delegata
a OPA, vedi §8.1):

1. **Path original**: Envoy ext_authz HTTP service con `path_prefix: /api/v1/evaluate` invoca l'orchestrator con URL tipo `/api/v1/evaluate/api/v1/auth/login`. L'orchestrator strippa il prefisso → `origPath = /api/v1/auth/login`.
2. **Estrai Bearer token** da `Authorization`. Se assente, mandiamo comunque il caso a OPA con `claims=null` (le rotte pubbliche sono autoriz­zate da OPA via `public_paths`; per rotte protette OPA rifiuta perche' il rule richiede `input.claims.sub`).
3. **Verify JWT** via JWKS verifier. Errore → 401 (Envoy non logga ancora la decisione OPA — è un fail prima).
4. **Parse cert** dall'header XFCC.
5. **TPM lookup**: cerca il `claims.device_id` in `device_fingerprints` con user_id matching.
6. **Build OPA input** completo. Chiama OPA.
7. **Rispondi**: 200 con header `x-current-user: <user_id>` (Envoy lo iniettea upstream) se allow, 403 con body JSON se deny.

### 7.8 Endpoint preservati dal master

- **`/health`** — `{"status":"ok","service":"security-orchestrator"}`.
- **`/api/v1/opa/logs`** — riceve `decision_logs` di OPA (configurato in `docker-compose.yaml` con `--set=services.orchestrator.url=http://security-orchestrator:8081/api/v1/opa`). Decompressi gzip se presente, scritti su `/var/log/ztaleaks/orchestrator/opa_decision.jsonl` per Splunk forwarding.

### 7.9 go.mod e Dockerfile

```
require (
    github.com/golang-jwt/jwt/v5 v5.3.1
    go.mongodb.org/mongo-driver v1.17.9
)
```

Dockerfile riordinato: `COPY .` prima di `go mod tidy && go mod download` così il tidy può vedere gli import e generare `go.sum` al volo (nessun `go.sum` committato).

---

## 8. Step 3 — OPA Policy

**Commit**: `362c2b0 feat(opa): role-route matrix, clearance, 3-tier admission + tests`

### 8.1 Struttura policy.rego

Pacchetto `envoy.authz` (matched dal binding `data.envoy.authz.allow` nell'orchestrator). `default allow := false`.

5 sezioni logiche:

#### Public paths
```rego
public_paths := {
    "/", "/health", "/login", "/register", "/materials",
    "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/verify-otp",
    "/api/v1/auth/register/finish",
    "/api/v1/auth/login/begin",    "/api/v1/auth/login/finish",
    "/.well-known/jwks.json",
}

allow if { input.request.path in public_paths }
allow if { startswith(input.request.path, "/static/") }
```

> Refactor 2026-05-10: `/api/v1/auth/register/begin` non e' piu' pubblica.
> Richiede `X-Current-User` iniettato dall'orchestrator dopo verifica JWT,
> quindi e' stata spostata in `route_rules` (vedi tabella sotto) con
> `min_tier=0`/`min_clearance=PUBLIC` e tutti i 6 ruoli ammessi: enrollment
> TPM aperto a qualunque utente con sessione valida.

Refactor 2026-05-10: e' stato anche rimosso il bypass `publicPaths` locale
nell'orchestrator — la decisione su quali rotte siano pubbliche vive ora
solo qui in OPA. Niente piu' divergenza possibile tra le due liste.

#### Tier admission
```rego
user_tier := 2 if { input.cert_present; input.tpm_verified }
user_tier := 1 if { input.cert_present; not input.tpm_verified }
user_tier := 0 if { not input.cert_present }
```

Tre rule head con la stessa firma — Rego v1 risolve a prima che matcha.

#### Clearance hierarchy
```rego
clearance_order := {
    "PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3, "TOP_SECRET": 4
}
```

Confronto in allow: `clearance_order[input.claims.clearance_level] >= clearance_order[rule.min_clearance]`.

#### Route matrix
La matrice è un dizionario hardcoded in policy.rego. Per ognuna delle 7 risorse business, 4 metodi (GET/POST/PUT/DELETE), ciascuno con `{roles, min_tier, min_clearance}`:

| Rotta | Metodo | Roles | min_tier | min_clearance |
|-------|--------|-------|----------|----------------|
| /api/v1/auth/register/begin | POST | tutti i 6 ruoli | 0 | PUBLIC |
| /personnel | GET | security_officer, plant_manager, inspector | 1 | INTERNAL |
| /personnel | POST/PUT/DELETE | plant_manager | 2 | SECRET |
| /zones | GET | tutti i 6 ruoli | 0 | PUBLIC |
| /zones | POST/PUT/DELETE | plant_manager | 2 | SECRET |
| /badges | GET | security_officer, plant_manager, inspector | 1 | INTERNAL |
| /badges | POST/PUT/DELETE | plant_manager | 2 | CONFIDENTIAL |
| /reactor-parameters | GET | operator, plant_manager, inspector | 1 | CONFIDENTIAL |
| /reactor-parameters | POST/PUT/DELETE | plant_manager | 2 | SECRET |
| /maintenance-orders | GET/POST/PUT | maintenance_technician, plant_manager | 1 | INTERNAL |
| /maintenance-orders | DELETE | maintenance_technician, plant_manager | 2 | CONFIDENTIAL |
| /documents | GET | tutti i 6 ruoli | 0 | PUBLIC |
| /documents | POST/PUT/DELETE | plant_manager | 2 | CONFIDENTIAL |
| /nuclear-materials | GET | plant_manager, inspector, radiation_protection_officer | 2 | SECRET |
| /nuclear-materials | POST/PUT/DELETE | plant_manager | 2 | TOP_SECRET |

#### Path matching con sub-resource

Il `matched_route` riconosce sia path esatto sia path con suffisso `/{id}`:

```rego
matched_route := key if {
    some key, _ in route_rules
    input.request.path == key
}
matched_route := key if {
    some key, _ in route_rules
    startswith(input.request.path, concat("", [key, "/"]))
}
```

Così `/api/v1/personnel/EMP-001` matcha la regola di `/api/v1/personnel`.

#### Allow principale
```rego
allow if {
    input.claims.sub                              # JWT presente
    rule := route_rules[matched_route][input.request.method]
    user_tier >= rule.min_tier                    # tier OK
    input.claims.role in rule.roles               # role OK
    clearance_order[input.claims.clearance_level] >= clearance_order[rule.min_clearance]
}
```

### 8.2 data.json

Solo zone metadata, tenuto come hook futuro:

```json
{
  "zones": {
    "ZONE-MAIN":   {"ztna_policy": {"min_tier": 0, "require_mfa": true}},
    "ZONE-CR-01":  {"ztna_policy": {"min_tier": 1, "require_mfa": true}},
    "ZONE-RC-01":  {"ztna_policy": {"min_tier": 2, "require_mfa": true}},
    ...
  }
}
```

L'attuale rule di allow non lo legge (out of scope). Il compose monta `data.json` come secondo file di OPA (oltre a `policy.rego`) così è già disponibile per future regole.

### 8.3 policy_test.rego — 16 test case

Categorie:
- **Public bypass**: `/api/v1/auth/login`, `/.well-known/jwks.json`, `/static/...`
- **Tier admission**: tier 2 OK, tier 0/1 negato per nuclear write
- **Clearance**: plant_manager INTERNAL → nuclear POST → DENY (TOP_SECRET required)
- **Role**: operator → reactor GET ALLOW; operator → nuclear GET DENY
- **Path matching**: `/api/v1/personnel/EMP-001` matcha le rule di `/api/v1/personnel`
- **Maintenance tier1**: maint con cert → POST OK; senza cert → DENY; DELETE richiede tier 2
- **Tier 0**: zones GET e documents GET aperti
- **No claims**: senza JWT su rotta protetta → DENY

Esecuzione:
```bash
docker run --rm -v $(pwd):/workspace openpolicyagent/opa:latest \
  test /workspace/infra/opa/ -v
```

Risultato: **PASS: 16/16**.

---

## 9. Step 4 — Envoy

**Commit**: `4b38058 feat(envoy): forward client cert details + identity bypass routes`

### 9.1 Forward client cert details

```yaml
filter_chains:
- transport_socket:
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
      require_client_certificate: false   # tier "niente" deve essere ammesso
      common_tls_context:
        tls_certificates: [{ certificate_chain: server.crt, private_key: server.key }]
        validation_context: { trusted_ca: ca.crt }
  filters:
  - name: envoy.filters.network.http_connection_manager
    typed_config:
      forward_client_cert_details: SANITIZE_SET   # client non può spoofare XFCC
      set_current_client_cert_details:
        subject: true
        cert: true
        dns: true
        uri: true
```

`SANITIZE_SET` significa: se il client mette `x-forwarded-client-cert` nella richiesta in arrivo, Envoy lo cancella e lo sostituisce con quello derivato dalla connessione TLS reale. Se non c'è cert, l'header semplicemente non viene impostato.

### 9.2 Bypass route per nuove rotte identity

```yaml
routes:
  - match: { prefix: "/api/v1/auth/" }              # register, login, verify-otp, WebAuthn
    route:  { cluster: identity_service_cluster }
  - match: { path: "/.well-known/jwks.json" }
    route:  { cluster: identity_service_cluster }
  - match: { prefix: "/api/v1/" }
    route:  { cluster: business_logic_cluster }
  - match: { prefix: "/" }
    route:  { cluster: business_logic_cluster }
```

Tutte queste rotte passano comunque per ext_authz, ma l'orchestrator le risolve come public e le lascia passare.

### 9.3 Allowed headers ext_authz estesi

```yaml
authorization_request:
  allowed_headers:
    patterns:
    - exact: "authorization"
    - exact: "cookie"
    - exact: "x-request-id"
    - exact: "x-ja3-fingerprint"
    - exact: "x-original-uri"
    - exact: "x-authz-request-path"
    - exact: "x-authz-request-method"
    - exact: "x-forwarded-client-cert"   # nuovo
    - exact: "x-zone-id"                  # nuovo
```

Gli ultimi due erano gli header che servivano all'orchestrator per costruire l'input completo per OPA.

### 9.4 Bug fix orchestrator

Con `path_prefix: /api/v1/evaluate`, Envoy invoca l'orchestrator come `/api/v1/evaluate/api/v1/auth/login`. Il primo deploy dell'orchestrator non strippava il prefisso, e il bypass public-path non matchava più → 403 anche su login. Fix:

```go
const evalPrefix = "/api/v1/evaluate"
origPath := r.URL.Path
if strings.HasPrefix(origPath, evalPrefix) {
    origPath = strings.TrimPrefix(origPath, evalPrefix)
    if origPath == "" { origPath = "/" }
}
```

### 9.5 Verifica end-to-end

```bash
# Login via Envoy HTTPS, no cert client
curl -sk -X POST https://localhost:8443/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
# → {"status":"otp_required","session_token":"..."}

# /personnel senza cert (tier 0): 403
curl -sk -H "Authorization: Bearer $JWT" https://localhost:8443/api/v1/personnel

# Stesso CON cert (tier 2 perché admin ha TPM enrollato): 200 + dati
curl -sk --cert client.crt --key client.key \
     -H "Authorization: Bearer $JWT" https://localhost:8443/api/v1/personnel
```

Verifica nel decision log di OPA:
```json
{
  "input": {
    "cert_present": true,
    "cert_subject": "CN=client-test,O=ZTA-Leaks,C=IT",
    "tpm_verified": true,
    "claims": {"role":"plant_manager","clearance_level":"TOP_SECRET","sub":"...","mfa_verified":true,"device_id":"..."},
    "request": {"method":"GET","path":"/api/v1/personnel"}
  },
  "result": true
}
```

---

## 10. Step 5 — Business Logic (verifica)

**Nessun commit di codice**. Master non aveva role middleware, e per direttiva ("OPA decide") non va aggiunto. Il `LoggingMiddleware` esistente è già coerente — emette JSON strutturato per Splunk.

Verifica funzionale: GET su tutte le 7 risorse via Envoy con un admin autenticato + cert restituisce dati reali:
- `/personnel` → 7 records
- `/zones` → 9 records
- `/reactor-parameters` → 5 records
- ecc.

---

## 11. Step 6 — Suite E2E

**Commit**: `3719c5e test(e2e): pillar scripts for auth/PEP/RBAC/ABAC/tier`

### 11.1 lib.sh — helpers riusabili

Compatibile **bash 3** (default macOS, no `declare -A`). Helpers principali:

| Funzione | Scopo |
|----------|-------|
| `wait_for_stack` | Polling Envoy `/.well-known/jwks.json` + MailHog `/api/v2/messages` |
| `mailhog_clear` | DELETE su `/api/v1/messages` per partire pulito |
| `mailhog_latest_otp_for $email` | Estrae l'OTP dall'ultimo messaggio per quel destinatario via regex `>(\d{6})<` |
| `get_jwt $user $pass` | Login → fetch OTP → verify-otp → echo JWT |
| `decode_jwt_payload $jwt` | Base64-decode + JSON-print del payload |
| `http_envoy $method $path $jwt $use_cert $body` | curl verso Envoy con/senza --cert; ritorna solo status code |
| `enroll_webauthn $jwt` | register/begin → register/finish con credential_id e public_key fake |
| `assert_eq $desc $expected $actual` | Tabella PASS/FAIL con counter globale |
| `print_summary` | Total/PASS/FAIL alla fine |

### 11.2 5 pillar script

| Script | Scenari | Cosa testa |
|--------|---------|-----------|
| `auth.sh` | 8 | Login admin, claim JWT (sub/role/clearance/mfa/iss), OTP errato 401, password errata 401 |
| `pep.sh` | 5 | Public bypass `/auth/login` e JWKS, 403 senza JWT su rotte protette, 401 su JWT garbage |
| `rbac.sh` | 4 | operator allow su reactor GET, deny su nuclear/maintenance, maint_tech1 allow su maintenance |
| `abac.sh` | 4 | Registra inline `pm_e2e_low` plant_manager INTERNAL: nuclear POST DENY (clearance underflow); admin TOP_SECRET allow; inspector CONFIDENTIAL personnel GET allow; inspector POST personnel deny (role) |
| `tier.sh` | 5 | Username random per garantire utente fresh: tier 0/1/2 su personnel e nuclear-materials POST con enroll WebAuthn intermedio |

### 11.3 run_all.sh

Esegue i 5 pillar in sequenza, accumula stati e output, rigenera `tests/e2e/REPORT.md` con summary table + per-pillar output (ANSI sanitizzati). Exit code 0 se tutti PASS, 1 altrimenti.

```bash
bash tests/e2e/run_all.sh
```

Output corrente: 26/26 scenari PASS (auth 8 + pep 5 + rbac 4 + abac 4 + tier 5).

### 11.4 Idempotency note

Gli script registrano utenti deterministici con nome fisso (es. `pm_e2e_low`). Mongo `unique` su `username` rende il register idempotente (409 al rerun). `tier.sh` invece **deve** partire fresh perché testa anche il caso "no TPM" — usa quindi un username randomizzato a runtime: `tier_pm_$(b64-of-random-bytes)`.

---

## 12. Step 7 — CI

**Commit**: `90e5d26 ci: OPA policy tests gate + E2E full-suite job`

`.github/workflows/ci.yaml` riscritto in 3 job in serie:

```
opa-tests  →  build-images  →  e2e-tests
```

### 12.1 `opa-tests`

```yaml
- name: Run OPA policy tests
  run: |
    docker run --rm -v ${{ github.workspace }}:/workspace \
      openpolicyagent/opa:latest \
      test /workspace/infra/opa/ -v
```

Gate veloce (~5 secondi). Se le policy o i test rompono, non si paga la build.

### 12.2 `build-images`

`needs: [opa-tests]`. Build individuale di tutti i Dockerfile (firewall, envoy, snort, snort-internal, business-db, security-db, identity-service, security-orchestrator, business-logic, seeder, test-client). Master ne aveva solo 7 — ora 11. `identity-service` e `security-db` mancavano, sono stati aggiunti.

### 12.3 `e2e-tests`

`needs: [build-images]`. Step:

1. Genera `.env` stub con tutte le 22 variabili (mirror del .env reale, secrets placeholder).
2. `docker compose up -d --build` da `deployments/docker/`.
3. Polling readiness Envoy + MailHog (max 120s).
4. `bash tests/e2e/run_all.sh`.
5. **`upload-artifact`**: il `tests/e2e/REPORT.md` viene caricato come artifact (`if: always()`).
6. Se fail: `docker compose logs --tail=300`.
7. Sempre teardown: `docker compose down -v`.

### 12.4 Trigger

Il workflow ora si attiva su:
- push a `master`
- push a `mix-master-zta-core` (così la branch può girare verde prima del merge)
- PR verso `master`

---

## 13. Mappa file modificati / aggiunti

### Aggiunti (nuovi file in questa branch)

```
docs/MIX_MASTER_ZTA_CORE.md                           ← questo documento
infra/opa/data.json
infra/opa/policy_test.rego
services/identity-service/config/config.go             ← refactor 2026-05-10
services/identity-service/internal/crypto/jwks.go
services/identity-service/internal/db/challenges_repo.go
services/identity-service/internal/db/device_repo.go
services/identity-service/internal/db/otp_repo.go
services/identity-service/internal/db/repositories.go  ← refactor 2026-05-10
services/identity-service/internal/db/user_repo.go    (rinominato da repository.go)
services/identity-service/internal/handler/handler.go      ← refactor 2026-05-10 (split api.go)
services/identity-service/internal/handler/login.go        ← refactor 2026-05-10 (split api.go)
services/identity-service/internal/handler/register.go     ← refactor 2026-05-10 (split api.go)
services/identity-service/internal/handler/routes.go       ← refactor 2026-05-10
services/identity-service/internal/handler/verify_otp.go   ← refactor 2026-05-10 (split api.go)
services/identity-service/internal/mailer/mailer.go
services/identity-service/internal/models/sessions.go
services/identity-service/internal/seed/users.go           ← refactor 2026-05-10 (estratto da main)
services/identity-service/internal/webauthn/handler.go     ← refactor 2026-05-10 (split webauthn.go)
services/identity-service/internal/webauthn/login.go       ← refactor 2026-05-10 (split webauthn.go)
services/identity-service/internal/webauthn/register.go    ← refactor 2026-05-10 (split webauthn.go)
services/security-orchestrator/internal/cert/cert.go
services/security-orchestrator/internal/db/mongo.go
services/security-orchestrator/internal/jwt/verifier.go
services/security-orchestrator/internal/opa/client.go
services/security-orchestrator/internal/tpm/lookup.go
tasks/todo.md
tests/e2e/abac.sh
tests/e2e/auth.sh
tests/e2e/lib.sh
tests/e2e/pep.sh
tests/e2e/rbac.sh
tests/e2e/REPORT.md  (auto-generato)
tests/e2e/run_all.sh
tests/e2e/tier.sh
```

### Modificati

```
.env                                              ← +12 variabili
.github/workflows/ci.yaml                          ← 3 job opa→build→e2e
deployments/docker/docker-compose.yaml             ← +mailhog, dipendenze, port temp
infra/databases/security/db_init/security-init.js  ← 6 collezioni + indici + TTL
infra/envoy/envoy.yaml                             ← XFCC, route bypass, allowed_headers
infra/opa/policy.rego                              ← matrice + tier + clearance + tests; refactor 2026-05-10: register/begin in route_rules
services/identity-service/cmd/identity/main.go     ← refactor 2026-05-10: ridotto a wiring (config/repos/seed/router)
services/identity-service/internal/crypto/jwt.go   ← HS256 → RS256 + ZTAClaims; refactor 2026-05-10: rimosso JWTManager.Verify
services/identity-service/internal/db/otp_repo.go  ← refactor 2026-05-10: ConsumeAttempt atomic, rimossi Find+Increment separati
services/identity-service/internal/models/user.go  ← +Email +ClearanceLevel
services/security-orchestrator/Dockerfile          ← go mod tidy in build
services/security-orchestrator/cmd/orchestrator/main.go  ← riscritto da placeholder; refactor 2026-05-10: rimossa map publicPaths
services/security-orchestrator/go.mod              ← +jwt/v5 +mongo-driver
```

### Rimossi

```
services/identity-service/internal/db/repository.go      ← spezzato in user_repo.go + altri
services/identity-service/internal/handler/api.go        ← refactor 2026-05-10: splittato in handler.go/register.go/login.go/verify_otp.go
services/identity-service/internal/webauthn/webauthn.go  ← refactor 2026-05-10: splittato in handler.go/register.go/login.go
```

### Preservati intatti dal master

- Tutti i Dockerfile di Snort, nftables, business-db, business-logic, seeder.
- `services/business-logic/` (eccetto build artifact).
- `infra/splunk-uf/`.
- `infra/databases/business/`.
- `tools/seeder/`.
- `tests/clients/`, `tests/dashboard-app/`.

---

## 14. Come eseguire localmente

### Prerequisiti

- Docker Desktop attivo.
- Repo clonato, branch `mix-master-zta-core` checkout.
- File `.env` presente (committato in branch — contiene placeholder secrets).

### Bring up

```bash
cd deployments/docker
docker compose up -d --build
```

Servizi attivi: 11 container. Web UI utili:
- **Splunk**: http://localhost:8000
- **MailHog**: http://localhost:8025
- **Envoy**: https://localhost:8443 (con `-k` su curl per ignorare il cert self-signed)

### Smoke test rapido

```bash
# JWKS
curl -sk https://localhost:8443/.well-known/jwks.json | jq

# Login admin
curl -sk -X POST https://localhost:8443/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
# → guarda MailHog http://localhost:8025 per l'OTP, poi:
curl -sk -X POST https://localhost:8443/api/v1/auth/verify-otp \
     -H "Content-Type: application/json" \
     -d '{"session_token":"<dal precedente>","otp":"<dalla mail>"}'

# Test mTLS (richiede client cert)
curl -sk --cert certs/client.crt --key certs/client.key \
     -H "Authorization: Bearer <JWT>" \
     https://localhost:8443/api/v1/personnel
```

### Suite E2E completa

```bash
bash tests/e2e/run_all.sh
# Output: 5 pillar, 26 scenari. REPORT.md aggiornato.
cat tests/e2e/REPORT.md
```

### OPA policy tests

```bash
docker run --rm -v $(pwd):/workspace openpolicyagent/opa:latest \
  test /workspace/infra/opa/ -v
# → 16/16 PASS
```

### Tear down

```bash
cd deployments/docker
docker compose down                # mantiene volumi (Splunk, db data)
# oppure
docker compose down -v             # cancella tutti i volumi (CI mode)
```

### Reset selettivo della security-db

Se la security-db ha dati stale (es. dopo cambio schema):

```bash
docker compose stop security-db
docker compose rm -f security-db
docker volume rm docker_security-db-data
docker compose up -d security-db    # init.js gira fresh
```

---

## 15. Open items e lavoro futuro

### Hooks lasciati per il futuro

- **Zone-aware policy**: `infra/opa/data.json` ha già le zone con `min_tier` e `require_mfa`. Basta aggiungere a `policy.rego`:
  ```rego
  zone_ok if { not input.zone_id }
  zone_ok if { user_tier >= data.zones[input.zone_id].ztna_policy.min_tier }
  ```
  e includere `zone_ok` nelle clausole di allow. L'orchestrator già forwarda `X-Zone-Id`.

- **Clone detection enforcement**: WebAuthn login/finish già rileva regressione di sign_count e ritorna `clone_suspected: true`. Per farlo entrare in OPA: salvare il flag nei `risk_flags` dell'utente in `identity_users`, includerlo nel JWT, aggiungere rule:
  ```rego
  no_critical_risk_flags if { not "possible_cloned_authenticator" in input.claims.risk_flags }
  ```

- **JWT revocation enforcement**: l'orchestrator non controlla ancora `jwt_blocklist`. Identity ha una collezione TTL pronta. Aggiungere `Revoke()` come endpoint identity (POST /api/v1/auth/logout) e un controllo nel verifier dell'orchestrator:
  ```go
  func (v *Verifier) IsRevoked(jti string) bool { ... }
  ```

- **JWKS rotation**: la chiave RSA è ephemeral. Per produzione: persistere in Docker volume oppure usare KMS. Il `kid` è già nell'header del JWT, quindi multi-key è banale.

- **Document filtering per applicable_roles** (decisione 5B esclusa): se i compagni vorranno reintrodurlo, è una `GetAllFiltered(role)` su `mongo_document.go` controllata da una chiamata OPA aggiuntiva (es. `data.envoy.authz.filtered_docs`). Tre commit ben tracciabili, niente di sconvolgente.

### TODO in `tasks/todo.md` (sintesi)

Tutti i 7 step sono marcati `✅`. Il file `tasks/todo.md` resta come traccia di sviluppo — utile per i compagni che vogliono ricostruire il percorso.

### Caveat noti

- **`require_client_certificate: false`** + cert opzionale: utenti possono presentare cert non firmato dalla nostra CA e Envoy lo rifiuta a livello TLS. È il comportamento desiderato. Per l'utente "tier niente" è sufficiente non presentare alcun cert.
- **Argon2id parametri**: master usa `m=65536,t=3,p=4`. Adeguati per dev. In produzione si valuteranno parametri più aggressivi (es. m=128MB).
- **`go 1.26-alpine`** nel Dockerfile dell'orchestrator: dipende dall'esistenza dell'image. Se la build CI dovesse fallire per image not found, downgrade a `golang:1.25-alpine` con `GOTOOLCHAIN=auto`.
- **Splunk forwarding**: i volumi log sono cablati ma le pipeline Splunk (search, dashboard) non sono state oggetto della trasposizione — restano come master li aveva.

---

## 16. Riferimento commit

I 7 commit della trasposizione (in ordine cronologico):

| # | Hash | Step | Messaggio |
|---|------|------|-----------|
| 1 | `ba91c84` | 0 | feat(security-db): schema for OTP, JWT blocklist, WebAuthn, audit |
| 2 | `cd57fab` | 1 | feat(identity): RS256 JWT, JWKS, OTP via MailHog, WebAuthn ceremony, multi-role seed |
| 3 | `5770078` | 2 | feat(orchestrator): JWT verify (JWKS), cert parse, TPM lookup, OPA call |
| 4 | `362c2b0` | 3 | feat(opa): role-route matrix, clearance, 3-tier admission + tests |
| 5 | `4b38058` | 4 | feat(envoy): forward client cert details + identity bypass routes |
| 6 | `3719c5e` | 6 | test(e2e): pillar scripts for auth/PEP/RBAC/ABAC/tier |
| 7 | `90e5d26` | 7 | ci: OPA policy tests gate + E2E full-suite job |

Step 5 non ha commit (verifica senza modifiche di codice).

### Follow-up post-review (2026-05-10) — 7 punti del compagno

Tre commit aggiunti dopo il review della branch, indirizzando i punti
elencati nel messaggio di feedback. Walkthrough dettagliato in
`fix_2026-05-10.md` alla root del repo.

| # | Hash | Messaggio | Punti review coperti |
|---|------|-----------|----------------------|
| 8  | `f59b33b` | refactor(identity): split main into config, repositories bundle, seed package | 1 (seed dedicato), 2 (config + repository) |
| 9  | `08cb129` | refactor(identity,opa): atomic OTP, split handlers/webauthn, drop JWT verify | 2 (routing), 3 (no JWT verify), 4 (OTP atomico), 5 (split handler), 6 (split webauthn) |
| 10 | `be1b5e8` | refactor(orchestrator): drop publicPaths bypass — OPA decides every path | 7 (rimuovere publicPaths) |

Branch ora pushata. PR review verso `master` puo' procedere.
