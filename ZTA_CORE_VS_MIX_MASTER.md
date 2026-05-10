# `zta-core` vs `mix-master-zta-core` — diff guidato

> **Per chi**: chi su `zta-core` aveva già lavorato (o ne ha visto solo il dump `project_documentation_ZTALeaks.txt`) e vuole capire **cosa cambia** in `mix-master-zta-core`, **perché**, e **dove**.
> **Branch base**: `master` (con merge `ids` recente, Splunk, identity-service placeholder).
> **Branch sviluppata in parallelo**: `zta-core` (stack ZTA monolitico, mai mergiata in master).
> **Branch corrente**: `mix-master-zta-core`, cut da `master`, applica le direttive del compagno e attinge selettivamente da `zta-core`.

---

## TL;DR

- **`zta-core`** aveva implementato uno stack ZTA "monolitico": tutta la logica auth + JWT + 2FA + WebAuthn + ext_authz dentro un unico `security-orchestrator`. `identity-service` era stato cancellato. Splunk pure.
- **`mix-master-zta-core`** parte da `master` (che aveva identity-service vivo, Splunk, IDS) e ricostruisce lo stack ZTA **rispettando le direttive nuove**:
  - Auth/JWT/TPM **divisi** tra `identity-service` (issuer) e `security-orchestrator` (verifier).
  - Tutta la matrice ruolo↔rotta finisce **dentro OPA**, niente RBAC middleware in business-logic.
  - **3 tier di ammissione**: `cert+TPM` / `solo cert` / `niente` — concetto **nuovo**, non c'era su `zta-core`.
- Cose **preservate da master** (che `zta-core` aveva eliminato): Splunk + splunk-uf, Argon2id (più moderno di bcrypt), schema `User` con campi TPM, `identity-service` come servizio separato, IDS Snort.
- Cose **prese da `zta-core`** (con adattamenti): pattern del JWT manager RS256, idea del JWKS endpoint, schema delle 6 collezioni del security-db, struttura della cerimonia WebAuthn (semplificata), suite di test E2E a 5 pillar, job CI `opa-tests` + `e2e-tests`.
- **Risultato**: 8 commit logici di trasposizione + 3 commit di refactor post-review (2026-05-10) (vs 2 mega-commit di `zta-core`), suite E2E 26/26, OPA tests 16/16.

---

## Indice

1. [Posizionamento delle due branch rispetto a master](#1-posizionamento-delle-due-branch-rispetto-a-master)
2. [Differenza architetturale di fondo](#2-differenza-architetturale-di-fondo)
3. [Diff per componente](#3-diff-per-componente)
4. [Cosa è stato preso da zta-core (con modifiche)](#4-cosa-è-stato-preso-da-zta-core-con-modifiche)
5. [Cosa NON è stato preso da zta-core (e perché)](#5-cosa-non-è-stato-preso-da-zta-core-e-perché)
6. [Cosa è stato preservato di master (e che zta-core aveva tolto)](#6-cosa-è-stato-preservato-di-master-e-che-zta-core-aveva-tolto)
7. [Cosa è completamente nuovo in mix-master-zta-core](#7-cosa-è-completamente-nuovo-in-mix-master-zta-core)
8. [Mappa file: corrispondenze e divergenze](#8-mappa-file-corrispondenze-e-divergenze)
9. [Diff di processo (commit, test, CI)](#9-diff-di-processo-commit-test-ci)
10. [Bug noti di zta-core risolti su mix-master](#10-bug-noti-di-zta-core-risolti-su-mix-master)
11. [FAQ veloci](#11-faq-veloci)

---

## 1. Posizionamento delle due branch rispetto a master

```
                  4a400ab  implement core ZTA security architecture
                f8470b8    minor tweaks
                c61414a    fix(auth): hash OTP with bcrypt + zone data into OPA
                c669b8c    feat(e2e+auth): scripted ZTA validation suite + device_id
zta-core   ─────●───●────●────●────  (mai mergiata in master)
                /
─master────────●────●────●─── ef095a0 logs-bunny ok ─── (cut)
                                            ↓
                                       ●──●──●──●──●──●──●──●  mix-master-zta-core
                                       (8 commit di trasposizione)
```

Le due branch sono **divergenti**: `master` aveva continuato sulla via Splunk + IDS; `zta-core` aveva implementato auth/PDP. Nessun merge è mai avvenuto. `mix-master-zta-core` è un nuovo tentativo che parte dal `master` aggiornato e applica le direttive del compagno guardando — ma non copiando — `zta-core`.

---

## 2. Differenza architetturale di fondo

### `zta-core`: PDP monolitico

```
[client] → [Envoy/PEP] ─── ext_authz gRPC ───→ [security-orchestrator]
                                                  ├─ /auth/login (OTP via SMTP/MailHog)
                                                  ├─ /auth/verify-otp → JWT
                                                  ├─ /auth/register/begin|finish (WebAuthn)
                                                  ├─ /auth/login/begin|finish (WebAuthn)
                                                  ├─ /.well-known/jwks.json
                                                  └─ Check() gRPC: JWT verify + OPA call
                                                          ↓
                                                       [OPA]
                                                          ↓ allow
                                                  inject x-user-claims
                                                          ↓
                                                  [business-logic]
                                                  ├─ ExtractClaims middleware
                                                  └─ RequireRole(...) per ogni rotta
                                                  └─ document filtering applicable_roles
```

Tutto in `security-orchestrator`. `identity-service` non esiste (cancellato). Business-logic ha `RequireRole` middleware con la matrice cablata in Go.

### `mix-master-zta-core`: split per direttiva

```
[client] → [firewall+nftables] → [Envoy/PEP, mTLS opt., XFCC]
                                          ├─── /api/v1/auth/* ───────→ [identity-service]
                                          ├─── /.well-known/* ───────→ [identity-service]
                                          │
                                          └─── ext_authz HTTP ─────→ [security-orchestrator]
                                                                       ├─ JWT verify (JWKS fetch)
                                                                       ├─ Cert parse (XFCC)
                                                                       ├─ TPM lookup (read-only)
                                                                       └─ POST OPA con input arricchito
                                                                              ↓
                                                                           [OPA]
                                                                       (matrice + tier + clearance)
                                                                              ↓
                                                                  inject x-current-user
                                                                              ↓
                                                                       [business-logic]
                                                                       ├─ NESSUN role check
                                                                       └─ logging only
```

Identity issue. Orchestrator verify. OPA decide. Business-logic serve.

| Aspetto | zta-core | mix-master-zta-core |
|---------|----------|---------------------|
| Identity service | cancellato | preservato e potenziato |
| Sigillo dei JWT | RS256 dentro security-orchestrator | RS256 dentro identity-service |
| Verify dei JWT | dentro security-orchestrator (stessa lib) | dentro security-orchestrator (via JWKS HTTP fetch) |
| Shared secret JWT | nessuno (ha la chiave privata in mano) | nessuno (orchestrator ha solo la pubblica via JWKS) |
| ext_authz | gRPC | HTTP (preserva master) |
| Role check | OPA + RequireRole middleware in BL | solo OPA |
| Document filtering | sì (`GetAllFiltered` in BL) | no (out of scope) |
| 3 tier admission | non presente | presente (cert, TPM, niente) |
| Verifica cert client | non presente | presente (XFCC parse) |
| Splunk forwarder | rimosso | preservato |

---

## 3. Diff per componente

### 3.1 Identity Service

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Esiste? | ❌ Cartella `services/identity-service/` cancellata | ✅ Servizio attivo, ampliato |
| Endpoint | n/a | register, login, verify-otp, JWKS, 4 rotte WebAuthn |
| Hash password | n/a | Argon2id (preservato master) |
| Issuance JWT | n/a | RS256 + ZTAClaims, ephemeral key |
| Espone JWKS | n/a | sì, `/.well-known/jwks.json` |
| Storage TPM | n/a | scrive in `device_fingerprints` dopo register/finish |

### 3.2 Security Orchestrator

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Linee di codice | ~1.500 LOC tra 7 pacchetti | ~680 LOC tra 5 pacchetti (refactor 2026-05-10: -20 LOC per drop publicPaths) |
| Pacchetti interni | `auth`, `jwt`, `jwks`, `webauthn`, `mailer`, `db`, `grpc` | `jwt` (verifier), `cert`, `tpm`, `db`, `opa` |
| Flow auth | implementato qui | DELEGATO a identity-service |
| WebAuthn | implementato qui | DELEGATO a identity-service |
| JWT issue | sì (Issue/Refresh/Revoke) | no, solo Verify |
| JWT verify | con la chiave privata locale | via JWKS fetch + cache 5 min |
| Cert parsing | non presente | nuovo modulo `internal/cert/` |
| TPM lookup read-only | non separato | nuovo modulo `internal/tpm/` |
| ext_authz protocol | gRPC (Authorization v3) | HTTP ext_authz |
| Public path bypass | hardcoded in `isPublicPath` | **rimosso** (refactor 2026-05-10): la lista vive solo in OPA `policy.rego` |
| Path normalization | n/a (gRPC passa attributes.request) | strip `path_prefix /api/v1/evaluate` da URL |
| Decision logs OPA | non gestiti | endpoint `/api/v1/opa/logs` (preservato master per Splunk) |

### 3.3 OPA

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Pacchetto | `envoy.authz` | `envoy.authz` |
| Default | `allow := false` | `allow := false` |
| Approccio decisione | 5 condizioni AND: token, clearance, role, trust_score, risk_flags | 4 condizioni AND: claims, tier, role, clearance |
| Trust score | `data.zones[zone].ztna_policy.min_trust_score`, fallback 0.5 | non usato (sostituito da tier) |
| Tier admission | non esiste | tre tier: 0/1/2 calcolati da cert+tpm |
| Role matrix | implicita (passa attraverso `applicable_roles` nel body) | esplicita: `route_rules` come dizionario in policy.rego |
| Path matching | n/a, lavora su attributi richiesta | esatto + prefisso `{key}/` per sub-resource |
| Risk flags | sì (terminated_access, security_hold) | non implementato (out of scope direttive) |
| Test rego | 8 test | 16 test |
| `data.json` | popolato con zone min_trust_score | con zone min_tier (hook futuro, non usato dalla rule attuale) |

### 3.4 Envoy

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| TLS Inspector | sì (JA3 enabled) | sì (preservato da master) |
| `require_client_certificate` | `true` (mTLS obbligatorio) | `false` (cert opzionale per tier "niente") |
| `forward_client_cert_details` | non impostato | `SANITIZE_SET` con subject, cert, dns, uri |
| ext_authz transport | gRPC | HTTP (preservato da master) |
| ext_authz allowed_headers | minimo (auth, ja3) | esteso: + xfcc, x-zone-id, x-authz-method |
| Route bypass per /auth | sì (path /auth/login → orchestrator) | sì (prefix /api/v1/auth/ → identity-service) |
| Route per /.well-known | sì (orchestrator) | sì (identity-service) |
| Route catch-all | business-logic | business-logic |
| Access log con cert | n/a | sì (`%REQ(x-forwarded-client-cert)%`) |

### 3.5 Security DB

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Nome DB | `security_db` (underscore) | `securitydb` (master convention) |
| Coll. utenti | `users` con campo `employee_id` | `identity_users` con `_id` ObjectId |
| Hash password seed | bcrypt (precomputato in JS) | Argon2id (calcolato a startup di identity-service) |
| OTP storage | bcrypt-hashed (dopo fix `c61414a`; prima era plaintext) | Argon2id-hashed |
| Collezioni | users, otp_sessions, jwt_blocklist, device_fingerprints, auth_events | identity_users, otp_sessions, jwt_blocklist, device_fingerprints, **webauthn_challenges**, auth_events |
| `webauthn_challenges` | menzionata, ma non separata | collezione dedicata con TTL 5 min |
| TTL OTP | 5 min | 5 min |
| TTL JWT blocklist | 25h (90000s) | 25h (90000s) |
| Auth | abilitata | abilitata (ztadmin/ztpassword via env) |

### 3.6 Business Logic

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Middleware role | `RequireRole(...)` per ogni rotta | nessuno (per direttiva: OPA decide) |
| Middleware claims | `ExtractClaims` da header `x-user-claims` | nessuno (master non lo aveva) |
| Document filtering | `GetAllFiltered(role)` su `mongo_document.go` | rimosso/non aggiunto (out of scope) |
| Logging | `LoggingMiddleware` JSON | `LoggingMiddleware` JSON (preservato master) |
| Routes | matrice cablata in `routes.go` | flat list (master) |
| Reserved page | `templates/reserved.html` rimossa | `templates/reserved.html` mantenuta |

### 3.7 docker-compose

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| identity-service | ❌ rimosso | ✅ presente, depends_on mailhog + security-db |
| mailhog | ✅ aggiunto su `auth-net` | ✅ aggiunto su `auth-net` (uguale) |
| splunk + splunk-uf | ❌ rimossi | ✅ preservati da master |
| firewall (nftables) | ✅ presente | ✅ presente |
| snort | ✅ presente | ✅ presente |
| snort-internal | ❌ assente | ✅ presente (preservato da merge `ids` di master) |
| security-orchestrator network | front-net + auth-net | front-net + auth-net (uguale) |
| business-logic network | back-net + auth-net | back-net + auth-net (uguale) |
| Porte esposte temp | 8081 (orchestrator) | 8081 (orchestrator) + 8082 (identity, per test diretto) |
| Compose ARM | `docker-compose.arm.yaml` separato | rimosso da master (single file) |

---

## 4. Cosa è stato preso da zta-core (con modifiche)

Lavoro di `zta-core` riusato come ispirazione, riscritto adattandolo allo split + ai nomi master:

| Da `zta-core` | Verso `mix-master-zta-core` | Modifica |
|---|---|---|
| `internal/jwt/jwt.go` (RS256 + ZTAClaims) | `services/identity-service/internal/crypto/jwt.go` | Spostato in identity, claim semplificati (no refresh token, no `risk_flags` nel JWT), `kid` deterministico SHA-256 |
| `internal/jwt/jwks.go` | `services/identity-service/internal/crypto/jwks.go` | Identico nello spirito; JWK base64url manuale, no big.Int helper |
| `internal/auth/auth.go` (login + OTP) | `services/identity-service/internal/handler/{handler,register,login,verify_otp}.go` | Argon2id invece di bcrypt; OTP-hashed con Argon2id; refactor 2026-05-10: split monolite in 4 file (uno per richiesta) + `routes.go` per il mount; OTP verify atomico via `FindOneAndUpdate` |
| `internal/mailer/mailer.go` | `services/identity-service/internal/mailer/mailer.go` | Identico nei contenuti; HTML template più snello |
| `internal/webauthn/webauthn.go` (~580 LOC) | `services/identity-service/internal/webauthn/{handler,register,login}.go` (~330 LOC totali) | Semplificato (no CBOR-decoding attestation); clone detection via sign_count mantenuta; refactor 2026-05-10: split monolite + `BeginRegistration` legge `X-Current-User` (niente piu' verify JWT in identity) |
| `infra/databases/security/db_init/security-init.js` | `infra/databases/security/db_init/security-init.js` | Stesse 6 collezioni e indici/TTL; nome DB `securitydb`, coll. `identity_users`; **niente seed di utenti in JS** (Argon2id si calcola in Go) |
| `infra/opa/policy_test.rego` (8 test) | `infra/opa/policy_test.rego` (16 test) | Riscritto sui nuovi rule (tier admission, route matrix esplicita) |
| Pattern dei pillar E2E (`auth.sh`, `pep.sh`, `rbac.sh`, `abac.sh`, `trust_score.sh`, `lib.sh`, `run_all.sh`) | `tests/e2e/{auth,pep,rbac,abac,tier}.sh` + `lib.sh` + `run_all.sh` | bash 3 compatibile (no `declare -A`); `tier.sh` sostituisce `trust_score.sh`; helper `enroll_webauthn` nuovo |
| Job CI `opa-tests` + `e2e-tests` | `.github/workflows/ci.yaml` | Stessa struttura; aggiunti build di `identity-service` e `security-db` (mancavano su master) |
| `internal/grpc/authz.go` (Check ext_authz) | `services/security-orchestrator/cmd/orchestrator/main.go` (handler `/api/v1/evaluate`) | Convertito da gRPC a HTTP; aggiunto strip path_prefix. Refactor 2026-05-10: rimossa la map `publicPaths` locale, OPA e' l'unico decisore anche per le rotte pubbliche |
| `lookupActiveDeviceID` per recuperare device dal DB | `internal/db/device_repo.go::FindMostRecentByUser` | Stesso comportamento, nomi adattati a `identity_users._id` |

---

## 5. Cosa NON è stato preso da `zta-core` (e perché)

| Componente di `zta-core` | Perché lasciato fuori |
|---|---|
| **Refresh token** (24h TTL accanto all'access 15min) | Non richiesto dalle direttive; ridurre superficie d'attacco. Si aggiunge se necessario in seguito. |
| **`jwtManager.Revoke()` esposto come endpoint** | OPA può negare un JWT verificando blocklist a ogni request (non implementato). Endpoint /logout è hook futuro. |
| **Risk flags nel JWT** (`terminated_access`, `security_hold`, `possible_cloned_authenticator`) | Direttive non li menzionano. Mantenuti come campo nel modello `User` e detection nel WebAuthn finish, ma non passati a OPA. Hook futuro. |
| **`data.zones` con `min_trust_score`** | Sostituito dal sistema a 3 tier. `data.json` di mix-master tiene zone con `min_tier` come hook futuro. |
| **Document filtering per `applicable_roles`** | Decisione 5B: out of scope. Tipo di logica che ridistribuisce decisione fuori da OPA. |
| **`RequireRole` middleware in business-logic** | Direttiva esplicita: tutta la matrice ruolo↔rotta in OPA. Master già non lo aveva. |
| **gRPC ext_authz** | Master ha HTTP ext_authz già funzionante; cambio inutile e invasivo. |
| **bcrypt come hash password** | Master ha Argon2id già pronto, più moderno. |
| **`security-orchestrator/Dockerfile EXPOSE 8081 9090`** | gRPC port 9090 non più necessaria. |
| **WebAuthn ceremony "production-grade"** con CBOR attestation parsing | Lab-grade è sufficiente: registriamo credenziale, contiamo sign_count. La verifica crypto attestation è hook futuro. |
| **IMPLEMENTATION_SUMMARY.md, FIX_REPORT_*.md, TEST_REPORT_ZTA.md, implementation_plan.md** | Documenti specifici del processo di sviluppo di `zta-core`. Riassunto storico, non utile a master. Mantenuti come tracce in `zta-core`. |

---

## 6. Cosa è stato preservato di `master` (e che `zta-core` aveva tolto)

| Componente | Note |
|---|---|
| `services/identity-service/` come servizio separato | Il punto di partenza per la direttiva di split. |
| **Argon2id** in `internal/crypto/password.go` | More current than bcrypt. Parametri: `m=64MiB, t=3, p=4, salt=16B, key=32B`. |
| Schema `User` con `HasTPM`, `TPMPublicKey`, `SecureEnclaveValid`, `TwoFAEnabled` | I campi erano già pronti — bastava popolarli. |
| `infra/splunk-uf/{inputs,outputs}.conf` + servizio `splunk` + `splunk-uf` in compose | Observability completa. |
| `firewall` (nftables) + entrypoint con `nft delete table` (idempotente, no `flush ruleset`) | Fix Docker DNS dal CLAUDE.md. |
| `snort-internal` (oltre a `snort`) | Aggiunto da merge `ids` su master. |
| ext_authz HTTP service | Già configurato e funzionante. |
| `LoggingMiddleware` JSON in business-logic | Compatibile Splunk. |
| `business-logic/templates/reserved.html` | Pagina HTML, non riguarda l'auth. |
| `tools/seeder/` | Popolatore business-db. |
| `tests/clients/` e `tests/dashboard-app/` | Asset di testing legacy preservati. |
| `MONGO_URI`, `SEED_MONGO_URI`, `SPLUNK_*` in `.env` | Aggiunti i nuovi senza toccare gli esistenti. |
| Decision-logs OPA → orchestrator endpoint `/api/v1/opa/logs` | Riusato (non gestito da zta-core). |

---

## 7. Cosa è completamente nuovo in `mix-master-zta-core`

| | Descrizione |
|---|---|
| **3-tier admission** | Concetto centrale delle direttive. Computazione `user_tier` in OPA da `cert_present` + `tpm_verified`; ogni rotta dichiara `min_tier`. |
| **Cert parser** (`internal/cert/cert.go` di orchestrator) | Estrae Subject e Hash da `x-forwarded-client-cert` (Envoy SANITIZE_SET). |
| **TPM lookup read-only** (`internal/tpm/lookup.go` di orchestrator) | `device_fingerprints` lookup dedicato, separato dalla logica di issuance. |
| **OPA route_rules dictionary** | Matrice ruolo↔rotta esplicita in Rego (vs implicita via parsed_body in zta-core). |
| **Path matching con sub-resource** in OPA | `matched_route` riconosce `/api/v1/personnel/EMP-001` per la rule di `/api/v1/personnel`. |
| **Strip `path_prefix /api/v1/evaluate`** in orchestrator | Necessario perché Envoy ext_authz HTTP usa path_prefix; zta-core gRPC non aveva il problema. |
| **Trigger CI su `mix-master-zta-core`** | Permette validazione branch prima del merge. |
| `tier.sh` E2E pillar | Test specifico dei 3 tier. zta-core aveva `trust_score.sh` con scenari basati su zone min_trust_score, sostituito. |
| Username **randomizzato** in `tier.sh` | Perché serve un utente fresh senza TPM enrollato per testare il salto tier 1 → 2. |
| `assert_eq` con counter PASS/FAIL globale | Helper bash 3 nei test. |
| `mailhog_clear` + `mailhog_latest_otp_for $email` | Estrazione OTP per destinatario specifico (zta-core prendeva sempre l'ultimo). |
| **Documento `docs/MIX_MASTER_ZTA_CORE.md`** | Walkthrough completo della trasposizione. |
| Questo documento (`ZTA_CORE_VS_MIX_MASTER.md`) | Diff guidato per chi viene da zta-core. |
| **OTP verify atomico** (refactor 2026-05-10) | `OTPRepository.ConsumeAttempt` collassa check-limite + increment in una sola `FindOneAndUpdate` Mongo con filtro `{token, attempts<MAX}` + `$inc`. zta-core aveva il check + `$inc` in due round-trip separati (race window). |
| **`X-Current-User` come fonte d'identita' downstream** (refactor 2026-05-10) | WebAuthn `BeginRegistration` legge l'header iniettato dall'orchestrator dopo verifica JWT. Identity non verifica piu' il JWT localmente — `JWTManager.Verify` rimosso. |
| **Pulizia `cmd/identity/main.go` in stile business-logic** (refactor 2026-05-10) | Estratti `config/config.go`, `internal/db/repositories.go`, `internal/seed/users.go`, `internal/handler/routes.go`. Main ridotto a wiring. |

---

## 8. Mappa file: corrispondenze e divergenze

### File CON corrispondenza diretta (zta-core → mix-master)

| `zta-core` | `mix-master-zta-core` |
|---|---|
| `services/security-orchestrator/internal/jwt/jwt.go` | `services/identity-service/internal/crypto/jwt.go` (SPOSTATO) |
| `services/security-orchestrator/internal/jwt/jwks.go` | `services/identity-service/internal/crypto/jwks.go` (SPOSTATO) |
| `services/security-orchestrator/internal/auth/auth.go` | `services/identity-service/internal/handler/{handler,register,login,verify_otp,routes}.go` (SPOSTATO + esteso + splittato per richiesta) |
| `services/security-orchestrator/internal/mailer/mailer.go` | `services/identity-service/internal/mailer/mailer.go` (SPOSTATO) |
| `services/security-orchestrator/internal/webauthn/webauthn.go` | `services/identity-service/internal/webauthn/{handler,register,login}.go` (SPOSTATO + semplificato + splittato login/register) |
| `services/security-orchestrator/internal/db/mongo.go` | `services/security-orchestrator/internal/db/mongo.go` (RIMASTO ma read-only) + `services/identity-service/internal/db/client.go` (originale master) |
| `services/security-orchestrator/internal/grpc/authz.go` | `services/security-orchestrator/cmd/orchestrator/main.go::buildEvaluateHandler` (riconvertito a HTTP, modulo eliminato) |
| `infra/opa/policy.rego` | `infra/opa/policy.rego` (RIDISEGNATO: route matrix esplicita + tier) |
| `infra/opa/policy_test.rego` | `infra/opa/policy_test.rego` (RIDISEGNATO: 16 test sui nuovi rule) |
| `infra/opa/data.json` | `infra/opa/data.json` (struttura simile, semantica zone diversa) |
| `infra/databases/security/db_init/security-init.js` | `infra/databases/security/db_init/security-init.js` (DB name diverso, no seed Argon2id-incompatibile) |
| `infra/envoy/envoy.yaml` | `infra/envoy/envoy.yaml` (HTTP ext_authz invece di gRPC; XFCC; route /api/v1/auth/) |
| `services/business-logic/internal/middleware/rbac.go` | (NESSUNO — rimosso, decisione 5B + direttiva OPA) |
| `tests/e2e/auth.sh` | `tests/e2e/auth.sh` (struttura simile, lib bash3-compatibile) |
| `tests/e2e/pep.sh` | `tests/e2e/pep.sh` |
| `tests/e2e/rbac.sh` | `tests/e2e/rbac.sh` |
| `tests/e2e/abac.sh` | `tests/e2e/abac.sh` (testa clearance underflow vs trust_score) |
| `tests/e2e/trust_score.sh` | `tests/e2e/tier.sh` (RIPENSATO sui 3 tier admission) |
| `tests/e2e/run_all.sh` | `tests/e2e/run_all.sh` (bash3-compatibile, niente associative array) |
| `tests/e2e/lib.sh` | `tests/e2e/lib.sh` |
| `tests/e2e/REPORT.md` | `tests/e2e/REPORT.md` (auto-generato) |
| `.github/workflows/ci.yaml` | `.github/workflows/ci.yaml` (3 job stessi, build esteso) |
| `tasks/todo.md` | `tasks/todo.md` (nuovo piano, 0..7) |

### File presenti SOLO su `zta-core`

- `BRANCH_DIFF_zta-core_vs_master.md` (analisi pre-merge, già fatta)
- `IMPLEMENTATION_SUMMARY.md` (+ pdf)
- `FIX_REPORT_2026-05-02.md`, `FIX_REPORT_2026-05-03.md`
- `TEST_REPORT_ZTA.md`
- `implementation_plan.md`
- `services/identity-service/` (era già stato cancellato)
- `services/security-orchestrator/internal/{auth,jwt,mailer,webauthn,grpc}/` (la cartella esiste in mix-master ma con altro contenuto)

### File presenti SOLO su `mix-master-zta-core`

- `docs/MIX_MASTER_ZTA_CORE.md` (walkthrough completo)
- `ZTA_CORE_VS_MIX_MASTER.md` (questo file)
- `fix_2026-05-10.md` (walkthrough dei 3 commit di refactor post-review)
- `services/security-orchestrator/internal/{cert,tpm,opa}/` (nuovi pacchetti)
- `services/identity-service/config/` (refactor 2026-05-10)
- `services/identity-service/internal/db/{user_repo,otp_repo,device_repo,challenges_repo,repositories}.go` (split di repository.go + bundle 2026-05-10)
- `services/identity-service/internal/seed/` (refactor 2026-05-10: estratto seedUsers da main)
- `services/identity-service/internal/handler/{handler,register,login,verify_otp,routes}.go` (refactor 2026-05-10: split di api.go)
- `services/identity-service/internal/webauthn/{handler,register,login}.go` (refactor 2026-05-10: split di webauthn.go)
- `services/identity-service/internal/models/sessions.go` (OTPSession, DeviceCredential, WebAuthnChallenge, JWTBlocklistEntry)
- `infra/splunk-uf/` (preservata da master)

---

## 9. Diff di processo (commit, test, CI)

### Commit cadence

**`zta-core`**:
```
4a400ab implement core ZTA security architecture     (mega-commit, 2.000+ LOC)
f8470b8 minor tweaks and test report
c61414a fix(auth): hash OTP with bcrypt + zone data into OPA
c669b8c feat(e2e+auth): scripted ZTA validation suite + device_id JWT claim
```
4 commit di cui 1 monolitico — bisognava leggere ~50 file per capirlo.

**`mix-master-zta-core`**:
```
ba91c84 feat(security-db): schema for OTP, JWT blocklist, WebAuthn, audit
cd57fab feat(identity): RS256 JWT, JWKS, OTP via MailHog, WebAuthn ceremony, multi-role seed
5770078 feat(orchestrator): JWT verify (JWKS), cert parse, TPM lookup, OPA call
362c2b0 feat(opa): role-route matrix, clearance, 3-tier admission + tests
4b38058 feat(envoy): forward client cert details + identity bypass routes
3719c5e test(e2e): pillar scripts for auth/PEP/RBAC/ABAC/tier
90e5d26 ci: OPA policy tests gate + E2E full-suite job
b268abd docs: comprehensive MIX_MASTER_ZTA_CORE walkthrough
─── follow-up post-review (2026-05-10) ───
f59b33b refactor(identity): split main into config, repositories bundle, seed package
08cb129 refactor(identity,opa): atomic OTP, split handlers/webauthn, drop JWT verify
be1b5e8 refactor(orchestrator): drop publicPaths bypass — OPA decides every path
```
8 commit di trasposizione + 3 commit di refactor post-review, ognuno una unità testabile. Rollback granulare.

### Test cadence

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| OPA tests | 8 (`opa test infra/opa -v`) | 16 |
| E2E pillar | 5 (auth, pep, rbac, abac, trust_score) | 5 (auth, pep, rbac, abac, tier) |
| E2E scenari totali | ~20 (REPORT.md storico) | 26 (auth 8 + pep 5 + rbac 4 + abac 4 + tier 5) |
| Test compatibility | bash + curl + python3 (no jq) | uguale, +bash 3 (macOS default) |
| REPORT.md | autogenerato | autogenerato |

### CI

| | `zta-core` | `mix-master-zta-core` |
|---|---|---|
| Job | opa-tests, build-images, e2e-tests | uguali |
| Trigger | push/PR su master | push/PR su master + push su `mix-master-zta-core` |
| Build images count | 8 (mancavano identity, security-db, snort-internal) | 11 (completo) |
| Stub `.env` in CI | sì | sì, esteso con 22 variabili |
| Upload REPORT.md | sì | sì (`if: always()`) |

---

## 10. Bug noti di `zta-core` risolti su `mix-master`

`BRANCH_DIFF_zta-core_vs_master.md` di `zta-core` listava (§7) tre divergenze interne:

1. **OTP storage in plaintext** in `auth/auth.go` (corretto in `c61414a`).
   - Su mix-master: OTP è hashed con Argon2id prima di essere scritto in `otp_sessions`. Il cleartext esiste solo nella memoria del request handler e nell'email (TTL 5 min).

2. **Test trust score §6.1 non riproducibile**: `data.zones` non popolato, fallback 0.5 lasciava passare 0.8.
   - Su mix-master: la logica trust_score è stata sostituita dai 3 tier. `data.json` con zone esiste come hook ma la rule attuale non lo legge — niente "test che passano per fallback".

3. **`device_id` JWT claim mai popolato**: campo presente in `ZTAClaims` ma il flusso OTP non lo settava (corretto in `c669b8c`).
   - Su mix-master: `verify-otp` chiama `Devices.FindMostRecentByUser` e setta `device_id` se l'utente ha registrato un WebAuthn. L'orchestrator poi lo verifica → `tpm_verified=true`. **Test E2E `tier.sh` lo prova esplicitamente**: enroll → re-login → JWT con device_id → orchestrator log conferma `tpm_verified=true`.

Inoltre è stato risolto un bug specifico di mix-master che non esisteva su zta-core (perché ext_authz era gRPC):

4. **Path mangling con `path_prefix /api/v1/evaluate`**: Envoy ext_authz HTTP service prepone il prefix; l'orchestrator deve stripparlo per recuperare la rotta originale e fare il public-path bypass. Fix nello step 4.

E nel refactor post-review del 2026-05-10:

5. **OTP race condition** (presente sia su mix-master pre-review sia su
   zta-core, mai sollevato esplicitamente nei BRANCH_DIFF): in
   `verify-otp` il check del limite tentativi (`session.Attempts >= 3`) e
   l'increment (`OTP.IncrementAttempts`) erano due round-trip Mongo
   separati. Due richieste concorrenti sullo stesso `session_token`
   potevano leggere `attempts=2` entrambe e passare il check, poi
   incrementare entrambe a 3 e 4. Fix: `OTPRepository.ConsumeAttempt`
   con `FindOneAndUpdate` filtrato `{token, attempts<MAX}` + `$inc` →
   il filtro Mongo applica il limite atomicamente.

6. **Verifica JWT duplicata su identity** (refactor): identity esponeva
   `JWTManager.Verify` usato in WebAuthn `BeginRegistration` per
   identificare l'utente in enrollment. Duplicava la responsabilita'
   dell'orchestrator (che ha gia' la pubkey via JWKS) e violava lo
   split. Fix: `Verify` rimosso; `BeginRegistration` legge ora
   `X-Current-User` iniettato dall'orchestrator dopo verifica.

---

## 11. FAQ veloci

**Q1: Posso ancora usare il codice di `zta-core` come riferimento?**
Sì, e dovresti. Il dump `project_documentation_ZTALeaks.txt` è canonico. Per ogni componente che vuoi capire, c'è una corrispondenza diretta in mix-master (vedi §8).

**Q2: Perché non un git-merge da `zta-core` invece di riscrivere?**
Perché l'architettura è cambiata: lo split identity/orchestrator non è una "fusione di file" ma uno spostamento di responsabilità. Un merge avrebbe portato auth/JWT/WebAuthn dentro orchestrator (sbagliato per direttiva) e cancellato Splunk + identity-service (regressioni).

**Q3: Cosa devo fare se voglio reintrodurre il document filtering?**
Aggiungi una `GetAllFiltered(role)` in `mongo_document.go` (la implementazione di `zta-core` è valida) ed un endpoint OPA dedicato `data.envoy.authz.filter_docs[role]`. È stato escluso (decisione 5B), non interdetto.

**Q4: Cosa succede al refresh token?**
Non implementato. L'access token vive 15 min e l'utente rifa la login (con OTP). Per produzione si ripristina la coppia access+refresh come in `zta-core/internal/jwt/jwt.go`, esponendo un endpoint `/api/v1/auth/refresh` su identity.

**Q5: Le risk_flags (terminated_access, security_hold) sono perse?**
No, sono salvate nel modello `User`. Mancano:
- L'iniezione nel JWT al verify-otp (~3 righe).
- L'uso in OPA come `no_critical_risk_flags` (~5 righe Rego).
Hook ben localizzato, da fare su richiesta dei compagni.

**Q6: Cosa cambia tra `data.zones[zone].min_trust_score` di zta-core e `data.zones[zone].min_tier` di mix-master?**
Sostanzialmente è una **rinominazione semantica**: invece di un float [0..1] interpretato come "trust score", ora è un intero {0,1,2} interpretato come "tier minimo richiesto per quella zona". Più diretto da combinare con la valutazione di `cert_present` + `tpm_verified`.

**Q7: Cosa succede se Splunk non è interessato a noi?**
Tieni la pipeline così. I servizi loggano in JSON su file `/var/log/ztaleaks/*/app.jsonl` e Splunk li drena. Se rimuovi Splunk dal compose i log restano nei volumi (utili per debug) ma non vengono indicizzati. Niente di Codice da modificare.

**Q8: Perché un username random in `tier.sh` ma deterministico in `abac.sh`?**
`abac.sh` testa solo che il register sia idempotente (Mongo unique → 409 al rerun va bene). `tier.sh` invece testa anche il caso "no TPM": se il rerun trova un utente con TPM già enrollato, il test fallisce. La randomizzazione in `tier.sh` garantisce un utente sempre fresh.

**Q9: Il push richiederà la review di chi?**
Convenzione del team. Suggerimento: chi ha lavorato a `zta-core` (per validare le scelte di trasposizione) e chi ha curato master/Splunk/IDS (per validare ciò che è stato preservato).

**Q10: Posso rimergiare `zta-core` da qualche parte in seguito?**
Tecnicamente sì, ma non c'è motivo: tutto ciò che valeva la pena tenere è già su `mix-master-zta-core`. `zta-core` resta come traccia storica dello sviluppo parallelo del lab.

---

**Documento completo. Per il walkthrough step-by-step della trasposizione (cosa è stato fatto in che ordine), vedere `docs/MIX_MASTER_ZTA_CORE.md`. Per la validazione attuale, vedere `tests/e2e/REPORT.md`.**
