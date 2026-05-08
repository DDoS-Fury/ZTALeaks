# mix-master-zta-core — Trasposizione ZTA su master (piano operativo)

Branch: `mix-master-zta-core` (da `master`).
Direttive ferme: vedi messaggio compagno + 6 risolte 2026-05-09.

Convenzioni:
- 1 commit locale per step (no push).
- Test al termine di ogni step prima del commit; "ok" dell'utente prima di proseguire.
- DB name `securitydb`, collezione utenti `identity_users` (master conventions).

## Step 0 — security-db schema + .env  ✅
- [x] Estendere `infra/databases/security/db_init/security-init.js`: 6 collezioni (identity_users, otp_sessions, jwt_blocklist, device_fingerprints, webauthn_challenges, auth_events) con index unique e TTL
- [x] Estendere `.env` con var per orchestrator, identity, SMTP, WebAuthn
- [x] Test: drop volume `security-db-data` (era pieno di dati zta-core con schema vecchio), rebuild security-db, `mongosh` verifica 6 collezioni e tutti gli indici/TTL come previsti
- [x] Commit: `feat(security-db): schema for OTP, JWT blocklist, WebAuthn, audit`

## Step 1 — identity-service RS256 + register + OTP + WebAuthn
- [ ] `internal/crypto/jwt.go`: HS256 → RS256 (gen ephemeral RSA 2048 a startup), claims `{sub, role, clearance_level, mfa_verified, device_id, ja3, exp, iat, iss}`
- [ ] `internal/crypto/jwks.go`: handler GET /.well-known/jwks.json
- [ ] `internal/handler/api.go`: aggiungere `POST /api/v1/auth/register`, `POST /api/v1/auth/verify-otp`; modificare login per emettere session_token + OTP
- [ ] `internal/mailer/mailer.go`: SMTP client → MailHog (1025)
- [ ] `internal/webauthn/webauthn.go`: portare da zta-core, adattare a `identity_users`/`device_fingerprints`/`webauthn_challenges`
- [ ] Estendere `seedDummyAdmin` a 6 utenti multi-ruolo con clearance
- [ ] `docker-compose.yaml`: aggiungere servizio `mailhog` su `auth-net` (UI 8025, SMTP 1025)
- [ ] Test: rebuild identity + mailhog, curl register/login → MailHog UI mostra OTP → verify-otp → JWT decodificabile con claims attesi; GET /.well-known/jwks.json ritorna chiave RSA
- [ ] Commit: `feat(identity): RS256 JWT, JWKS, OTP via MailHog, WebAuthn ceremony, register`

## Step 2 — security-orchestrator: PDP coordinator
- [ ] `go.mod`: dipendenze (`golang-jwt/jwt/v5`, `mongo-driver`)
- [ ] `internal/jwt/verifier.go`: fetch JWKS da `IDENTITY_JWKS_URL` (cache), verify RS256
- [ ] `internal/cert/cert.go`: parse `x-forwarded-client-cert` header (subject, hash) inviato da Envoy
- [ ] `internal/db/mongo.go`: client securitydb
- [ ] `internal/tpm/tpm.go`: lookup `device_fingerprints` per user_id; restituisce `tpm_verified` boolean
- [ ] `internal/opa/client.go`: POST a OPA con `{claims, cert_present, tpm_verified, zone, request:{path,method}}`
- [ ] `cmd/orchestrator/main.go`: rimuovere stub `getAIRiskScore`, wirare i moduli, esporre `/api/v1/evaluate`
- [ ] Test: curl con/senza JWT, con/senza cert, con/senza TPM → orchestrator log corretto
- [ ] Commit: `feat(orchestrator): JWT verify (JWKS), cert parse, TPM lookup, OPA call`

## Step 3 — OPA policy + data + tests
- [ ] Riscrivere `infra/opa/policy.rego`: matrice ruolo↔rotta (7 risorse), clearance hierarchy, 3 tier (`none`/`cert`/`cert+tpm`) con min_tier per rotta
- [ ] Creare `infra/opa/data.json`: zone min_trust_score (da zta-core); eventuale tier-per-route map
- [ ] Creare `infra/opa/policy_test.rego`: 10-12 test (tier × clearance × role × route)
- [ ] Test: `docker run --rm -v $(pwd):/workspace openpolicyagent/opa test /workspace/infra/opa/ -v`
- [ ] Commit: `feat(opa): role-route matrix, clearance, 3-tier admission + tests`

## Step 4 — Envoy: forward client cert + bypass nuove rotte
- [ ] `infra/envoy/envoy.yaml`: aggiungere `forward_client_cert_details: APPEND_FORWARD` + `set_current_client_cert_details: {subject, cert, dns}`
- [ ] Aggiungere route bypass per `/api/v1/auth/register`, `/api/v1/auth/verify-otp`, `/auth/register/begin|finish`, `/auth/login/begin|finish`, `/.well-known/jwks.json` → `identity_service_cluster`
- [ ] Test: `curl -k --cert ./certs/client.crt --key ./certs/client.key https://localhost:8443/...` → orchestrator riceve `x-forwarded-client-cert`; senza --cert il request passa ma senza header
- [ ] Commit: `feat(envoy): forward client cert details + identity bypass routes`

## Step 5 — business-logic: verifica
- [ ] Confermare assenza role middleware (master già non ne ha); eventualmente aggiungere `ExtractClaims` per logging strutturato
- [ ] Test: curl end-to-end alle 7 risorse con utenti diversi
- [ ] Commit (solo se modifiche): `chore(business-logic): claims extraction for logging`

## Step 6 — tests/e2e
- [ ] Creare `tests/e2e/lib.sh`, `auth.sh`, `pep.sh`, `rbac.sh`, `abac.sh` (clearance), `tier.sh` (3 tier), `tpm.sh` (sign_count clone detection), `run_all.sh` (regenera REPORT.md)
- [ ] Test: `bash tests/e2e/run_all.sh` → tutti i pillar PASS
- [ ] Commit: `test(e2e): pillar scripts for auth/PEP/RBAC/ABAC/tier/TPM`

## Step 7 — CI
- [ ] `.github/workflows/ci.yaml`: aggiungere job `opa-tests` (gate per `build-images`) e `e2e-tests` (full stack)
- [ ] Test: locale `act` o push su feature branch
- [ ] Commit: `ci: OPA policy tests + E2E full-suite gate`
