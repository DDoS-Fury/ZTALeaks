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

## Step 1 — identity-service RS256 + register + OTP + WebAuthn  ✅
- [x] `internal/crypto/jwt.go`: HS256 → RS256 ephemeral RSA-2048; ZTAClaims con sub/role/clearance/mfa_verified/device_id/ja3/iss/jti
- [x] `internal/crypto/jwks.go`: handler GET /.well-known/jwks.json (kty=RSA, alg=RS256, kid)
- [x] Repository: user_repo (esteso con FindByID, MarkTPMEnrolled), otp_repo, device_repo, challenges_repo
- [x] `internal/handler/api.go`: register + login (→ OTP) + verify-otp (→ JWT con device_id)
- [x] `internal/mailer/mailer.go`: SMTP HTML → MailHog
- [x] `internal/webauthn/webauthn.go`: register/begin|finish + login/begin|finish con clone detection (sign_count regression)
- [x] `cmd/identity/main.go`: seed 6 utenti multi-ruolo (Argon2id "admin123") + wiring completo
- [x] `docker-compose.yaml`: aggiunto mailhog (UI 8025); identity-service esposto temp su 8082 per test
- [x] 12 test verdi: JWKS, login, OTP via MailHog, verify-otp, JWT decode (claim corretti), WebAuthn register, JWT successivo contiene device_id, login WebAuthn/begin, OTP errato (counter), pwd errata, register nuovo utente
- [x] Commit: `feat(identity): RS256 JWT, JWKS, OTP via MailHog, WebAuthn ceremony, multi-role seed`

## Step 2 — security-orchestrator: PDP coordinator  ✅
- [x] `go.mod`: jwt/v5 + mongo-driver + indirette; Dockerfile aggiornato (go mod tidy in build)
- [x] `internal/jwt/verifier.go`: JWKS fetch (cache 5 min), RS256 verify, kid-based key lookup
- [x] `internal/cert/cert.go`: parse header forwarded da Envoy (Subject, Hash, Present)
- [x] `internal/db/mongo.go`: client read-only su securitydb
- [x] `internal/tpm/lookup.go`: `device_fingerprints` lookup per coppia (credential_id, user_id)
- [x] `internal/opa/client.go`: POST OPA con input `{request, claims, cert_present, cert_subject, tpm_verified, zone_id}`
- [x] `cmd/orchestrator/main.go`: rimosso stub AI risk, wirato tutto; preservato endpoint `/api/v1/opa/logs` per decision logs (master)
- [x] Test: 6 scenari (public bypass, no JWT, JWT valido, JWT invalido, con cert) tutti verdi; OPA riceve input arricchito completo (verificato da OPA decision logs)
- [x] Commit: `feat(orchestrator): JWT verify (JWKS), cert parse, TPM lookup, OPA call`

## Step 3 — OPA policy + data + tests  ✅
- [x] `infra/opa/policy.rego`: public paths whitelist + matrice ruolo↔rotta sulle 7 risorse + clearance hierarchy + 3 tier (none/cert/cert+tpm) con min_tier per (path, method) + path matching esatto/prefisso
- [x] `infra/opa/data.json`: zone metadata (min_tier per zona, require_mfa) — tenuto come hook futuro
- [x] `infra/opa/policy_test.rego`: 16 test (public bypass, tier 0/1/2, clearance, role denied, path con sub-id, no claims) — `opa test` 16/16 PASS
- [x] Compose: OPA monta anche `data.json`
- [x] Test E2E via orchestrator: 11/11 PASS (admin con/senza cert su personnel, nuclear-materials POST tier=2, operator role denied su nuclear/maintenance, zones/documents tier=0, public bypass)
- [x] Commit: `feat(opa): role-route matrix, clearance, 3-tier admission + tests`

## Step 4 — Envoy: forward client cert + bypass nuove rotte  ✅
- [x] `infra/envoy/envoy.yaml`: `forward_client_cert_details: SANITIZE_SET` (no spoofing) + `set_current_client_cert_details: {subject, cert, dns, uri}`
- [x] Allowed_headers ext_authz estesi: x-forwarded-client-cert, x-zone-id, x-authz-request-method
- [x] Route prefix `/api/v1/auth/` (cattura register, verify-otp, register/begin|finish, login/begin|finish) e `/.well-known/jwks.json` → identity_service_cluster
- [x] Access log estesi con `client_cert: %REQ(x-forwarded-client-cert)%`
- [x] Fix orchestrator: strip `path_prefix /api/v1/evaluate` da r.URL.Path per riconoscere il path originale
- [x] Test E2E via HTTPS:8443 (con e senza --cert client.crt): JWKS ✓, login flow ✓, no-cert→tier0→DENY personnel ✓, cert→tier2→ALLOW personnel/nuclear ✓, no-cert→DENY nuclear ✓, no-JWT→DENY ✓
- [x] OPA decision log conferma `cert_subject="CN=client-test,O=ZTA-Leaks,C=IT"` correttamente forwarded
- [x] Commit: `feat(envoy): forward client cert details + identity bypass routes`

## Step 5 — business-logic: verifica  ✅
- [x] Confermata assenza di role middleware su master (allineato alle direttive: OPA è l'unico decisore)
- [x] LoggingMiddleware esistente è già coerente: emette JSON strutturato con x-request-id, method, path, status, duration → forwarder Splunk OK
- [x] E2E reale via HTTPS:8443 con admin (cert+JWT): GET /personnel 7 records 200, GET /zones (no-cert, tier 0) 9 records 200, GET /reactor-parameters 5 records 200; business-logic log conferma le richieste
- [x] Nessuna modifica codice (master + step 4 già coerente con direttive). Non viene creato commit dedicato per evitare rumore.

## Step 6 — tests/e2e  ✅
- [x] `tests/e2e/lib.sh`: helpers bash3-compat (assert_eq, get_jwt via Envoy+MailHog, http_envoy con/senza --cert, enroll_webauthn, mailhog OTP fetch)
- [x] `auth.sh` (8 test): login admin → JWT con sub/role/clearance/mfa/iss corretti, OTP errato → 401, password errata → 401
- [x] `pep.sh` (5 test): public bypass /auth/login + JWKS, protezioni 403 senza JWT, JWT garbage → 401
- [x] `rbac.sh` (4 test): operator allowed/denied per matrice, maint_tech1 allowed
- [x] `abac.sh` (4 test): registra inline plant_manager INTERNAL → /nuclear POST DENY (clearance underflow), admin TOP_SECRET allow, inspector CONFIDENTIAL su /personnel allow, inspector POST personnel deny (role)
- [x] `tier.sh` (5 test): username random per isolare TPM-vergine; copre 3 tier su /personnel e /nuclear-materials
- [x] `run_all.sh`: bash3-compatibile, esegue i 5 pillar, rigenera `tests/e2e/REPORT.md` con summary table + per-pillar output
- [x] Test: `bash tests/e2e/run_all.sh` → 5/5 pillar PASS, 26/26 scenari
- [x] Commit: `test(e2e): pillar scripts for auth/PEP/RBAC/ABAC/tier`

## Step 7 — CI  ✅
- [x] `.github/workflows/ci.yaml` riscritto: trigger anche su `mix-master-zta-core`; 3 job in serie:
  - `opa-tests` (gate, ~5s)
  - `build-images` (incluso identity-service e security-db, mancanti su master) — needs opa-tests
  - `e2e-tests` (genera .env stub, `docker compose up -d --build`, polling readiness Envoy+MailHog, `bash tests/e2e/run_all.sh`, upload REPORT.md, teardown `down -v`) — needs build-images
- [x] Test locale: `docker run openpolicyagent/opa test /workspace/infra/opa/ -v` → 16/16 PASS
- [x] Commit: `ci: OPA policy tests gate + E2E full-suite job`

## Step 8 — snort-mid (Envoy ↔ Security Orchestrator) — IN PROGRESS
Obiettivo: terzo Snort identico agli altri due, posizionato sul segmento Envoy→Security Orchestrator, per rilevare SQL Injection e Cross-Site Scripting su traffico HTTP plaintext.

Verifiche fatte:
- Q3: `envoy.yaml:145` usa `http://security-orchestrator:8081/...` → plaintext, ispezionabile ✓
- Q4: front-net, replicato via `network_mode: service:firewall` (come gli altri due)
- Q1: solo JSON processato ✓
- Q2: nessuna rotation, allineato agli altri due
- Q5: test live con richieste HTTP reali via Envoy

Limite noto: ext_authz forwarda solo gli header consentiti (incluso `x-original-uri`) ma NON il body → SQL/XSS in URL/query catturati; SQL/XSS in body NO (su questo segmento).

Plan:
- [x] Creare `infra/snort-mid/` (Dockerfile, parser.go, rules/mid.rules — 9 regole SQLi+XSS scoped port 8081)
- [x] `deployments/docker/docker-compose.yaml`: servizio + volume + mount splunk-uf
- [x] `.github/workflows/ci.yaml`: build di `infra/snort-mid/Dockerfile`
- [x] Test live: payload SQL/XSS inviati via nc da firewall netns → alert correttamente generati su volume (UNION SELECT, tautology URL-encoded, OR 1=1, XSS <script>). Stdout identico agli altri due snort.
- [x] **BLOCCANTE risolto**: envoy non è più in restart loop — `server.key` ora è di proprietà uid 101 (perm 644) e il processo gira come uid 101. Verificato 2026-06-01: `RestartCount 0`, running, nessun errore sui permessi nei log.
- [x] Commit manuale dopo OK utente (mergiato su `master`)

## Audit 2026-06-01 — criticità aperte (da discutere coi compagni)

Audit eseguito sullo stack avviato in locale, testando ogni punto dal vivo.
Già risolti in questa sessione: race boot business-logic e hardening avvio Envoy
(commit unico). Restano i 3 punti sotto, **da discutere prima di toccarli**.

### #1 — mTLS NON imposto dal PEP (Envoy)  🔴 Alta
- **Cosa:** `infra/envoy/envoy.yaml` → `require_client_certificate: false`. Una connessione senza certificato client completa comunque l'handshake TLS e arriva all'orchestrator con `cert_present:false`. Il cert è validato solo dall'identity-service al login, non dal proxy. Contraddice lo Zero Trust (CLAUDE.md indica `true`).
- **Test:** `curl -sk https://localhost:8443/...` senza cert → handshake OK, HTTP 403 (da OPA, non dal TLS).
- **Fix proposto:** `require_client_certificate: true`.
- **In pausa perché:** i certificati client li gestisce un compagno e li usa per altri test; va coordinato con lui.

### #2 — `network_location` falsificabile (spoofing X-Forwarded-For)  🔴 Alta
- **Cosa:** `services/security-orchestrator/internal/handler/handler.go:187` `clientIPFromRequest` prende il **primo** elemento di `X-Forwarded-For`, controllabile dal client. Envoy ha `use_remote_address: true` e appende l'IP reale in coda, ma l'orchestrator legge la testa → bug lato orchestrator.
- **Test:** `curl ... -H 'X-Forwarded-For: 10.0.0.99'` → orchestrator logga `ip_address: 10.0.0.99 | network_location: internal`. Un client esterno si dichiara "internal".
- **Fix proposto:** in Envoy usare `xff_num_trusted_hops`; nell'orchestrator fidarsi solo dell'IP impostato da Envoy (ultimo hop), non del primo elemento.
- **Caveat:** in Docker l'IP "vero" è il gateway della bridge → verificare insieme che `network_location` continui a classificare sensatamente il traffico di test. Trasparente per il flusso normale; blocca solo lo spoof manuale.

### #3 — Ramo anonimo scarta il certificato verso OPA  🟡 Media
- **Cosa:** `handler.go:91` — nel ramo "nessun token" il cert è già parsato (`cc := cert.Parse(...)`) ma a OPA va `CertPresent: false` hardcoded e `Claims: nil`. Per richieste senza JWT, OPA non sa mai che c'era un cert (loggato ma non usato).
- **Probabile intenzione:** serve comunque il JWT, quindi forse voluto. Resta un'incoerenza.
- **Fix proposto (se confermato bug):** passare `CertPresent: cc.Present` e `CertSubject: cc.Subject` anche nel ramo anonimo.
