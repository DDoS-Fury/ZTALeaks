# Differenze `zta-core` vs `master`

**Data analisi**: 2026-05-02
**Repository**: ZTALeaks
**Branch confrontate**: `zta-core` (feature) ↔ `master` (baseline corrente)
**Scopo**: Mappa esaustiva dei divari tra le due branch, da usare come base per la pianificazione del merge/rebase.

---

## 1. Sintesi esecutiva

Le due branch sono **divergenti**, non in serie. `zta-core` ha implementato l'intero stack Zero Trust (NIST 800-207); `master` nel frattempo ha aggiunto la configurazione Splunk Universal Forwarder. Nessuno dei due lavori è mai confluito nell'altra branch.

| Branch | Commit unici | LOC nette aggiunte | Tema |
|---|---|---|---|
| `zta-core` | 2 (`4a400ab`, `f8470b8`) | ~4.100 (in 30 file) | Implementazione ZTA (JWT, 2FA, RBAC, OPA, WebAuthn, ext_authz) |
| `master` | 1 (`5347e24`) | ~36 (in 2 file) | Splunk Universal Forwarder configs |

**Stato di completezza ZTA su master**: ~5%. La policy OPA è uno stub (`allow if { true }`), il Security Orchestrator è un placeholder che risponde solo `200 OK` su `/`.

---

## 2. Topologia dei commit

```
            * f8470b8  minor tweaks and test report          (zta-core)
            * 4a400ab  implement core ZTA security architecture
           /
----o-----o------o-----o------ ... ---* 5347e24  splunk funziona  (master)
                                       (commit base comune: 9df84dd)
```

Base comune: `9df74dd` ("correzione configurazione test").

---

## 3. File presenti SOLO su `zta-core` (mancanti su master)

### 3.1 Documentazione e pianificazione

| File | Righe | Note |
|---|---|---|
| `IMPLEMENTATION_SUMMARY.md` | 1.160 | Riepilogo dei 5 task ZTA implementati |
| `IMPLEMENTATION_SUMMARY.pdf` | binario | Versione PDF del summary |
| `TEST_REPORT_ZTA.md` | 222 | Validation report con curl/PowerShell |
| `implementation_plan.md` | 180 | Piano operativo dei task |

### 3.2 Codice nuovo (interamente assente su master)

| Pacchetto | File | Righe | Funzione |
|---|---|---|---|
| Security Orchestrator | `internal/jwt/jwt.go` | 193 | JWT Manager RS256, Issue/Verify/Revoke/Refresh, blocklist |
| Security Orchestrator | `internal/jwt/jwks.go` | 54 | Endpoint JWKS per chiave pubblica |
| Security Orchestrator | `internal/auth/auth.go` | 357 | Login + 2FA OTP via email |
| Security Orchestrator | `internal/mailer/mailer.go` | 110 | SMTP client (MailHog) |
| Security Orchestrator | `internal/webauthn/webauthn.go` | 581 | FIDO2 device attestation, clone detection |
| Security Orchestrator | `internal/grpc/authz.go` | 260 | Server gRPC ext_authz per Envoy |
| Security Orchestrator | `internal/db/mongo.go` | 73 | Client MongoDB Security DB |
| Business Logic | `internal/middleware/rbac.go` | 111 | `ExtractClaims` + `RequireRole` |
| OPA | `infra/opa/policy_test.rego` | 155 | 8 test case (clearance, role, trust, risk flags) |
| Security DB | `infra/databases/security/db_init/security-init.js` | 142 | 6 collections + TTL + 6 seed users |

**Totale codice nuovo**: ~2.036 righe in 10 file.

---

## 4. File modificati su `zta-core` rispetto a master

| File | Δ righe | Cambiamento principale |
|---|---|---|
| `services/security-orchestrator/cmd/orchestrator/main.go` | 28 → 121 | Da placeholder a server completo (HTTP+gRPC, DB, JWT, mailer, WebAuthn, graceful shutdown) |
| `services/security-orchestrator/Dockerfile` | +9 | `EXPOSE 8081 9090`, supporto `go.sum` |
| `services/security-orchestrator/go.mod` | +25 | jwt/v5, mongo-driver, golang.org/x/crypto, grpc |
| `infra/opa/policy.rego` | 9 → 108 | Da stub `allow=true` a policy ZTA completa (5 condizioni) |
| `infra/envoy/envoy.yaml` | +58 | Route bypass `/auth/`, `/.well-known/`, filtro ext_authz, cluster gRPC |
| `deployments/docker/docker-compose.yaml` | +64 | Servizio MailHog, env vars Security Orchestrator |
| `services/business-logic/cmd/server/main.go` | +27 | Wrapper `ExtractClaims` su tutto il mux |
| `services/business-logic/internal/handler/routes.go` | +137 | Matrice RBAC per ogni route |
| `services/business-logic/internal/handler/api.go` | +59 | Filtering documenti per role |
| `services/business-logic/internal/db/mongo_document.go` | +24 | `GetAllFiltered` con `$in` |
| `services/business-logic/internal/db/repositories.go` | +1 | Interfaccia `GetAllFiltered` |
| `services/business-logic/templates/login.html` | +135 | UI a due step (credentials + OTP) |
| `.github/workflows/ci.yaml` | +28 | Job `opa-tests` come prerequisito di `build-images` |
| `.env` | +10 | Variabili Security Orchestrator, SMTP, WebAuthn |

---

## 5. File presenti SOLO su `master` (eliminati o mai creati su `zta-core`)

| File | Righe | Note |
|---|---|---|
| `infra/splunk-uf/inputs.conf` | 29 | Definisce gli input log (path, sourcetype, index) per Splunk UF |
| `infra/splunk-uf/outputs.conf` | 7 | Forwarder destination (Splunk indexer host:port) |

**Importante**: il diff mostra questi file come `-29` / `-7` su `zta-core`. Significa che su `zta-core` risultano **eliminati**. Probabile causa: la branch `zta-core` è stata creata prima del commit Splunk e non ha mai recuperato quel lavoro. Al momento del merge bisognerà preservarli esplicitamente, altrimenti un merge naive li cancellerà da master.

---

## 6. Mappa di completezza per componente

Stato di ciascun componente ZTA dichiarato in `IMPLEMENTATION_SUMMARY.md`, valutato sulle due branch:

| Componente | `zta-core` | `master` |
|---|---|---|
| JWT (RS256, Issue/Verify/Revoke/Refresh) | Implementato | Assente |
| JWKS endpoint `/.well-known/jwks.json` | Implementato | Assente |
| 2FA OTP via email (MailHog) | Implementato (con OTP in plaintext, vedi §7) | Assente |
| WebAuthn/FIDO2 (4 endpoint, clone detection) | Implementato (device_id non propagato in JWT, vedi §7) | Assente |
| RBAC middleware (`ExtractClaims`, `RequireRole`) | Implementato | Assente |
| Matrice ruoli per risorsa | Implementata | Assente |
| Document filtering per role | Implementato | Assente |
| OPA policy (5 condizioni allow) | Implementata | Stub `allow if { true }` |
| OPA test suite (8 test case) | Implementata | Assente |
| Envoy ext_authz + bypass `/auth/` `/.well-known/` | Configurato | Non configurato |
| MailHog SMTP container | Configurato | Non configurato |
| Security DB schema + seed | Implementato | Non implementato |
| CI con `opa test` | Implementata | Non implementata |
| Splunk UF forwarder | Assente | Configurato |

---

## 7. Divergenze interne a `zta-core` da risolvere prima del merge

Anomalie rilevate durante l'audit del codice di `zta-core` (separate dal confronto fra branch):

1. **OTP storage in plaintext** — `services/security-orchestrator/internal/auth/auth.go:75-81`. Il summary dichiara "bcrypt hash, non plaintext" (§9.3) ma in codice l'OTP è memorizzato come stringa nuda nel documento `otp_sessions`. Mitigato dal TTL di 5 minuti, ma resta un disallineamento doc/codice.
2. **Test trust score §6.1 non riproducibile** — `infra/opa/policy.rego:84-100` legge `data.zones[input.zone_id].ztna_policy.min_trust_score`, ma `data.zones` non viene mai popolato (nessun bundle, nessun seed). Il fallback (linea 99) lascia passare `0.5`, quindi un trust score `0.8` verrebbe ammesso, non negato. Il `403` osservato nel test report è stato ottenuto con un override manuale non documentato.
3. **`device_id` JWT claim mai popolato** — `services/security-orchestrator/internal/auth/auth.go:277-283`. Il campo esiste in `ZTAClaims` ma il flusso OTP non lo imposta. La registrazione WebAuthn fa boost di trust ma il device_id non si propaga ai JWT successivi.

---

## 8. Strategia di merge consigliata

Ordine raccomandato:

1. **Sistemare i tre punti del §7 direttamente su `zta-core`** (sono fix da poche decine di righe).
2. **Rebase `zta-core` su `master`** (non merge):
   ```bash
   git checkout zta-core
   git rebase master
   # Risolvi i conflitti recuperando da master:
   #   - infra/splunk-uf/inputs.conf
   #   - infra/splunk-uf/outputs.conf
   ```
3. **Cablare Splunk forwarder ai nuovi servizi** (`security-orchestrator`, `auth_events` collection) così l'osservabilità di master copre anche il piano ZTA.
4. **PR `zta-core` → `master`** con review e validazione CI (la pipeline `opa-tests` deve girare verde).

In alternativa, merge no-fast-forward se si vuole preservare la storia parallela; in tal caso comunque va eseguito il salvataggio esplicito dei file Splunk.

---

## 9. Riferimenti

- Summary di implementazione: `IMPLEMENTATION_SUMMARY.md` (su `zta-core`)
- Report di validazione: `TEST_REPORT_ZTA.md` (su `zta-core`)
- Piano operativo: `implementation_plan.md` (su `zta-core`)
- Workflow CI: `.github/workflows/ci.yaml`

**Comando per riprodurre il diff completo**:
```bash
git diff --stat master zta-core
git log --oneline master..zta-core
git log --oneline zta-core..master
```
