# ZTALeaks — Riepilogo implementazione

## Panoramica

Questo documento descrive lo stato attuale delle componenti aggiunte/modificate sul branch `mix-master-zta-core` lungo i quattro assi seguenti:

1. Contesto di provenienza nei log strutturati
2. Hardening del firewall (nftables)
3. Parsing e normalizzazione dei log di rete
4. Suite di test automatizzati

L'architettura mantiene la separazione PEP (Envoy) / PDP (Security Orchestrator) e la tracciabilità via `X-Request-ID` correlato in tutti i sink.

---

## 1. Contesto di provenienza nei log

Ogni riga di log strutturato emessa dallo stack porta un campo `service` che identifica il microservizio sorgente, abilitando filtraggio e correlazione diretta in Splunk senza dover dedurre la provenienza da hostname o cluster.

### 1.1 Servizi Go — pre-popolazione via `slog.With`

L'attributo `service` viene impostato sul default logger una sola volta al boot, e tutte le `slog.X` esistenti lo ereditano automaticamente. Pattern minimo-invasivo: nessuna touch puntuale sulle decine di chiamate `slog.Info`/`Warn`/`Error` sparse.

- `services/business-logic/cmd/server/main.go`: `slog.New(...).With("service", "business-logic")`
- `services/security-orchestrator/cmd/orchestrator/main.go`: `... .With("service", "security-orchestrator")`
- `services/iam-service/internal/logger/logger.go` (`InitLogger`): `... .With("service", "iam-service")`

### 1.2 Envoy access log

Il campo `service: "envoy"` è inserito come literal nei due `json_format` (stdout + file `/var/log/ztaleaks/envoy/access.jsonl`). Gli altri campi popolati sono: `start_time`, `request_id`, `response_code`, `remote_address`, `tls_ja3`, `upstream_cluster`, `client_cert`, `user`.

I campi `risk_score` e `zone_id` non sono inclusi: il primo dipende da un modello AI ancora da implementare, il secondo da una logica di zone-mapping policy-driven non ancora definita. Loggarli ora come stringhe vuote produrrebbe solo rumore in Splunk.

### 1.3 Business Logic — middleware di logging

`services/business-logic/internal/middleware/logging.go` estrae dagli header iniettati dall'orchestrator e da Envoy:

- `X-Request-ID`
- `X-Current-User` (popolato da `allowed_upstream_headers` dell'ext_authz Envoy)
- `X-Ja3-Fingerprint` (aggiunto da Envoy via `request_headers_to_add`)

Più `method`, `path`, `remote_addr`, `status_code`, `duration`.

### 1.4 Security Orchestrator — decision log

Ogni decisione di autorizzazione viene loggata con il contesto completo: `path`, `method`, `user`, `role`, `clearance`, `cert_present`, `tpm_verified`, `zone`, `allow`. Permette auditing e analisi forense post-incident.

---

## 2. Hardening del firewall (nftables)

### 2.1 Rate-limiting per-source contro SYN flood

`infra/nftables/nftables.conf`, chain `input`:

```
tcp flags & (fin|syn|rst|ack) == syn meter syn_meter { ip saddr limit rate over 20/second } log prefix "fw-syn-flood-drop: " group 100 drop
```

Il `meter` dinamico mantiene un token bucket separato per ogni `ip saddr`. Soglia 20 SYN/sec per-source: un attaccante che inonda non può saturare una quota condivisa bloccando anche i client legittimi. Validato empiricamente: 50 SYN burst dallo stesso IP → ~85 entry `threat: syn_flood` nel JSONL del parser, con `src` IP loggato per ogni drop.

### 2.2 Egress filtering — policy DROP con allow-list minimale

`infra/nftables/nftables.conf`, chain `output`:

```
chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    tcp dport { 53, 8080, 8081, 8082 } accept
    udp dport 53 accept
    log prefix "fw-egress-drop: " group 100 drop
}
```

Allow-list ristretta a ciò che Envoy davvero apre in uscita (il firewall condivide il network namespace con Envoy):

- 53 DNS interno Docker
- 8080 business-logic
- 8081 security-orchestrator (ext_authz)
- 8082 iam-service

Le porte 80/443/8088/8181 sono usate da altri container nei loro namespace e non vanno permesse qui. Principio Zero Trust: only what is strictly used.

### 2.3 Ordine regole input

```
chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ip saddr @blocked_ips tcp dport ENV_ENVOY_PORT log prefix "fw-drop: " group 100 reject
    tcp flags & (fin|syn|rst|ack) == syn meter syn_meter { ip saddr limit rate over 20/second } log prefix "fw-syn-flood-drop: " group 100 drop
    tcp dport ENV_ENVOY_PORT ct state new log prefix "fw-accept: " group 100 accept
}
```

`blocked_ips reject` precede il SYN meter: così un IP in deny-list non consuma quota del token bucket prima di essere rifiutato.

### 2.4 Forward chain — policy DROP

`chain forward { type filter hook forward priority 0; policy drop; }`. In setup container non c'è routing tra interfacce, quindi è puramente "good hygiene", ma è coerente con il default deny della chain input/output.

---

## 3. Parsing e normalizzazione log nftables

`infra/nftables/parser.go` legge in tail il file syslogemu di `ulogd` ed emette JSONL strutturato in `/var/log/ztaleaks/nftables/firewall.jsonl`. Ogni record è arricchito con `service: "nftables"` e categorizzato per prefisso di log:

| Prefisso log | `action` | `threat` |
|---|---|---|
| `fw-accept` | accept | — |
| `fw-drop` | drop | — |
| `fw-syn-flood-drop` | drop | `syn_flood` |
| `fw-egress-drop` | drop | `unauthorized_egress` |

I campi `IN`, `OUT`, `SRC`, `DST`, `PROTO`, `DPORT`, `SPT` ecc. di ulogd vengono splittati e indicizzati come chiavi JSON. Abilita allerting Splunk diretto su `threat`.

---

## 4. Suite di test automatizzati

### 4.1 Unit test OPA (`infra/opa/policy_test.rego`)

Tre scenari di rifiuto coprenti le dimensioni critiche della matrice di autorizzazione:

- `test_deny_unauthorized_role_nuclear_materials`: operator → GET `/nuclear-materials` → DENY (RBAC)
- `test_deny_insufficient_clearance_nuclear`: plant_manager con CONFIDENTIAL → POST `/nuclear-materials` (richiede SECRET+) → DENY
- `test_deny_low_tier_on_tier2_route`: plant_manager senza cert+TPM → POST `/nuclear-materials` (richiede tier 2) → DENY

### 4.2 E2E firewall (`tests/e2e/nftables.sh`)

Sesto pillar della suite E2E. Verifica reale via `docker exec nft list ...` sul ruleset attivo (non valori hardcoded):

1. Traffico legittimo verso Envoy accettato (HTTP 200/404 su `/.well-known/jwks.json`)
2. Set `blocked_ips` caricato con elementi attesi (10.99.99.99, 172.18.0.10)
3. Chain `output` ha `policy drop` + allow-list `{8080, 8081, 8082}` + log `fw-egress-drop` presente
4. File JSONL del parser esistente e con campo `action` ben formato
5. Regola SYN-flood (`fw-syn-flood-drop`) presente nella chain input
6. Connessioni stabilite passano (replay test 1)

10 sub-test, tutti PASS.

### 4.3 Test client (`tests/clients/main.{go,py}`)

Generano pattern di traffico anomalo per esercitare il firewall e Snort:

- `simulate_port_scan`: SYN scan su 15 porte 8000-8014
- `simulate_syn_flood`: burst di 40 connessioni TCP rapide
- `simulate_rapid_requests`: 50 SYN a intervalli controllati (per il rate-limit)
- `simulate_malformed_requests`: 5 handshake TLS incompleti (`0x16 0x03 0x01 …` + payload `JUNK`)

I drop generati vengono catturati dal parser JSONL e categorizzati come visto in §3.

### 4.4 Helper di test (`tests/e2e/lib.sh`)

`enroll_webauthn` esegue `register/begin` + `register/finish` mandando sia `Authorization: Bearer` sia `--cert/--key`, come richiesto dal `min_tier=1` (mTLS) di `infra/opa/policy.rego` sugli endpoint di enrollment TPM.

### 4.5 Orchestratore (`tests/e2e/run_all.sh`)

Esegue in sequenza i 6 pillar (`auth`, `pep`, `rbac`, `abac`, `tier`, `nftables`) e rigenera `tests/e2e/REPORT.md` con summary tabellare e per-pillar output.

---

## 5. File modificati / creati

### Servizi e infrastruttura

| File | Tipo modifica |
|---|---|
| `infra/envoy/envoy.yaml` | Aggiunto `service: "envoy"` agli access_log; rimosso `zone_id` non popolato |
| `infra/nftables/nftables.conf` | Per-source SYN meter; egress allow-list ristretta; riordino input |
| `infra/nftables/parser.go` | Aggiunto `service: "nftables"`; switch case su prefix per `action`/`threat` |
| `infra/opa/policy_test.rego` | 3 nuovi test di rifiuto |
| `services/business-logic/cmd/server/main.go` | Pre-popola `service` sul default logger |
| `services/business-logic/internal/middleware/logging.go` | Logga `user`, `ja3_fingerprint`, `x_request_id` |
| `services/iam-service/internal/logger/logger.go` | Pre-popola `service` sul default logger |
| `services/security-orchestrator/cmd/orchestrator/main.go` | Pre-popola `service` sul default logger |

### Test

| File | Tipo |
|---|---|
| `tests/e2e/nftables.sh` | Nuovo — 6 test reali via `docker exec` |
| `tests/e2e/lib.sh` | `enroll_webauthn` ora manda cert+Authorization |
| `tests/e2e/run_all.sh` | 6° pillar (nftables) integrato |
| `tests/clients/main.{go,py}` | Aggiunte simulazioni rapid/malformed/syn-flood |

---

## 6. Validazione

`docker-compose up -d --build` + `bash tests/e2e/run_all.sh`:

- **6/6 pillar PASS, 36/36 sub-test PASS**
- auth 8/8 · pep 5/5 · rbac 4/4 · abac 4/4 · tier 5/5 · nftables 10/10

Verifica empirica del rate-limit per-source: 50 SYN burst da un singolo IP → 85 entry `threat: syn_flood` nel parser JSONL, con `src` IP loggato. Il token bucket per-source funziona come atteso.

Verifica empirica del campo `service`: campione di log estratto da ogni sink (envoy, business-logic, iam-service, security-orchestrator, nftables-parser) mostra `"service":"<name>"` correttamente popolato.

---

## 7. Aree non coperte (in standby per scelta)

Le seguenti aree sono fuori dallo scope corrente per decisione del project owner e verranno affrontate in iterazioni successive:

- **Modello AI per risk scoring** — l'header `X-Risk-Score` non viene popolato e non è loggato nello stack
- **Definizione/applicazione di nuove policy** (oltre quelle già in `policy.rego`)
- **Gestione avanzata del certificato client** — il flusso enrollment via `.p12` è funzionante (commit precedente), ma estensioni (revoca, rotation, CRL) sono in standby
- **Zone topology** — l'header `X-Zone-Id` non è settato; serve prima la logica di mapping zone↔risorsa

---

## 8. Migliorie da fare nei prossimi giorni

Le voci seguenti sono tutte **fattibili in autonomia adesso**, nessuna dipende dagli item in standby (AI / policy / cert / zone). Lasciate fuori dai commit di questa sessione per non gonfiare lo scope.

### 8.1 Logging — completare il quadro

- **Middleware HTTP strutturato in `iam-service`**: oggi le `slog.Info` sono sparse a mano nei singoli handler (login, register, verify_otp). Replicare il pattern di `business-logic/internal/middleware/logging.go` aggiungerebbe per ogni request un'unica riga con `method`/`path`/`status_code`/`duration`/`x_request_id`, evitando log inconsistenti tra handler.
- **`duration` nel decision log dell'orchestrator** (`internal/handler/handler.go`): cronometrare `BuildEvaluateHandler` dall'inizio alla `respondAllow` e aggiungere `slog.Duration("decision_ms", ...)`. Utile per profiling del PDP sotto carico.
- **`X-Request-ID` correlato lato `iam-service`**: l'header è già iniettato da Envoy, ma le `slog.X` dei singoli handler non lo leggono. Va letto e propagato (sempre via middleware §8.1).
- **`cert_subject` nel decision log dell'orchestrator**: il valore è già parsato in `cc.Subject` ma viene loggato solo da `evaluateStrictDeviceFingerprinting` in shadow mode. Aggiungerlo al log "decisione" principale rende il record auto-sufficiente per audit (oggi serve incrociare due righe).

### 8.2 Firewall — coperture aggiuntive

- **Anti-spoofing sull'`iif`**: aggiungere regole che droppano pacchetti con `ip saddr` di rete privata in arrivo su interfacce dove non dovrebbero esistere. Difesa contro forged source IP. Esempio: `iif eth0 ip saddr 127.0.0.0/8 drop`.
- **Rate-limit sulle connessioni complete (non solo SYN)**: oggi il meter agisce sul flag SYN. Aggiungere un secondo meter per-source su connessioni in stato `new` (handshake completato) limita anche flood applicativi che superano il SYN gate.
- **Protezione ICMP**: oggi `iif "lo" accept` + `ct state established,related` lasciano passare ICMP localhost e di risposta; `icmp echo-request` da remoto cade nel default DROP. Una regola esplicita con rate-limit (`icmp type echo-request limit rate 5/second accept`) permette diagnostica controllata senza esporre a flood ICMP.

### 8.3 Test — chiudere il cerchio sul firewall

- **Test empirico del SYN meter**: oggi `tests/e2e/nftables.sh` test 5 verifica solo che la regola sia *caricata*. Aggiungere un test che inietta un burst di 50 SYN dallo stesso IP, poi `grep -c "syn_flood" /var/log/ztaleaks/nftables/firewall.jsonl` e asserisce che il delta sia ≥ N (es. 20). Trasforma una verifica di config in una verifica di **comportamento**. La procedura manuale è già stata fatta e funziona — basta wrapparla in bash con assert.
