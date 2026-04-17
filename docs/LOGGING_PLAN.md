# Logging & Splunk Integration Plan

Piano di implementazione per la raccolta centralizzata dei log di tutti i servizi ZTALeaks (Snort, Envoy, Security Orchestrator, Business Logic, OPA, nftables, MongoDB) e l'inoltro a Splunk, con eventuale persistenza selettiva nel Security DB.

## 1. Obiettivi

- **Centralizzare** i log di tutti i container in un'unica pipeline.
- **Normalizzare** gli eventi in JSON per indicizzazione Splunk senza regex fragili.
- **Correlare** richieste end-to-end tramite `X-Request-ID` condiviso fra Envoy → Orchestrator → Business Logic → OPA.
- **Non perdere eventi** di sicurezza in caso di indisponibilità temporanea di Splunk (buffering su disco).
- **Separare** il piano di osservabilità (Splunk) da quello decisionale (Security DB): Splunk è la source of truth; il Security DB riceve solo ciò che serve alla PDP.

## 2. Architettura proposta

```
┌──────────────┐   file JSON   ┌──────────────────┐   splunktcp/HEC   ┌──────────┐
│  Snort       │──────────────▶│                  │──────────────────▶│          │
│  Envoy       │  volume RO    │  Splunk          │                   │  Splunk  │
│  Orchestr.   │──────────────▶│  Universal       │                   │  Indexer │
│  BizLogic    │               │  Forwarder (UF)  │                   │          │
│  OPA         │──────────────▶│                  │                   └─────┬────┘
│  nftables    │               └──────────────────┘                         │
│  MongoDB     │                                                            │
└──────────────┘                                                            │
                                                                            ▼
                                                              ┌───────────────────────┐
                                                              │ Alert action /        │
                                                              │ consumer → Security DB │
                                                              └───────────────────────┘
```

**Pattern**: *Universal Forwarder + volumi condivisi read-only*.
Ogni servizio scrive log strutturati su un volume dedicato; un container UF li monta RO e inoltra a Splunk.

### Perché non HEC diretto da ogni container?
- HEC diretto perde eventi se Splunk è irraggiungibile (nessun buffer persistente).
- Un cambio di endpoint Splunk richiederebbe redeploy di tutti i servizi.
- L'UF fornisce buffering, compressione, ack, e un unico punto di configurazione/credenziali.

## 3. Layout filesystem (volumi)

```
/var/log/ztaleaks/
├── snort/           alert_json.txt, stats.log
├── envoy/           access.jsonl, admin.log
├── orchestrator/    app.jsonl
├── business-logic/  app.jsonl
├── opa/             decision.jsonl
├── nftables/        firewall.jsonl (via ulogd o logger)
└── mongodb/         mongod.log (già JSON nativo da 4.4+)
```

Volume Docker dedicato `ztaleaks_logs` montato:
- **rw** nei container che producono log,
- **ro** nel container Splunk UF.

## 4. Modifiche per servizio

### 4.1 Snort (`infra/snort/`)
- Configurare output plugin **`alert_json`** in `snort.lua` (Snort 3) o `alert_json` via `u2json` (Snort 2).
- Path: `/var/log/ztaleaks/snort/alert_json.txt`.
- Rotazione con `logrotate` nel container (daily, keep 7, compress).
- Sourcetype Splunk: `snort:alert:json`.

### 4.2 Envoy (`infra/envoy/`)
- Access log in formato JSON strutturato via `access_log` con `json_format`:
  - Campi chiave: `request_id`, `ja3_hash`, `client_cert_subject`, `ext_authz_decision`, `upstream_cluster`, `response_code`, `duration`.
- Output su `/var/log/ztaleaks/envoy/access.jsonl`.
- Sourcetype: `envoy:access:json`.

### 4.3 Security Orchestrator (`services/security-orchestrator/`)
- Logger strutturato Go (`log/slog` JSON handler o `zerolog`).
- Campi: `request_id`, `ja3_md5`, `device_trust_level`, `opa_decision`, `user`, `resource`.
- Output su stdout **e** su file `/var/log/ztaleaks/orchestrator/app.jsonl` (double-write per sopravvivere al restart del container).
- Sourcetype: `ztaleaks:orchestrator`.

### 4.4 Business Logic (`services/business-logic/`)
- Stesso pattern: `slog` JSON, campi `request_id`, `user`, `collection`, `operation`, `latency_ms`.
- Sourcetype: `ztaleaks:business`.

### 4.5 OPA (`opa/`, da aggiungere)
- Abilitare **decision logs** (`--set decision_logs.console=true` con formato JSON) e/o plugin file.
- Campi nativi: `decision_id`, `input`, `result`, `path`, `timestamp`.
- Sourcetype: `opa:decision`.

### 4.6 nftables (`infra/nftables/`)
- Aggiungere regole `log prefix "ztaleaks-fw: " level info` per drop/reject rilevanti.
- Catturare via `ulogd2` con output JSON su `/var/log/ztaleaks/nftables/firewall.jsonl`, oppure parsing di `journald`/`dmesg` dall'host.
- Sourcetype: `nftables:drop`.

### 4.7 MongoDB (Security DB e Business DB)
- `mongod` già emette JSON nativo. Redirigere su volume condiviso.
- Sourcetype: `mongodb:log`.

## 5. Nuovo container: Splunk Universal Forwarder

### 5.1 Struttura
```
infra/splunk-uf/
├── Dockerfile
├── inputs.conf
├── outputs.conf
└── entrypoint.sh
```

### 5.2 `inputs.conf` (scheletro)
```ini
[monitor:///var/log/ztaleaks/snort/alert_json.txt]
sourcetype = snort:alert:json
index = ztaleaks_security

[monitor:///var/log/ztaleaks/envoy/access.jsonl]
sourcetype = envoy:access:json
index = ztaleaks_access

[monitor:///var/log/ztaleaks/orchestrator/app.jsonl]
sourcetype = ztaleaks:orchestrator
index = ztaleaks_app
# ... etc.
```

### 5.3 `outputs.conf`
```ini
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = <SPLUNK_HOST>:9997
useACK = true
```

Credenziali/token via `.env` (non committare).

### 5.4 docker-compose
```yaml
splunk-uf:
  build: ./infra/splunk-uf
  container_name: ztaleaks_splunk_uf
  volumes:
    - ztaleaks_logs:/var/log/ztaleaks:ro
  environment:
    - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
    - SPLUNK_HOST=${SPLUNK_HOST}
  networks:
    - front-net   # accesso Internet/Splunk
  restart: unless-stopped
```

## 6. Indici e sourcetype Splunk

| Indice              | Contenuto                                  |
|---------------------|--------------------------------------------|
| `ztaleaks_security` | Snort, nftables, OPA deny, auth failures   |
| `ztaleaks_access`   | Envoy access log                           |
| `ztaleaks_app`      | Orchestrator, business-logic               |
| `ztaleaks_infra`    | MongoDB, container stdout residui          |

Definire i sourcetype in `props.conf` sul lato indexer con `KV_MODE=json`, `TIME_PREFIX`, `LINE_BREAKER` appropriati.

## 7. Correlazione end-to-end

- Envoy genera/propaga `x-request-id` (già default).
- Orchestrator, Business Logic e OPA **devono** loggare il medesimo `request_id` prelevato dall'header.
- In Splunk: `index=ztaleaks_* request_id=<id> | transaction request_id` ricostruisce la richiesta completa.

## 8. Flusso Splunk → Security DB

Due opzioni, da valutare dopo l'integrazione OPA:

1. **Splunk Alert Action** (preferita): ricerca salvata (es. "device con JA3 sconosciuto dopo 3 handshake") → webhook verso un piccolo *enricher* Go che scrive nel Security DB.
2. **Splunk DB Connect** verso MongoDB (richiede licenza Enterprise; meno flessibile per logica custom).

In entrambi i casi il Security DB resta isolato su `auth-net`; il consumer va collocato lì.

## 9. Rotazione e retention

- `logrotate` in ogni container produttore (daily, keep 7, compress, copytruncate) per evitare che i file crescano illimitatamente mentre l'UF tiene file descriptor aperti.
- Retention Splunk lato indexer (es. 30gg hot, 90gg cold) — fuori scope di questo repo.

## 10. Sicurezza

- Volume log **read-only** per l'UF: impedisce che un UF compromesso corrompa i log originali.
- Traffico UF → Indexer su TLS (`sslRootCAPath`, `sslVerifyServerCert = true`).
- Token HEC/credenziali solo via `.env`, mai in immagine.
- Nessun log deve contenere credenziali, JWT completi o chiavi private: aggiungere redattori lato servizio (`slog` Replacer) prima del write.

## 11. Fasi di implementazione

- [ ] **Fase 1 — Fondamenta**
  - [ ] Creare volume `ztaleaks_logs` in `docker-compose.yml`.
  - [ ] Aggiungere logger JSON strutturato a Orchestrator e Business Logic (`slog`).
  - [ ] Propagare `X-Request-ID` end-to-end.
- [ ] **Fase 2 — Snort & Envoy**
  - [ ] Configurare `alert_json` in Snort.
  - [ ] Configurare access log JSON in Envoy con campi JA3/ext_authz.
- [ ] **Fase 3 — Universal Forwarder**
  - [ ] Scrivere `infra/splunk-uf/` (Dockerfile + `inputs.conf` + `outputs.conf`).
  - [ ] Integrare nel compose con volume RO.
  - [ ] Testare ingestion su Splunk di dev.
- [ ] **Fase 4 — OPA (dopo aggiunta container)**
  - [ ] Abilitare decision logs JSON.
  - [ ] Aggiungere monitor path all'UF.
- [ ] **Fase 5 — Feedback loop**
  - [ ] Definire alert Splunk rilevanti.
  - [ ] Implementare consumer webhook → Security DB.
- [ ] **Fase 6 — Hardening**
  - [ ] TLS UF↔Indexer, redazione campi sensibili, logrotate in ogni produttore.

## 12. Verifica

- `docker exec ztaleaks_splunk_uf /opt/splunkforwarder/bin/splunk list monitor` mostra tutti i path attesi.
- Ricerca Splunk `index=ztaleaks_* | stats count by sourcetype` mostra eventi da ogni sourcetype.
- Test di correlazione: una singola richiesta end-to-end produce eventi con lo stesso `request_id` in `envoy:access:json`, `ztaleaks:orchestrator`, `opa:decision`, `ztaleaks:business`.
- Stop dell'indexer per 5 min → riavvio → nessun evento perso (verificare ACK UF).
