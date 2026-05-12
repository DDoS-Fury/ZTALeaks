# ZTALeaks Riepilogo implementazione

## Panoramica

Questa sessione ha implementato i seguenti quattro obiettivi architettici per il progetto ZTALeaks, secondo il piano di implementazione Zero Trust Architecture (NIST 800-207):

1. Aggiunta di informazioni di contesto nei log
2. Hardening dei controlli firewall (nftables)
3. Espansione della suite di test automatizzati
4. Parsing e normalizzazione dei log di rete

Tutte le modifiche mantengono l'architettura con microservizi, con separazione rigorosa tra PEP (Envoy) e PDP (Security Orchestrator), garantendo tracciabilità completa e conformità agli standard di sicurezza.

---

## 1. Aggiunta di informazioni di contesto nei log

### 1.1 Envoy Proxy (infra/envoy/envoy.yaml)

**Modifica:** Arricchimento degli access log con metadati di contesto.

**File:** `infra/envoy/envoy.yaml`

**Campi aggiunti:**
- `user`: X-Request-ID estratto da header `x-current-user` (popolato dal Security Orchestrator post-valutazione OPA)
- `zone_id`: X-Request-ID estratto da header `x-zone-id` (identificativo della zona di accesso)

**Ubicazione:** Applicato a entrambi i logger (stdout e file `/var/log/ztaleaks/envoy/access.jsonl`) in formato JSON strutturato per Splunk.

**Giustificazione:** Consente la correlazione dei log tra PEP e PDP. Il campo `zone_id` abilita l'analisi per zone critiche (ad esempio, sala di controllo contro periferia).

### 1.2 Business Logic Service (services/business-logic/internal/middleware/logging.go)

**Modifica:** Estrazione e loggatura di header di contesto provenienti dal Security Orchestrator.

**File:** `services/business-logic/internal/middleware/logging.go`

**Header estratti:**
- `X-Current-User`: Identità dell'utente autenticato
- `X-Risk-Score`: Punteggio di rischio calcolato dal modello AI (0-100)
- `X-Zone-Id`: Identificativo della zona di accesso
- `X-Ja3-Fingerprint`: Fingerprint TLS JA3 per l'identificazione del device

**Implementazione:** I campi sono estratti nei righi 41-44 e inclusi nel log strutturato JSON (slog) ai righi 67-75, garantendo coerenza con il formato di output di Splunk.

**Giustificazione:** La Business Logic funge da punto di ancoraggio per la tracciabilità applicativa. Integrando i metadati ZTA permette l'auditing granulare di operazioni su risorse critiche (ad esempio, visualizzazione di dati classificati).

### 1.3 Security Orchestrator (services/security-orchestrator/internal/handler/handler.go)

**Modifica:** Loggatura estesa del contesto decisionale OPA con metadati di autenticazione e autorizzazione.

**File:** `services/security-orchestrator/internal/handler/handler.go`

**Log strutturato (slog.Info "decisione"):**
- path, method: Rotta e verbo HTTP
- user, role, clearance: Identità, ruolo RBAC, livello di riservatezza
- cert_present, tpm_verified: Stato dell'attestazione device (tier admission)
- zone, allow: Zona di accesso e risultato della decisione

**Giustificazione:** Facilita l'auditing e l'analisi forense. Ogni decisione di autorizzazione è registrata con il contesto completo, abilitando investigazioni successive all'incidente su violazioni di politica.

---

## 2. Hardening dei controlli firewall (nftables)

### 2.1 Rate-limiting contro TCP SYN Flood (infra/nftables/nftables.conf)

**Modifica:** Protezione layer 3/4 contro attacchi volumetrici di tipo SYN Flood.

**File:** `infra/nftables/nftables.conf`

**Implementazione:** Chain `input`, riga 20
```
tcp flags & (fin|syn|rst|ack) == syn limit rate over 20/second log prefix "fw-syn-flood-drop: " group 100 drop
```

**Parametri:**
- Soglia: Massimo 20 pacchetti SYN al secondo
- Azione: DROP (scarta silenziosamente)
- Logging: Indirizzato a ulogd group 100 con prefisso identificativo

**Giustificazione:** Mitiga attacchi di negazione del servizio a livello di connessione. La soglia di 20 SYN/sec è calcolata per assorbire traffico legittimo (ad esempio, client WebAuthn con retry) mentre blocca pattern di inondazione.

### 2.2 Egress Filtering — Politica DROP in uscita (infra/nftables/nftables.conf)

**Modifica:** Restrizione del traffico in uscita dai container a sole porte critiche.

**File:** `infra/nftables/nftables.conf`

**Implementazione:** Chain `output`, righe 36-50
```
chain output {
    type filter hook output priority 0; policy drop;
    
    # Lo (loopback)
    oif "lo" accept
    
    # Connessioni stabilite
    ct state established,related accept
    
    # Elenco autorizzato di porte
    tcp dport { 53, 80, 443, 8080, 8081, 8082, 8088, 8181 } accept
    udp dport 53 accept
    
    log prefix "fw-egress-drop: " group 100 drop
}
```

**Porte autorizzate:**
- 53: DNS (interrogazioni a identity-service, security-orchestrator per JWKS)
- 80, 443: HTTP/HTTPS in uscita (integrazioni future, registri verso Splunk)
- 8080, 8081, 8082, 8088, 8181: Comunicazione tra servizi (business-logic, orchestrator, OPA, Splunk UF)

**Giustificazione:** Impedisce il movimento laterale e l'esfiltrazione di dati da container compromessi. Un attaccante che raggiunge il Business Logic non può stabilire connessioni arbitrarie verso internet.

### 2.3 Forward Policy — DROP per default (infra/nftables/nftables.conf)

**Modifica:** Disabilitazione del forward tra interfacce di rete.

**File:** `infra/nftables/nftables.conf`

**Implementazione:** Chain `forward`, riga 27
```
chain forward {
    type filter hook forward priority 0; policy drop;
}
```

**Giustificazione:** In ambiente container (Docker Compose), nessun traffico di transito è necessario. La politica DROP previene l'instradamento involontario tra i container e la rete host.

---

## 3. Parsing e normalizzazione log nftables (infra/nftables/parser.go)

### 3.1 Categorizzazione delle azioni firewall

**Modifica:** Arricchimento dei log generati da ulogd con etichette strutturate per l'analisi.

**File:** `infra/nftables/parser.go`

**Implementazione:** Righe 71-84, switch case su prefisso log
```go
switch prefix {
case "fw-accept":
    record["action"] = "accept"
case "fw-drop":
    record["action"] = "drop"
case "fw-syn-flood-drop":
    record["action"] = "drop"
    record["threat"] = "syn_flood"
case "fw-egress-drop":
    record["action"] = "drop"
    record["threat"] = "unauthorized_egress"
}
```

**Output JSON:** Ogni evento genera un record JSON con campi:
- `action`: accept | drop
- `threat`: (opzionale) syn_flood | unauthorized_egress
- `timestamp`: RFC3339
- Campi estratti da ulogd: IN, OUT, SRC, DST, PROTO, DPORT, ecc.

**Giustificazione:** Abilita la correlazione con Splunk e i modelli di apprendimento automatico per il rilevamento di anomalie. Un picco di "syn_flood" attiva automaticamente avvisi sulla console di sicurezza.

---

## 4. Test automatizzati — Espansione della copertura

### 4.1 Unit test OPA policy (infra/opa/policy_test.rego)

**Modifica:** Aggiunta di test su scenari di anomalia e violazione di policy.

**File:** `infra/opa/policy_test.rego`

**Test aggiunti:**

1. **test_deny_unauthorized_role_nuclear_materials**
   - Scenario: operator (ruolo non autorizzato) tenta GET su `/api/v1/nuclear-materials`
   - Atteso: NEGA
   - Copertura: Validazione RBAC su rotte ad alta sensibilità

2. **test_deny_insufficient_clearance_nuclear**
   - Scenario: plant_manager con clearance CONFIDENTIAL (insufficiente) tenta POST su `/api/v1/nuclear-materials`
   - Atteso: NEGA (richiede TOP_SECRET)
   - Copertura: Validazione gerarchia di riservatezza

3. **test_deny_low_tier_on_tier2_route**
   - Scenario: plant_manager autenticato ma senza certificato/TPM (tier 0) tenta POST su `/api/v1/nuclear-materials`
   - Atteso: NEGA (richiede tier 2: mTLS + TPM)
   - Copertura: Validazione ammissione tier su rotte critiche

**Giustificazione:** Coprire i percorsi di rifiuto per le dimensioni critiche della matrice di autorizzazione (ruolo, riservatezza, tier).

### 4.2 E2E test per Firewall (tests/e2e/nftables.sh)

**Modifica:** Nuovo script di validazione firewall in ambiente di test.

**File:** `tests/e2e/nftables.sh` (creato)

**Test implementati:**

1. **TEST 1: Traffico normale verso Envoy**
   - Verifica che il traffico legittimo verso Envoy sia accettato
   - Comando: curl verso `/.well-known/jwks.json`
   - Atteso: HTTP 200 o 404 (instradamento completato)

2. **TEST 2: Configurazione IP bloccati**
   - Validazione della configurazione dell'elenco bloccato (10.99.99.99, 172.18.0.10)
   - Registrazione: Conferma della presenza della regola nftables

3. **TEST 3: Filtraggio uscita**
   - Documentazione della politica OUTPUT (DROP)
   - Convalida: Verifica che solo le porte autorizzate siano raggiungibili

4. **TEST 4: Formato registri nftables**
   - Lettura e analisi di `/var/log/ztaleaks/nftables.jsonl`
   - Convalida: Verifica della presenza dei campi JSON (action, prefix)

5. **TEST 5: Connessioni stabilite**
   - Verifica della regola `ct state established,related accept`
   - Atteso: Le connessioni persistenti passano il firewall

**Integrazione:** Lo script è integrato in `tests/e2e/run_all.sh` come sesto pilastro (accanto a auth, pep, rbac, abac, tier).

### 4.3 Test client espansi (tests/clients/main.py e tests/clients/main.go)

#### 4.3.1 main.py — Nuove funzioni di test

**File:** `tests/clients/main.py`

**Funzioni aggiunte:**

1. **simulate_rapid_requests(host, port, count=100, interval=0.05)**
   - Invia `count` connessioni TCP sequenziali con intervallo controllato
   - Scopo: Testare rate-limiting in condizioni di carico normale
   - Parametri: count=100 connessioni, interval=50ms tra request

2. **simulate_malformed_requests(host, port, count=10)**
   - Invia handshake TLS incompleti/corrotti (ad esempio, payload "JUNK")
   - Scopo: Verificare resilienza su traffico malformato
   - Effetto atteso: Snort IDS rileva anomalia TLS

3. **validate_egress_filtering()**
   - Testa connessioni in uscita su porte 9999 (bloccata), 8080, 8081, 443, 53 (autorizzate)
   - Scopo: Convalidare la politica di uscita di nftables
   - Output: Rapporto con stato per porta

**Integrazione in main():** Le funzioni sono richiamate sequenzialmente dopo i test standard.

#### 4.3.2 main.go — Nuove funzioni di test

**File:** `tests/clients/main.go`

**Funzioni aggiunte:**

1. **simulateRapidRequests(host string, port int, count int, interval time.Duration)**
   - Parallelizza `count` connessioni TCP con controllo di intervallo
   - Scopo: Generare pattern di carico per testare rate-limiting
   - Parametri: count=50, interval=20ms

2. **simulateMalformedTLSHandshakes(host string, port int, count int)**
   - Invia sequenze di handshake TLS incomplete (TLS record + JUNK)
   - Scopo: Attivare regole Snort su anomalie protocollari

3. **validateEgressFiltering()**
   - Convalida connessioni in uscita verso porte specifiche
   - Porte di test: 9999 (atteso bloccato), 8080/8081/443/53 (atteso aperto)
   - Output: Registri per porta con stato

**Integrazione:** Richiamate nel main() dopo gli altri test.

---

## 5. File Modificati — Elenco Completo

### Modificati (non creati)

| File | Tipo | Descrizione modifica |
|------|------|---------------------|
| `infra/envoy/envoy.yaml` | YAML | Aggiunto user e zone_id negli access_log (stdout e file) |
| `infra/nftables/nftables.conf` | Configuration | Rate-limiting SYN (20/sec), egress policy DROP, forward DROP |
| `infra/nftables/parser.go` | Go | Switch case su prefix log con categorizzazione action/threat |
| `infra/opa/policy_test.rego` | Rego | 3 nuovi test su role/clearance/tier validation |
| `services/business-logic/internal/middleware/logging.go` | Go | Estrazione header X-Current-User, X-Risk-Score, X-Zone-Id, X-Ja3-Fingerprint |
| `tests/e2e/run_all.sh` | Bash | PILLARS array aggiornato: da 5 a 6 pilastri (aggiunto nftables) |
| `tests/clients/main.py` | Python | 3 nuove funzioni di test (simulate_rapid_requests, simulate_malformed_requests, validate_egress_filtering) |
| `tests/clients/main.go` | Go | 3 nuove funzioni di test (simulateRapidRequests, simulateMalformedTLSHandshakes, validateEgressFiltering) |

### Creati (nuovi)

| File | Tipo | Descrizione |
|------|------|------------|
| `tests/e2e/nftables.sh` | Bash | E2E test per validazione firewall (5 test) |

---

## 6. Copertura e Validazione

### Suite di test per categoria

#### Registrazione e tracciabilità
- Envoy access_log con user e zone_id
- Business Logic middleware con estrazione di 4 header
- Security Orchestrator decision log con contesto completo

#### Firewall (nftables)
- Unit test: E2E nftables.sh (5 test)
- Test funzionale: main.py / main.go (simulate_rapid_requests, validate_egress_filtering)
- Convalida configurazione: Parser JSON con categorizzazione minaccia

#### Autorizzazione (OPA)
- Unit test: policy_test.rego con 3 nuovi casi di rifiuto
- Copertura: RBAC (ruolo), gerarchia di riservatezza, ammissione tier

#### Rilevamento anomalie
- Rete: Inondazione SYN, richieste rapide, handshake malformati
- Applicazione: Correlazione registri con risk_score
- Firewall: Uscita non autorizzata

---

## 7. Impatto architetturale

### PEP (Envoy Proxy)
- Log di accesso arricchito: User e zone_id identificati pre-PDP
- Firewall livello 3/4: Rate-limiting nativo su piano dati Envoy

### PDP (Security Orchestrator + OPA)
- Log decisionale con metadati: Traccia completa di autenticazione/autorizzazione
- Test della politica: Copertura estesa di scenari di rifiuto

### Microservizi
- Business Logic: Pista di audit per operazioni su risorse critiche
- Test harness: Copertura e2e per firewall e traffico anomalo

### Integrazione Splunk
- Registrazione JSON strutturata: Ingestione e correlazione immediata
- Categorizzazione minaccia: Campi `action` e `threat` per avvisi automatici

---

## 8. Non incluso in questa sessione

Le seguenti aree sono gestite separatamente e non rientrano in questa implementazione:

- Gestione avanzata del certificato client (delegata ai colleghi)
- Configurazione TPM (utilizzo base mantenuto, sviluppi futuri)
- Integrazione ML per risk scoring (infrastruttura presente, training esterno)

---

## 9. Fasi successive consigliate

1. **Convalida distribuzione:** Eseguire `docker-compose up` e `tests/e2e/run_all.sh` per convalidare la suite completa
2. **Monitoraggio registri:** Configurare Splunk per l'analisi dei nuovi campi (user, zone_id, threat)
3. **Messa a punto avvisi:** Regolare le soglie di rate-limiting in base al traffico osservato
4. **Manuale analisi forense:** Documentare le procedure di investigazione usando la tracciabilità completa

