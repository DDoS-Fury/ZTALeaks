# ZTALeaks
📌 Progetto Overview
ZeroTrust-Lab è un'infrastruttura di microservizi progettata per implementare un controllo d'accesso adattivo basato sul rischio. Il sistema non si limita alla validazione delle credenziali (Identity), ma analizza l'integrità del dispositivo e del contesto tramite JA3 Fingerprinting, Mutual TLS (mTLS) e analisi comportamentale dinamica.

L'architettura segue i principi NIST Zero Trust (800-207), separando nettamente il Policy Enforcement Point (PEP) dal Policy Decision Point (PDP).

🏗️ Architettura del Sistema
Il sistema è composto dai seguenti moduli containerizzati:

Ingress Gateway (Envoy Proxy): Agisce come PEP. Gestisce la terminazione TLS, l'ispezione dei pacchetti (TLS Inspector) e delega l'autorizzazione tramite il protocollo ext_authz.

Security Orchestrator (Golang): Il "cuore" logico. Riceve i metadati da Envoy, calcola l'hash JA3, interroga il database di sicurezza e orchestra la chiamata verso OPA.

Policy Engine (Open Policy Agent): Agisce come PDP. Valuta le policy scritte in linguaggio Rego basandosi sugli attributi forniti (Resource, User Role, JA3 Trust, Cert Presence).

Persistence Layer (Dual MongoDB):

Security DB: Memorizza le impronte hardware (Device Trust) e i metadati dei certificati.

Business DB: Memorizza i dati applicativi e i profili utente.

Observability Stack (Splunk): Centralizza i log di sicurezza e di business per la correlazione degli eventi e l'alerting asincrono.

🛡️ Flusso di Sicurezza (Step-by-Step)
Handshake: Il client avvia una connessione HTTPS. Envoy esegue il TLS Inspector per estrarre i parametri dell'handshake (Cipher Suites, Extensions).

Intercettazione: Envoy sospende la richiesta e invia i metadati al Security Orchestrator.

Identificazione: * L'Orchestratore genera l'MD5 del JA3 string.

Verifica nel Security DB se l'hash è associato all'utente.

Decisione: OPA riceve l'input e restituisce un verdetto (Allow/Deny) basato sulla sensibilità della risorsa richiesta.

Esecuzione: Se autorizzato, la richiesta raggiunge la Business Logic.

Audit: Tutti i componenti inviano log a Splunk tramite lo stesso X-Request-ID per garantire la tracciabilità end-to-end.

📂 Struttura delle Directory
```text
.
├── deployments/         # Orchestrazione dei container (docker-compose) e test
├── docs/                # Documentazione estesa sull'architettura e testing
├── infra/
│   ├── databases/       # Script di init e configurazioni MongoDB (Business e Security)
│   ├── envoy/           # Configurazione Proxy (L4/L7) e mTLS
│   └── opa/             # Policy as Code (Rego files)
└── services/
    ├── business-logic/  # Servizio di Backend (Go): Business Logic
    └── security-orchestrator/ # Orchestratore (Go): JA3 Logic & DB Bridge
```
🔧 Specifiche Tecniche
1. Fingerprinting JA3
Il sistema utilizza l'ordine e la tipologia delle Cipher Suites e delle estensioni TLS per creare una firma univoca del client (browser/libreria). Questo permette di identificare bot o tentativi di impersonificazione anche se le credenziali sono corrette.

2. Segmentazione di Rete (Docker Networks)
Front-Net: Isola Envoy e l'Orchestratore dal mondo esterno.

Auth-Net: Canale privato tra Orchestratore e OPA.

Back-Net: Connessione esclusiva tra Business Logic e Business DB.

Security Note: Il Business DB non è raggiungibile dall'esterno né dal Security Orchestrator.

3. Analisi dei Log (Splunk HEC)
I log vengono inviati tramite HTTP Event Collector (HEC) in formato JSON.

Correlation: Utilizzo di request_id per unire log di accesso e operazioni sul database.

Alerting: Query programmate per rilevare Impossible Travel o Credential Stuffing.

🚀 Setup e Installazione

📌 **Documentazione Completa:**
- 📖 [Architettura e Componenti ZTA](docs/architecture.md)
- 🚀 [Guida di Avvio e Testing](docs/getting-started.md)

**Prerequisiti:** Docker & Docker Compose installati.

**Configurazione:** Clonare il repository e configurare il file `.env` con i token di Splunk e le password dei DB.

**Avvio:**
```bash
docker-compose -f deployments/docker-compose/docker-compose.yaml up -d --build
```
