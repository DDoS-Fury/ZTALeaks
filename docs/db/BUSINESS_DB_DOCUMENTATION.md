
# Business Database - Documentazione Tecnica Completa

## Progetto ZTALeaks - Zero Trust Architecture per Centrale Nucleare

---

### Indice

1. [Obiettivo e contesto](#1-obiettivo-e-contesto)
2. [Architettura del database](#2-architettura-del-database)
3. [Modello di sicurezza dei dati](#3-modello-di-sicurezza-dei-dati)
4. [Integrazione ZTNA](#4-integrazione-ztna)
5. [Configurazione MongoDB](#5-configurazione-mongodb)
6. [Utenti e controllo degli accessi](#6-utenti-e-controllo-degli-accessi)
7. [Collection: personnel](#7-collection-personnel)
8. [Collection: access_badges](#8-collection-access_badges)
9. [Collection: zones](#9-collection-zones)
10. [Collection: reactor_parameters](#10-collection-reactor_parameters)
11. [Collection: maintenance_orders](#11-collection-maintenance_orders)
12. [Collection: documents](#12-collection-documents)
13. [Collection: nuclear_materials](#13-collection-nuclear_materials)
14. [Indici e ottimizzazione delle query](#14-indici-e-ottimizzazione-delle-query)
15. [Seed del database](#15-seed-del-database)
16. [Containerizzazione](#16-containerizzazione)
17. [Struttura della cartella](#17-struttura-della-cartella)
18. [Flusso di valutazione delle policy](#18-flusso-di-valutazione-delle-policy)

---

### 1. Obiettivo e contesto

Il Business Database rappresenta l'insieme delle risorse applicative che l'architettura Zero Trust deve proteggere. Lo scenario scelto e' quello di una centrale nucleare, un dominio in cui:

- esistono ruoli operativi con responsabilita' e privilegi nettamente distinti;
- le informazioni hanno livelli di sensibilita' molto diversi, dal dato pubblico fino al materiale classificato TOP_SECRET;
- l'accesso ai dati deve essere valutato in base a identita', ruolo, clearance, dispositivo, rete, posizione fisica e livello di rischio corrente;
- la correlazione tra accesso fisico e accesso digitale e' un requisito di sicurezza reale.

Il database e' realizzato con MongoDB 7, containerizzato con Docker, e popolato tramite un'applicazione Go dedicata.

---

### 2. Architettura del database

Il database `nuclear_plant_db` contiene 7 collection:

| Collection | Scopo | Sensibilita' tipica |
|---|---|---|
| `personnel` | Anagrafica del personale, ruolo, clearance, qualifiche, metadati ZTNA | CONFIDENTIAL |
| `access_badges` | Badge di accesso fisico, zone autorizzate, log di accesso con contesto | CONFIDENTIAL |
| `zones` | Aree della centrale, requisiti di sicurezza, policy ZTNA per zona | INTERNAL - TOP_SECRET |
| `reactor_parameters` | Parametri operativi del reattore in serie temporale | SECRET |
| `maintenance_orders` | Ordini di lavoro di manutenzione con ciclo di vita completo | INTERNAL - CONFIDENTIAL |
| `documents` | Documenti tecnici, procedure, manuali, report, analisi | INTERNAL - TOP_SECRET |
| `nuclear_materials` | Inventario del materiale nucleare e radioattivo | SECRET - TOP_SECRET |

Le collection sono progettate per essere sufficienti a rappresentare in modo realistico il dominio e a fornire una base concreta per la definizione di policy Zero Trust.

---

### 3. Modello di sicurezza dei dati

#### 3.1 Livelli di classificazione

Ogni collection include il campo `classification_level` che indica la sensibilita' del dato. I livelli sono ordinati gerarchicamente:

| Livello | Significato |
|---|---|
| `PUBLIC` | Dato accessibile senza restrizioni |
| `INTERNAL` | Dato riservato al personale della centrale |
| `CONFIDENTIAL` | Dato la cui divulgazione causerebbe danni significativi |
| `SECRET` | Dato la cui divulgazione comprometterebbe la sicurezza dell'impianto |
| `TOP_SECRET` | Dato la cui divulgazione avrebbe conseguenze gravissime per la sicurezza nazionale |

Il `clearance_level` di un dipendente determina il livello massimo di classificazione a cui puo' accedere. Il PDP (Policy Decision Point) confronta il clearance dell'utente con la classificazione della risorsa richiesta durante ogni decisione di accesso.

#### 3.2 Ruoli operativi

Sono definiti 6 ruoli che modellano le funzioni operative della centrale:

| Ruolo | Significato | Clearance tipica |
|---|---|---|
| `operator` | Operatore di impianto, conduce il reattore dalla sala controllo | SECRET |
| `maintenance_technician` | Tecnico di manutenzione meccanica, elettrica o strumentale | CONFIDENTIAL |
| `radiation_protection_officer` | Responsabile della radioprotezione e del monitoraggio dosimetrico | SECRET |
| `security_officer` | Responsabile della sicurezza fisica dell'impianto | SECRET |
| `plant_manager` | Direttore di impianto, massima autorita' operativa | TOP_SECRET |
| `inspector` | Ispettore esterno (ISIN, IAEA), accesso temporaneo per verifiche | TOP_SECRET |

I ruoli determinano:
- quali collection e documenti un utente puo' leggere o modificare;
- a quali zone fisiche puo' accedere;
- quali operazioni CRUD puo' eseguire sulle risorse.

---

### 4. Integrazione ZTNA

Il database integra direttamente nel modello dati i parametri necessari alla valutazione delle policy Zero Trust. Questo approccio consente al PDP di interrogare il database per ottenere tutti gli attributi necessari a una decisione di accesso senza dover consultare sistemi esterni.

#### 4.1 Metadati ZTNA sull'identita' (personnel)

Ogni record del personale include un sotto-documento `ztna_metadata` con i seguenti attributi:

| Campo | Tipo | Significato |
|---|---|---|
| `trust_score` | double | Punteggio di fiducia calcolato dall'analisi comportamentale (0.0 - 1.0) |
| `last_trust_evaluation` | date | Timestamp dell'ultimo calcolo del trust score |
| `risk_flags` | array | Indicatori di rischio attivi (es. `expired_qualification`, `external_entity`, `anomalous_access_pattern`) |
| `mfa_enrolled` | bool | Se l'utente ha configurato l'autenticazione multi-fattore |
| `last_successful_auth` | date | Timestamp dell'ultima autenticazione riuscita |
| `failed_auth_count` | int | Conteggio dei tentativi di autenticazione falliti nella finestra corrente |
| `access_review_date` | date | Data dell'ultima revisione periodica degli accessi |

Il trust score e' un valore numerico tra 0.0 e 1.0 che sintetizza la fiducia nell'identita' sulla base di:
- storico degli accessi e comportamento;
- stato delle qualifiche e della formazione;
- risultati dei controlli medici;
- pattern di accesso fisico e digitale.

I risk flags sono etichette che segnalano condizioni specifiche che possono ridurre il trust score o bloccare l'accesso a determinate risorse.

#### 4.2 Policy ZTNA sulle zone (zones)

Ogni zona include un sotto-documento `ztna_policy` che definisce i requisiti Zero Trust per l'accesso:

| Campo | Tipo | Significato |
|---|---|---|
| `min_trust_score` | double | Trust score minimo richiesto per accedere alla zona |
| `require_mfa` | bool | Se l'autenticazione multi-fattore e' obbligatoria |
| `max_session_duration_minutes` | int | Durata massima della sessione prima della ri-autenticazione |
| `allowed_device_types` | array | Tipi di dispositivo ammessi (workstation, control_terminal, tablet, mobile) |
| `allowed_networks` | array | Segmenti di rete da cui l'accesso e' consentito (plant_internal, control_room_net, admin_net, vpn) |
| `continuous_monitoring` | bool | Se il monitoraggio comportamentale continuo e' attivo durante la sessione |

La logica di accesso per una zona e':

```
accesso_consentito =
    utente.clearance_level >= zona.required_clearance
    AND utente.ztna_metadata.trust_score >= zona.ztna_policy.min_trust_score
    AND (NOT zona.ztna_policy.require_mfa OR utente.ztna_metadata.mfa_enrolled)
    AND dispositivo.type IN zona.ztna_policy.allowed_device_types
    AND rete.segment IN zona.ztna_policy.allowed_networks
    AND utente.qualifications CONTAINS zona.required_qualifications
```

#### 4.3 Contesto di accesso fisico (access_badges)

Ogni entry nei log di accesso fisico (`access_log`) include un sotto-documento `context` che registra:

| Campo | Tipo | Significato |
|---|---|---|
| `device_type` | string | Tipo di dispositivo usato al momento dell'accesso |
| `network` | string | Segmento di rete da cui l'utente era connesso |
| `ip_address` | string | Indirizzo IP del dispositivo (opzionale) |

Questa informazione consente la correlazione tra accesso fisico e accesso digitale: se un utente risulta fisicamente nella zona amministrativa ma tenta di accedere digitalmente a risorse della zona reattore, il sistema puo' identificare l'anomalia.

#### 4.4 Integrita' dei dati operativi (reactor_parameters)

Ogni lettura dei parametri del reattore include il campo `data_integrity_hash`, un hash SHA-256 calcolato sui valori critici (potenza termica, potenza elettrica, pressione, flusso neutronico, concentrazione boro, stato reattore). Questo hash consente al Security Orchestrator di verificare che i dati non siano stati alterati durante il transito tra il database e il client.

#### 4.5 Calibrazione dei parametri ZTNA

I parametri ZTNA sono calibrati per riflettere il rischio reale di ogni zona:

| Zona | Trust score minimo | MFA | Sessione max | Monitoraggio continuo |
|---|---|---|---|---|
| ZONE-ADM-01 (Amministrazione) | 0.2 | No | 480 min | No |
| ZONE-MAIN (Campus) | 0.3 | No | 480 min | No |
| ZONE-TB-01 (Turbine) | 0.5 | No | 360 min | No |
| ZONE-AUX-01 (Ausiliario) | 0.5 | No | 360 min | No |
| ZONE-CR-01 (Sala Controllo) | 0.7 | Si' | 240 min | Si' |
| ZONE-RC-01 (Contenimento) | 0.85 | Si' | 120 min | Si' |
| ZONE-RC-01A (Contenimento inf.) | 0.9 | Si' | 60 min | Si' |
| ZONE-RC-01B (Contenimento sup.) | 0.85 | Si' | 90 min | Si' |
| ZONE-SF-01 (Combustibile esausto) | 0.9 | Si' | 60 min | Si' |

---

### 5. Configurazione MongoDB

Il file `mongod.conf` definisce la configurazione del server MongoDB:

- **Storage**: percorso dati `/data/db` con journaling abilitato per la durabilita' delle scritture.
- **Logging**: log su file con append e verbosity 1 per il tracciamento operativo.
- **Rete**: porta 27017, binding su `0.0.0.0`, limite di 100 connessioni concorrenti.
- **Sicurezza**: autenticazione e autorizzazione abilitate (`authorization: enabled`). Nessun accesso anonimo e' possibile.
- **Profiling**: le operazioni piu' lente di 200ms vengono registrate per analisi prestazionale.

---

### 6. Utenti e controllo degli accessi

Il database definisce 4 utenti di servizio, ciascuno con il minimo dei privilegi necessari:

| Utente | Ruolo MongoDB | Scopo | Permessi |
|---|---|---|---|
| `envoy_service` | readWrite | Usato dal PEP (Envoy) per inoltrare le operazioni CRUD autorizzate | Lettura e scrittura su tutte le collection |
| `seed_service` | readWrite | Usato dal container di seed per il popolamento iniziale | Lettura e scrittura su tutte le collection |
| `splunk_reader` | read | Usato dallo stack di osservabilita' (Splunk) per la raccolta log | Sola lettura |
| `pdp_reader` | read | Usato dal Policy Decision Point (OPA) per interrogare i metadati delle risorse | Sola lettura |

L'utente `seed_service` dovrebbe essere disabilitato dopo il popolamento iniziale in un ambiente di produzione. L'utente `pdp_reader` consente al PDP di leggere i campi `classification_level`, `ztna_policy`, `ztna_metadata` e `required_clearance` senza poter modificare alcun dato.

---

### 7. Collection: personnel

Rappresenta il personale della centrale. Ogni documento contiene l'identita' completa del dipendente, il suo ruolo, le qualifiche, le zone assegnate e i metadati ZTNA.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `employee_id` | string | Si' | Identificativo univoco, formato `NP-YYYY-NNNN` |
| `classification_level` | string | Si' | Sensibilita' del record |
| `first_name` | string | Si' | Nome |
| `last_name` | string | Si' | Cognome |
| `role` | string | Si' | Ruolo operativo (uno dei 6 ruoli definiti) |
| `department` | string | Si' | Reparto (operations, maintenance, security, management, radiation_protection, external) |
| `clearance_level` | string | Si' | Livello massimo di classificazione accessibile |
| `qualifications` | array | No | Certificazioni e abilitazioni con date di validita' |
| `assigned_zones` | array | No | Zone in cui il dipendente opera |
| `badge_id` | string | Si' | Badge associato, formato `BDG-*` |
| `contact` | object | No | Email, telefono, contatto di emergenza |
| `status` | string | Si' | Stato: active, inactive, suspended, terminated |
| `hire_date` | date | No | Data di assunzione |
| `last_medical_check` | date | No | Data ultimo controllo medico |
| `ztna_metadata` | object | No | Metadati Zero Trust (trust score, risk flags, MFA, auth history) |
| `created_at` | date | No | Data di creazione del record |
| `updated_at` | date | No | Data di ultimo aggiornamento |

#### Sotto-documento: qualifications

| Campo | Tipo | Descrizione |
|---|---|---|
| `name` | string | Nome della qualifica |
| `issued_by` | string | Ente emittente |
| `issue_date` | date | Data di emissione |
| `expiry_date` | date | Data di scadenza |
| `status` | string | Stato della qualifica |

#### Sotto-documento: ztna_metadata

| Campo | Tipo | Descrizione |
|---|---|---|
| `trust_score` | double | Punteggio di fiducia (0.0 - 1.0) |
| `last_trust_evaluation` | date | Timestamp ultimo calcolo |
| `risk_flags` | array | Indicatori di rischio attivi |
| `mfa_enrolled` | bool | Stato di enrollment MFA |
| `last_successful_auth` | date | Ultima autenticazione riuscita |
| `failed_auth_count` | int | Tentativi falliti nella finestra corrente |
| `access_review_date` | date | Ultima revisione periodica degli accessi |

#### Indici

- `employee_id`: univoco
- `role` + `department`: composito per query per reparto
- `badge_id`: univoco
- `clearance_level`: per filtraggio per livello di accesso
- `status`: per filtraggio rapido dei dipendenti attivi
- `ztna_metadata.trust_score`: per query sulle soglie di trust

---

### 8. Collection: access_badges

Modella i badge di accesso fisico e registra i log di attraversamento dei varchi.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `badge_id` | string | Si' | Identificativo univoco, formato `BDG-*` |
| `classification_level` | string | Si' | Sensibilita' del record |
| `employee_id` | string | Si' | Dipendente associato, formato `NP-*` |
| `type` | string | Si' | Tipo badge: permanent, temporary, visitor, contractor |
| `authorized_zones` | array | No | Zone accessibili con questo badge |
| `issue_date` | date | No | Data di emissione |
| `expiry_date` | date | No | Data di scadenza |
| `status` | string | Si' | Stato: active, inactive, revoked, expired |
| `access_log` | array | No | Log cronologico degli accessi fisici |

#### Sotto-documento: access_log[]

| Campo | Tipo | Descrizione |
|---|---|---|
| `timestamp` | date | Istante dell'evento |
| `gate_id` | string | Identificativo del varco |
| `direction` | string | Direzione: in, out |
| `zone_entered` | string | Zona raggiunta |
| `status` | string | Esito: granted, denied |
| `context` | object | Contesto del dispositivo e della rete |

#### Sotto-documento: context

| Campo | Tipo | Descrizione |
|---|---|---|
| `device_type` | string | Tipo di dispositivo (workstation, mobile, control_terminal, tablet) |
| `network` | string | Segmento di rete (plant_internal, control_room_net, admin_net, vpn) |
| `ip_address` | string | Indirizzo IP (opzionale) |

#### Indici

- `badge_id`: univoco
- `employee_id`: per lookup rapido dei badge di un dipendente
- `status` + `type`: per filtraggio dei badge attivi per tipo
- `expiry_date`: per identificazione dei badge in scadenza

---

### 9. Collection: zones

Rappresenta le aree fisiche della centrale con i loro requisiti di sicurezza e le policy ZTNA.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `zone_id` | string | Si' | Identificativo univoco, formato `ZONE-*` |
| `classification_level` | string | Si' | Sensibilita' delle informazioni sulla zona |
| `name` | string | Si' | Nome esteso |
| `code` | string | Si' | Codice sintetico (es. control_room, containment) |
| `type` | string | Si' | Tipo: public, controlled, restricted, exclusion |
| `radiation_zone` | bool | No | Presenza di rischio radiologico |
| `max_radiation_level` | string | No | Livello massimo di radiazione (medium, high, very_high) |
| `required_clearance` | string | Si' | Clearance minimo richiesto per l'accesso |
| `required_qualifications` | array | No | Qualifiche obbligatorie |
| `required_ppe` | array | No | Dispositivi di protezione individuale richiesti |
| `max_occupancy` | int | No | Numero massimo di occupanti simultanei |
| `access_points` | array | No | Punti di ingresso fisici |
| `parent_zone` | string | No | Zona padre nella gerarchia (null per la radice) |
| `sub_zones` | array | No | Sotto-zone contenute |
| `status` | string | Si' | Stato operativo |
| `ztna_policy` | object | No | Parametri Zero Trust per l'accesso alla zona |

#### Sotto-documento: access_points[]

| Campo | Tipo | Descrizione |
|---|---|---|
| `gate_id` | string | Identificativo del varco |
| `type` | string | Tipo: badge_reader, biometric, airlock |
| `status` | string | Stato: active, inactive, maintenance |

#### Sotto-documento: ztna_policy

| Campo | Tipo | Descrizione |
|---|---|---|
| `min_trust_score` | double | Trust score minimo richiesto (0.0 - 1.0) |
| `require_mfa` | bool | Se MFA e' obbligatorio |
| `max_session_duration_minutes` | int | Durata massima della sessione |
| `allowed_device_types` | array | Tipi di dispositivo ammessi |
| `allowed_networks` | array | Segmenti di rete ammessi |
| `continuous_monitoring` | bool | Se il monitoraggio continuo e' attivo |

#### Gerarchia delle zone

```
ZONE-MAIN (Main Campus)
  |- ZONE-CR-01  (Main Control Room)
  |- ZONE-RC-01  (Reactor Containment Building)
  |     |- ZONE-RC-01A (Containment - Lower Level)
  |     |- ZONE-RC-01B (Containment - Upper Level)
  |- ZONE-TB-01  (Turbine Hall)
  |- ZONE-AUX-01 (Auxiliary Building)
  |- ZONE-SF-01  (Spent Fuel Storage)
  |- ZONE-ADM-01 (Administration Building)
```

#### Indici

- `zone_id`: univoco
- `type` + `classification_level`: per filtraggio per categoria di zona
- `required_clearance`: per query sulle soglie di accesso

---

### 10. Collection: reactor_parameters

Contiene le letture temporali dei parametri operativi del reattore. E' una delle collection piu' sensibili.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `classification_level` | string | Si' | Tipicamente SECRET |
| `timestamp` | date | Si' | Istante della misura |
| `reactor_id` | string | Si' | Identificativo del reattore (es. REACTOR-01) |
| `thermal_power_mw` | double | No | Potenza termica in MW |
| `electrical_power_mw` | double | No | Potenza elettrica in MW |
| `coolant_temperature_inlet_c` | double | No | Temperatura ingresso refrigerante in gradi C |
| `coolant_temperature_outlet_c` | double | No | Temperatura uscita refrigerante in gradi C |
| `coolant_pressure_mpa` | double | No | Pressione del refrigerante in MPa |
| `coolant_flow_rate_kg_s` | double | No | Portata del refrigerante in kg/s |
| `neutron_flux` | double | No | Flusso neutronico |
| `control_rod_positions` | array | No | Posizione percentuale dei gruppi di barre di controllo |
| `boron_concentration_ppm` | int | No | Concentrazione di boro in ppm |
| `reactor_status` | string | Si' | Stato: shutdown, startup, power_operation, hot_standby, emergency_shutdown |
| `scram_status` | bool | No | Se lo SCRAM (arresto di emergenza) e' attivo |
| `alerts` | array | No | Segnalazioni operative |
| `recorded_by` | string | Si' | Dipendente che ha registrato la misura (formato NP-*) |
| `shift_id` | string | Si' | Identificativo del turno |
| `data_integrity_hash` | string | No | Hash SHA-256 dei parametri critici per rilevazione manomissioni |

#### Sotto-documento: control_rod_positions[]

| Campo | Tipo | Descrizione |
|---|---|---|
| `rod_group` | string | Gruppo di barre (A, B, C, D) |
| `position_percent` | double | Percentuale di estrazione (0 = completamente inserita) |

#### Indici

- `timestamp` (discendente) + `reactor_id`: per query temporali per reattore
- `reactor_status`: per filtraggio per stato operativo
- `recorded_by`: per tracciabilita' delle registrazioni
- `shift_id`: per raggruppamento per turno

---

### 11. Collection: maintenance_orders

Modella gli ordini di lavoro di manutenzione con il loro ciclo di vita completo.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `order_id` | string | Si' | Identificativo univoco, formato `MO-*` |
| `classification_level` | string | Si' | Sensibilita' dell'ordine |
| `title` | string | Si' | Titolo dell'intervento |
| `type` | string | Si' | Tipo: preventive, corrective, predictive |
| `priority` | string | Si' | Priorita': low, medium, high, critical |
| `system` | string | No | Sistema coinvolto (es. primary_coolant, emergency_core_cooling, hvac) |
| `equipment_id` | string | No | Apparato coinvolto |
| `zone_id` | string | No | Zona interessata, formato `ZONE-*` |
| `description` | string | No | Descrizione estesa dell'intervento |
| `safety_classification` | string | Si' | Classificazione nucleare: safety_related, non_safety, augmented_quality |
| `requested_by` | string | Si' | Dipendente richiedente, formato `NP-*` |
| `assigned_to` | array | No | Dipendenti assegnati |
| `status` | string | Si' | Stato: created, approved, scheduled, in_progress, completed, cancelled |
| `dates` | object | No | Date del ciclo di vita |
| `parts_required` | array | No | Componenti necessari |
| `radiation_work_permit` | string | No | Riferimento al permesso radiologico |
| `estimated_dose_msv` | double | No | Dose stimata in mSv |
| `procedures` | array | No | Procedure operative da seguire |
| `approval_chain` | array | No | Catena di approvazione con firme |

#### Sotto-documento: dates

| Campo | Tipo | Descrizione |
|---|---|---|
| `created` | date | Data di creazione |
| `approved` | date | Data di approvazione |
| `scheduled_start` | date | Inizio programmato |
| `scheduled_end` | date | Fine programmata |
| `actual_start` | date | Inizio effettivo |
| `actual_end` | date | Fine effettiva |

#### Sotto-documento: approval_chain[]

| Campo | Tipo | Descrizione |
|---|---|---|
| `role` | string | Ruolo dell'approvatore |
| `approved_by` | string | Dipendente che ha approvato |
| `date` | date | Data dell'approvazione |
| `status` | string | Esito dell'approvazione |

#### Indici

- `order_id`: univoco
- `status` + `priority`: per query sugli ordini aperti per urgenza
- `assigned_to`: per query sugli ordini assegnati a un dipendente
- `zone_id`: per query sugli ordini per zona
- `requested_by`: per tracciabilita'
- `safety_classification`: per filtraggio per criticita' nucleare

---

### 12. Collection: documents

Raccoglie i metadati dei documenti tecnici e procedurali della centrale.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `document_id` | string | Si' | Identificativo univoco, formato `DOC-*` |
| `classification_level` | string | Si' | Sensibilita' del documento |
| `title` | string | Si' | Titolo |
| `type` | string | Si' | Tipo: procedure, manual, drawing, report, analysis |
| `category` | string | Si' | Categoria: operational, emergency, maintenance, safety, administrative |
| `revision` | object | No | Informazioni sulla revisione corrente |
| `applicable_systems` | array | No | Sistemi a cui il documento si applica |
| `applicable_zones` | array | No | Zone a cui il documento si applica |
| `applicable_roles` | array | No | Ruoli autorizzati a consultare il documento |
| `file_reference` | string | No | Percorso logico del file |
| `keywords` | array | No | Parole chiave per la ricerca |
| `status` | string | Si' | Stato: draft, under_review, approved, superseded, archived |
| `previous_revisions` | array | No | Riferimenti alle revisioni precedenti |
| `review_date` | date | No | Data della prossima revisione programmata |
| `created_at` | date | No | Data di creazione |
| `updated_at` | date | No | Data di ultimo aggiornamento |

#### Sotto-documento: revision

| Campo | Tipo | Descrizione |
|---|---|---|
| `number` | int | Numero di revisione |
| `date` | date | Data della revisione |
| `author` | string | Autore della revisione (formato NP-*) |
| `approved_by` | string | Approvatore (formato NP-*) |
| `changes_summary` | string | Descrizione delle modifiche |

Il campo `applicable_roles` e' particolarmente rilevante per il PDP: un documento con `applicable_roles: ["operator", "plant_manager"]` sara' accessibile solo a utenti con quei ruoli, indipendentemente dal loro clearance level. Questo implementa un controllo di accesso basato su ruolo (RBAC) che si sovrappone al controllo basato su classificazione.

#### Indici

- `document_id`: univoco
- `classification_level` + `type`: per filtraggio per sensibilita' e tipo
- `category` + `status`: per ricerca di documenti approvati per categoria
- `applicable_roles`: per query sui documenti accessibili a un ruolo specifico
- `keywords`: per ricerca full-text

---

### 13. Collection: nuclear_materials

Modella l'inventario del materiale nucleare e radioattivo. E' la collection piu' critica del database.

#### Campi principali

| Campo | Tipo | Obbligatorio | Descrizione |
|---|---|---|---|
| `material_id` | string | Si' | Identificativo univoco, formato `NM-*` |
| `classification_level` | string | Si' | Tipicamente SECRET o TOP_SECRET |
| `type` | string | Si' | Tipo: fuel_assembly, spent_fuel, waste, source |
| `description` | string | No | Descrizione del materiale |
| `enrichment_percent` | double | No | Percentuale di arricchimento |
| `mass_kg` | double | No | Massa in kg |
| `initial_u235_kg` | double | No | Quantita' iniziale di U-235 in kg |
| `status` | string | Si' | Stato: in_storage, in_reactor, spent_pool, dry_cask, transferred |
| `location` | object | Si' | Localizzazione fisica |
| `burnup_mwd_t` | double | No | Burnup in MWd/t |
| `cycle_loaded` | int | No | Ciclo di caricamento nel reattore |
| `dates` | object | No | Date rilevanti (ricezione, caricamento, scarico previsto) |
| `supplier` | string | No | Fornitore o origine |
| `serial_number` | string | Si' | Numero seriale univoco |
| `iaea_safeguards` | object | No | Dati delle salvaguardie IAEA |
| `accountability` | object | No | Dati inventariali |

#### Sotto-documento: location

| Campo | Tipo | Descrizione |
|---|---|---|
| `zone_id` | string | Zona in cui il materiale si trova (formato ZONE-*) |
| `position` | string | Posizione specifica (es. Core position H-7, Spent fuel pool rack B-12) |
| `storage_rack` | string | Rack di stoccaggio (opzionale) |

#### Sotto-documento: iaea_safeguards

| Campo | Tipo | Descrizione |
|---|---|---|
| `seal_id` | string | Identificativo del sigillo IAEA |
| `last_inspection` | date | Data dell'ultima ispezione |
| `next_inspection` | date | Data della prossima ispezione programmata |

#### Sotto-documento: accountability

| Campo | Tipo | Descrizione |
|---|---|---|
| `last_inventory` | date | Data dell'ultimo inventario |
| `verified_by` | string | Dipendente che ha verificato (formato NP-*) |

#### Indici

- `material_id`: univoco
- `status` + `location.zone_id`: per query sul materiale per stato e zona
- `type` + `status`: per filtraggio per categoria e disposizione
- `serial_number`: univoco, per ricerca rapida per numero seriale
- `iaea_safeguards.next_inspection`: per monitoraggio delle scadenze ispettive

---

### 14. Indici e ottimizzazione delle query

Il database definisce un totale di 30 indici distribuiti sulle 7 collection. Gli indici sono progettati per supportare:

- **Query di identita'**: lookup rapido per `employee_id`, `badge_id`, `zone_id`, `order_id`, `document_id`, `material_id`.
- **Query di policy**: filtraggio per `clearance_level`, `classification_level`, `status`, `role`, `required_clearance`.
- **Query ZTNA**: filtraggio per `ztna_metadata.trust_score`, `applicable_roles`, `allowed_device_types`.
- **Query temporali**: ordinamento per `timestamp` sui parametri del reattore.
- **Query di audit**: lookup per `recorded_by`, `requested_by`, `assigned_to`.
- **Query di scadenza**: monitoraggio di `expiry_date` sui badge e `iaea_safeguards.next_inspection` sui materiali.

Tutti gli identificativi primari sono univoci a livello di indice per garantire l'integrita' referenziale.

---

### 15. Seed del database

Il database viene popolato con dati realistici tramite un'applicazione Go dedicata contenuta nella cartella `seed/`.

#### Architettura del seed

L'applicazione e' strutturata in tre livelli:

- **models/**: definisce le struct Go che mappano i documenti MongoDB e le costanti enumerate.
- **seeders/**: contiene un file per ogni collection con i dati di popolamento.
- **main.go**: punto di ingresso che gestisce la connessione e invoca i seeder in ordine di dipendenza.

#### Ordine di esecuzione

L'ordine rispetta le dipendenze referenziali:

1. `zones` - referenziate da tutte le altre collection
2. `personnel` - referenzia zone, referenziato da badge e ordini
3. `access_badges` - referenzia personnel e zone
4. `reactor_parameters` - referenzia personnel (recorded_by)
5. `maintenance_orders` - referenzia personnel e zone
6. `documents` - referenzia personnel, zone e ruoli
7. `nuclear_materials` - referenzia zone e personnel

#### Volumi di dati seed

| Collection | Documenti inseriti |
|---|---|
| zones | 9 |
| personnel | 7 |
| access_badges | 7 |
| reactor_parameters | 5 |
| maintenance_orders | 4 |
| documents | 7 |
| nuclear_materials | 5 |

#### Idempotenza

Ogni seeder verifica se la collection contiene gia' dati prima di procedere all'inserimento. Se la collection non e' vuota, il seeder salta l'esecuzione senza errore.

#### Variabili di ambiente

| Variabile | Default | Descrizione |
|---|---|---|
| `MONGO_URI` | `mongodb://seed_service:seedServicePass2025!@localhost:27017/nuclear_plant_db?authSource=nuclear_plant_db` | Stringa di connessione |
| `MONGO_DB` | `nuclear_plant_db` | Nome del database |

---

### 16. Containerizzazione

#### Container del database

L'immagine del database si basa su `mongo:7` e include:

- Il file `mongod.conf` con la configurazione personalizzata.
- Gli script di inizializzazione in `/docker-entrypoint-initdb.d/`.
- Un health check che verifica la raggiungibilita' di MongoDB ogni 30 secondi tramite `mongosh`.

MongoDB esegue gli script di inizializzazione solo al primo avvio, quando la directory dati e' vuota.

#### Container del seed

L'immagine del seed utilizza un build multi-stage:

- **Stage 1** (golang:1.22-alpine): compila il binario Go con linking statico e flag di ottimizzazione (`-ldflags="-s -w"`).
- **Stage 2** (alpine:3.19): contiene solo il binario compilato e i certificati CA. L'esecuzione avviene come utente non-root (`seeduser`).

Il container del seed e' effimero: viene eseguito una volta per popolare il database e poi termina.

---

### 17. Struttura della cartella

```
databases/business/
|- Dockerfile                          # Immagine MongoDB con configurazione e script
|- mongod.conf                         # Configurazione del server MongoDB
|- init-scripts/
|   |- 01-init-users.js               # Creazione utenti di servizio
|   |- 02-create-collections.js       # Creazione collection con validatori e indici
|- seed/
    |- Dockerfile                      # Immagine Go per il popolamento
    |- go.mod                          # Definizione del modulo Go
    |- go.sum                          # Checksum delle dipendenze
    |- main.go                         # Punto di ingresso del seed
    |- models/
    |   |- enums.go                    # Costanti enumerate (classificazione, ruoli, stati, tipi ZTNA)
    |   |- types.go                    # Struct Go per tutte le collection (con campi ZTNA)
    |- seeders/
        |- zones.go                    # Seed delle zone con policy ZTNA
        |- personnel.go               # Seed del personale con metadati ZTNA
        |- access_badges.go           # Seed dei badge con contesto di accesso
        |- reactor_parameters.go      # Seed dei parametri reattore con hash di integrita'
        |- maintenance_orders.go      # Seed degli ordini di manutenzione
        |- documents.go              # Seed dei documenti tecnici
        |- nuclear_materials.go       # Seed del materiale nucleare
```

---

### 18. Flusso di valutazione delle policy

Il Business Database supporta il seguente flusso di valutazione nel contesto dell'architettura Zero Trust:

```
1. Un soggetto (utente) invia una richiesta di accesso a una risorsa
   attraverso il PEP (Envoy).

2. Il PEP sospende la richiesta e inoltra i metadati al Security Orchestrator.

3. Il Security Orchestrator interroga il Business Database (tramite pdp_reader)
   per ottenere:
   - Il record personnel del soggetto (clearance, ruolo, ztna_metadata)
   - Il record della risorsa richiesta (classification_level)
   - Se la risorsa e' associata a una zona: il record zones (ztna_policy)

4. Il Security Orchestrator compone l'input per il PDP (OPA) con:
   - Identita': ruolo, clearance, trust_score, mfa_enrolled, risk_flags
   - Contesto: device_type, network, ip_address
   - Risorsa: collection, classification_level, applicable_roles
   - Zona: required_clearance, ztna_policy

5. Il PDP valuta la policy Rego e restituisce il verdetto (allow/deny)
   con eventuali condizioni (es. accesso in sola lettura, campi mascherati).

6. Il PEP esegue il verdetto: inoltra la richiesta al Business Database
   (tramite envoy_service) oppure la blocca.

7. L'intera transazione viene registrata su Splunk (tramite splunk_reader
   per la correlazione con i dati del database).
```

I campi ZTNA nel database sono progettati specificamente per alimentare i passi 3 e 4 di questo flusso. Il trust score, i risk flags, i requisiti delle zone e il contesto di accesso sono tutti dati che il PDP puo' valutare per prendere decisioni granulari e adattive, coerenti con i principi NIST 800-207.