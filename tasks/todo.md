# TODO — Fix decision-log OPA non rilevati da Splunk

## Causa radice (verificata a runtime)
La Splunk Universal Forwarder tiene la fishbucket (checkpoint di lettura) su volumi
**anonimi** (`/opt/splunkforwarder/var` e `/etc`), non dichiarati nel compose. Ad ogni
recreate del container la UF riceve un `var` vuoto → rilegge ogni file da capo.
Prove: indexer con **64788 eventi / 16095 decision_id unici (~4× duplicati)** e
`avg_age ≈ 24h` (replay del backlog → eventi recenti fuori finestra di ricerca).
Aggravante: `opa_decision.jsonl` mai ruotato (39 MB dal 2 giugno).
Il file **viene scritto** e il mount è corretto (stesso inode): il problema è solo l'ingestion.

## Step
- [x] Volumi nominati `splunk-uf-var` / `splunk-uf-etc` su `splunk-uf` — docker-compose.yml
- [x] Idem — docker-compose.cpu.yml
- [x] Dichiarazione volumi in entrambe le sezioni `volumes:`
- [x] Rotazione bounded di `opa_decision.jsonl` + `app.jsonl` (lumberjack) — main.go
- [x] `OPALogsHandler` accetta `io.Writer` e logga gli errori di scrittura (niente più drop silenzioso) — handler.go
- [x] `go build` / `go vet` / `go mod tidy` puliti; lumberjack in go.mod/go.sum
- [x] `docker compose config` valido su entrambi i compose
- [ ] Rimuovere monitor fantasma `[monitor:///var/log/ztaleaks/opa]` — inputs.conf
      (BLOCCATO: file di proprietà root:41812, serve sudo dell'utente)
- [ ] Deploy: rebuild orchestrator + recreate splunk-uf
- [ ] Bonifica duplicati storici nell'indice `main` (source=*opa_decision.jsonl)
- [ ] Verifica end-to-end (avg_age in secondi, count==dc(decision_id), visibilità -15m)

## Review

**Fix applicato e verificato a runtime:**
- Volumi nominati `splunk-uf-var`/`splunk-uf-etc` aggiunti e attivi: `docker inspect` mostra
  `var -> docker_splunk-uf-var`, `etc -> docker_splunk-uf-etc`.
- **Prova di persistenza del checkpoint**: dopo un 2° `--force-recreate` della UF, il volume
  (`CreatedAt` invariato) e il `fishbucket.sqlite.db` (stesso inode 16276265) **sopravvivono** →
  niente più riletture da zero ad ogni recreate (era la causa di duplicati + backlog).
- Orchestrator ricostruito (lumberjack) e ripartito pulito; pipeline OPA→orchestrator→file
  funzionante: OPA "Logs uploaded successfully" 10:54:28 e `opa_decision.jsonl` cresciuto in pari data.
- `go build`/`vet`/`mod tidy` ok; build Docker alpine ok.

**Costo una-tantum (atteso):** lo switch a fishbucket nominata parte vuota → la UF rilegge UNA volta
tutti i log monoliti (mongod ~16gg, snort ~37gg, opa ~24gg). Code sature per qualche minuto, poi
steady-state real-time. Questo aggiunge un ultimo giro di duplicati nell'indice (vedi sotto).

**Follow-up manuali rimasti:**
1. `inputs.conf` (monitor fantasma): bloccato da permessi root. Comando per l'utente:
   `sudo sed -i '/monitor:\/\/\/var\/log\/ztaleaks\/opa\]/,+3d' infra/splunk-uf/inputs.conf`
   (oppure editarlo a mano). Non indispensabile al fix, solo igiene.
2. Bonifica duplicati storici nell'indice (DISTRUTTIVA, non eseguita in automatico):
   in Splunk `index=main source=*opa_decision.jsonl | dedup decision_id` per le ricerche, oppure
   `... | delete` per rimuoverli fisicamente. Da valutare con l'utente.

**Nota dati:** il contenuto dei decision-log NON è stato toccato (restano interi, con `input` e
`result` completi) — su esplicita richiesta dell'utente.
