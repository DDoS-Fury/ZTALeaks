# Snort IDS — note di sviluppo (ultimi 4 commit)

Documento che racconta cosa è stato fatto, perché, quali problemi sono
emersi e con quali soluzioni li abbiamo risolti, nell'ordine cronologico
dei commit.

Range coperto: da `2df7d06` (introduzione di snort-mid) a `8ad7379`
(suite di test offline per i 22 alert).

```
8ad7379 test(alerts): offline-pcap suite covering all 22 snort alerts
245f79d feat(snort-internal): TLS downgrade, legacy version and weak cipher rules
b17661b feat(snort): enrich parser JSON with service and rule sid/gid/rev
2df7d06 feat(snort-mid): IDS for Envoy↔Orchestrator SQLi/XSS detection
```

---

## Architettura IDS risultante

Tre Snort, tutti in `network_mode: service:firewall` (condividono il
netns del container `firewall`, dove vive anche Envoy via lo stesso
meccanismo), ognuno con un set di regole specializzato e un parser Go
che converte il fast-format in JSON strutturato per Splunk.

| Container         | Segmento osservato                                | Focus rule                                    |
|-------------------|---------------------------------------------------|-----------------------------------------------|
| `snort`           | external -> Envoy (eth0 del netns firewall)       | port scanning                                 |
| `snort-internal`  | external -> Envoy, lato TLS handshake             | mTLS, TLS version, weak cipher, SYN flood     |
| `snort-mid`       | Envoy -> Security Orchestrator (porta 8081)       | SQLi e XSS su ext_authz HTTP plaintext        |

Ogni Snort scrive in `/var/log/ztaleaks/snort-<name>/alert_json.txt`
(volume Docker dedicato), montato in `splunk-uf` in read-only.

---

## `2df7d06` — feat(snort-mid): IDS per ext_authz

### Cosa fa
Aggiunge il terzo Snort (`snort-mid`) sul segmento Envoy → Security
Orchestrator. Le regole (`mid.rules`) cercano pattern SQLi (UNION
SELECT, OR 1=1, DROP TABLE, tautologia URL-encoded) e XSS (`<script>`,
`javascript:`, `onerror=`, `onload=`, varianti URL-encoded) sulla porta
8081 in chiaro che Envoy usa per la chiamata ext_authz.

### Scelte di design
- **Stesso pattern degli altri due Snort**: `network_mode: service:firewall`,
  parser.go identico, stdout su parser → JSON su volume dedicato,
  mount read-only in `splunk-uf`. La replicazione del pattern era la
  scelta più semplice, ed è quella che ha portato successivamente a
  un design smell (ne parliamo sotto).
- **Solo HTTP plaintext**: snort-mid sniffa il segmento dopo che Envoy
  ha terminato la TLS, quindi può ispezionare l'URI inoltrato in
  `x-original-uri` / `x-authz-request-path` / headers consentiti
  dalla config `authorization_request.allowed_headers` in `envoy.yaml`.

### Limite architetturale (non bug, di design)
Envoy `ext_authz` con configurazione `authorization_request.allowed_headers`
inoltra al security-orchestrator **solo gli header esplicitamente in
whitelist**, e **non inoltra il body** della richiesta originale. Di
conseguenza snort-mid:

- vede SQLi/XSS in URL e query string (passati in `x-original-uri`,
  `x-authz-request-path`)
- vede SQLi/XSS in cookie e headers in whitelist (`authorization`,
  `cookie`, `x-zone-id`)
- **non vede** SQLi/XSS nel body POST/PUT della richiesta originale,
  perché quel body non transita mai sul segmento Envoy↔Orchestrator
  in chiaro

Per coprire il body servirebbe detection in un punto diverso del
percorso (es. middleware nel security-orchestrator o nel
business-logic), non un'altra rule Snort qui.

### Side-fix incluso
`infra/envoy/Dockerfile` adesso fa `chown envoy:envoy server.key`.
Senza, l'utente envoy (uid 101) non poteva leggere la chiave privata
(perm 600 root) e il container partiva in restart loop con
`Failed to load incomplete private key`.

### KNOWN ISSUE dichiarato nel commit
Le regole scattavano sul traffico diretto a `:8081` (verificato con
`nc` da dentro il netns firewall) ma non sul flusso E2E reale
(`curl HTTPS:8443 --cert`). Motivo dichiarato: `x-forwarded-client-cert`
contiene il certificato client URL-encoded (~2 KB), la richiesta
ext_authz finisce frammentata su più segmenti TCP, e le content rule
con `distance`/`within` non matchano oltre i confini di pacchetto.
`flow:established,to_server` provato senza risolvere.

---

## `b17661b` — feat(snort): JSON con `service` + `rule_*`

### Cosa fa
I tre `parser.go` adesso emettono JSON con 4 campi nuovi:

```json
{
  "service":   "snort-internal",
  "rule_gid":  "1",
  "rule_sid":  "2000005",
  "rule_rev":  "1",
  "timestamp": "...",
  "message":   "...",
  "classification": "...",
  "priority":  "...",
  "src_ip":  "...", "src_port": "...",
  "dst_ip":  "...", "dst_port": "..."
}
```

### Problema risolto
Prima del commit, gli alert dei tre Snort erano indistinguibili in
Splunk una volta fuori dal volume: stesso schema, niente provenienza,
niente rule_sid. Filtrare per "tutti gli alert RC4" o "tutti gli alert
di snort-mid" richiedeva regex sul `message`. Inoltre questa lacuna
era proprio sui tre Snort, mentre tutti gli altri sink di log
strutturato (Envoy, nftables, i tre servizi Go) avevano già il campo
`service` da una precedente passata.

### Soluzione
- Regex del fast-format esteso da `\[\d+:\d+:\d+\]` (non-capturing) a
  `\[(\d+):(\d+):(\d+)\]` (capturing) → tre nuovi gruppi mappati su
  `rule_gid`, `rule_sid`, `rule_rev`.
- Service name letto da `os.Args[3]` del parser, passato dal `CMD`
  del Dockerfile (`snort-parser <in> <out> snort|snort-internal|snort-mid`).
- I tre `parser.go` erano già praticamente identici tra loro; abbiamo
  scelto di tenerli separati (richiesta esplicita: "lasciarli separati")
  invece di consolidarli in un file condiviso. Tre file uguali è il
  prezzo di una replicazione di responsabilità più chiara.

### Verifica
Container rebuild, iniezione manuale di una riga fast-format nel file
`/var/log/snort/alert`, lettura di `alert_json.txt`: tutti i campi
presenti e corretti per ognuno dei 3 Snort.

---

## `245f79d` — feat(snort-internal): TLS rules

### Cosa fa
Riscrive `infra/snort-internal/rules/internal.rules`. Numerazione SID
organizzata per categoria:

| Range          | Categoria                                                |
|----------------|----------------------------------------------------------|
| 1000004        | ICMP canary                                              |
| 2000002        | mTLS Violation (empty Certificate handshake)             |
| 2000006        | SYN flood verso porta Envoy                              |
| 2000010-12     | Legacy TLS version offerta nel ClientHello               |
| 2000020-22     | TLS downgrade attack (ServerHello negoziato <TLS 1.2)    |
| 2000030-32     | Weak cipher offerto (RC4 / 3DES / NULL+EXPORT+anon DH)   |

### Decisioni di design

**Match sulla `ClientHello.legacy_version` (offset 9-10), non sul record
header.** In TLS 1.3 il client mette `0x0303` nella `legacy_version`
del ClientHello ma `0x0301` nel `legacy_record_version` del record
layer. Una regola che matchava sul record (la vecchia `sid:2000005`
`content:"|16 03 01|"; depth:3;`) produceva falsi positivi su ogni
handshake TLS 1.3 moderno. Il match a offset 9-10, dietro la sequenza
ancorata `16 03 .. .. .. 01 00 00`, è invece affidabile.

**ServerHello-based downgrade detection.** Le 2000020-22 hanno
`flow:from_server,established` e `priority:1`. Sono i veri "attacco di
downgrade" perché TLS 1.3 imposta `ServerHello.legacy_version = 0x0303`
sempre: qualsiasi valore minore qui significa che il server ha
realmente accettato un protocollo pre-TLS 1.2.

**Cipher detection in due famiglie.** Le 2000030-32 usano `pcre` per
catturare i codici della famiglia (RC4, 3DES, NULL+EXPORT+anon), ancorati
al ClientHello marker e relativi (`/R` flag).

**Cosa è stato rimosso:**
- `sid:2000003` (`content:"|00 2F|"` = AES-128-CBC-SHA): è offerto da
  ogni browser moderno → era un FP factory.
- `sid:2000005` (record-layer `16 03 01`): sostituito da 2000011 con
  match più chirurgico sulla `legacy_version` del ClientHello.

**Prerequisito già coperto.** Le regole con `flow:established`
richiedono il preprocessor `stream5_tcp` attivo. Verificato in
`snort.conf` del container snort-internal: `preprocessor stream5_global`
e `preprocessor stream5_tcp` ci sono già, nessuna modifica al
Dockerfile necessaria.

---

## `8ad7379` — test(alerts): suite offline-pcap (22 test)

### Cosa fa
Nuova directory `tests/alerts/` con un harness pytest che fabbrica
pcap con scapy e li passa a `snort -r` (modalità batch) usando le
rule del servizio target, parsando il fast-format restituito.
22 test, tutti passing in ~10 secondi, copertura completa di ogni
SID definito nei 3 rule set.

```
snort           1  port scan
snort-internal 12  ICMP, mTLS empty, SYN flood,
                   3 legacy ClientHello, 3 ServerHello downgrade,
                   3 weak cipher
snort-mid       9  4 SQLi + 5 XSS
```

### Perché offline e non live

Durante lo sviluppo iniziale (Wave 1, approccio live), abbiamo
provato a generare traffico HTTPS da un container test verso Envoy e
verificare che gli Snort registrassero gli alert nel volume. Tutti i
container e la connettività erano OK (richieste a Envoy ricevevano
403 da OPA, quindi ext_authz era invocato), ma **nessuno dei tre
Snort scriveva alcun alert raw**. Dopo varie verifiche:

- `snort -v -i eth0` lanciato manualmente dentro il container
  snort-mid: 0 pacchetti capturati, nonostante il netns fosse
  condiviso correttamente con il firewall e Envoy.
- `-i any` non utilizzabile (Snort 2.9: "Cannot decode data link type 113").
- Rebuild `--no-cache`, `docker compose down && up`, restart selettivo:
  nessuno di questi ha cambiato il comportamento.

La conclusione operativa è che **libpcap dentro un container in
`network_mode: service:firewall`, su Docker Desktop per macOS, non
riceve pacchetti in modo affidabile** (probabilmente una limitazione
nel modo in cui Docker Desktop gestisce lo shared netns dentro la
VM Linux). L'approccio live era quindi inutilizzabile per la
validazione delle rule indipendentemente dalla bontà delle stesse.

### Pivot a offline pcap

Lo stesso obiettivo — "ogni rule deve scattare sul traffico atteso" —
si raggiunge in modo deterministico fabbricando pcap con scapy e
passandoli a Snort in modalità batch. Vantaggi:

- Niente dipendenza dal pcap live → bypass del bug Docker Desktop.
- I test non richiedono lo stack ZTALeaks attivo (Envoy, OPA,
  business-logic). Solo il container `alerts-tester` (ubuntu:24.04 +
  snort + python + scapy/pytest).
- Tempo di esecuzione: ~10 secondi per 22 test, contro decine di
  secondi per il setup live di tutto lo stack.
- CI-friendly: un solo container, un solo entry point.

### Architettura dei test

- `tests/alerts/Dockerfile`: ubuntu:24.04 con snort, virtualenv Python
  (per bypassare PEP 668), scapy/pytest. Le rule dei 3 servizi vengono
  copiate in `/rules/<service>/` e il placeholder `ENV_ENVOY_PORT`
  viene sostituito a build time con `8443`.
- `tests/alerts/snort-test.conf`: config minimale Snort, con stream5
  abilitato (necessario per `flow:established`), include
  `classification.config` / `reference.config` di sistema, output su
  stdout in fast-format.
- `tests/alerts/conftest.py`: la fixture `snort_offline(service,
  packets)` scrive un pcap temporaneo, lancia
  `snort -r <pcap> -c <conf_temp> -A console -N -q`, parsa lo stdout
  in fast-format con la stessa regex usata dal parser.go runtime, e
  ritorna una lista di oggetti `Alert(sid, gid, rev, msg, raw)`.
- `tests/alerts/helpers.py`: primitive scapy condivise — `tcp_flow`
  per generare un handshake TCP completo + segmento dati + teardown,
  `tls_record` / `client_hello` / `server_hello` per fabbricare bytes
  TLS controllando ogni campo (legacy_version, cipher_suites, ecc).
- `tests/alerts/test_snort_*.py`: tre file, uno per servizio.
- `deployments/docker/docker-compose.yaml`: nuovo service
  `alerts-tester` sotto profile `alerttest` (non parte di default).

Comando di lancio:

```bash
docker compose -f deployments/docker/docker-compose.yaml \
  --profile alerttest run --rm alerts-tester
```

---

## Note operative post-commit: cosa sappiamo del KNOWN ISSUE di snort-mid

Dopo aver scritto la suite offline, abbiamo provato a riprodurre il
KNOWN ISSUE dichiarato nel commit `2df7d06` (rule SQLi che non scattano
quando il payload ext_authz è frammentato per via di
`x-forwarded-client-cert` grande).

### Tentativi di riproduzione (offline)

1. **Payload piccolo (~70 B), split tra `UNION` e `+SELECT`**: il test
   passa, la rule scatta. Stream5 riassembla il flusso.
2. **Stesso payload, split in mezzo alla parola `UNION` (tra `UN` e
   `ION`)**: il test passa lo stesso. Stream5 ricostruisce il pattern
   intero prima del match.
3. **Payload realistico (~2 KB, header `X-Forwarded-Client-Cert` con
   cert PEM URL-encoded a dimensione reale), split in mezzo a `UNION`**:
   il test passa lo stesso. Anche su 2 KB stream5 default basta.

### Diagnosi rivista

Le rule attuali, raw-TCP-content + stream5 default, sono in realtà
**robuste alla frammentazione** quando Snort vede tutti i pacchetti
del flusso. Il problema descritto nel commit `2df7d06`
("non matchano cross-segment, anche con `flow:established`") torna a
quadrare se Snort vede **pacchetti parziali**, cioè se libpcap perde
una parte del flusso e stream5 non può riassemblare l'intera richiesta
HTTP.

Lo stesso identico sintomo lo abbiamo osservato direttamente durante
la fase live del lavoro sulla suite di test (vedi sopra: `snort -v`
mostra 0 pacchetti capturati anche con traffico reale presente).

### Conclusione operativa

Il KNOWN ISSUE di `2df7d06` è verosimilmente **lo stesso bug del
pcap-live su shared netns sotto Docker Desktop macOS**, e non un
problema di design delle rule. Le rule attuali sono adeguate per il
caso in cui il transport funzioni correttamente.

### Cosa non abbiamo fatto, e perché

Abbiamo considerato due strade per "completare" il commit `2df7d06`:

- **Migrare le rule a `http_uri` / `http_inspect`** (la strada
  suggerita dallo stesso commit). È buona pratica per detection HTTP
  e ha vantaggi indipendenti (normalizzazione URL-encoding automatica,
  riduzione del numero di rule), ma **non risolve** il sintomo
  originario, che è a livello transport. Avremmo aggiunto un refactor
  di principio senza un bug riproducibile dietro.
- **Indagare il pcap-live**. Lavoro più grosso, fuori scope di questa
  sessione. Possibili strade future: cambiare meccanismo di capture
  (es. mirror via iptables/NFQUEUE), spostare la detection HTTP
  dentro il security-orchestrator stesso come middleware, oppure
  verificare se Docker Desktop su Linux/Linux native non riproduce
  il bug.

L'opzione scelta è quindi: **non toccare le rule, documentare la
scoperta** (questo file), e tornare al problema solo se/quando
disponiamo di un ambiente live in cui sia riproducibile.

---

## Riassunto file toccati

| Commit     | File                                                        |
|------------|-------------------------------------------------------------|
| `2df7d06`  | `infra/snort-mid/{Dockerfile,parser.go,rules/mid.rules}`    |
|            | `infra/envoy/Dockerfile` (side-fix chown server.key)        |
|            | `deployments/docker/docker-compose.yaml`                    |
|            | `.github/workflows/ci.yaml`                                 |
| `b17661b`  | `infra/snort/{parser.go,Dockerfile}`                        |
|            | `infra/snort-internal/{parser.go,Dockerfile}`               |
|            | `infra/snort-mid/{parser.go,Dockerfile}`                    |
| `245f79d`  | `infra/snort-internal/rules/internal.rules`                 |
| `8ad7379`  | `tests/alerts/` (nuova directory, 9 file)                   |
|            | `deployments/docker/docker-compose.yaml`                    |
