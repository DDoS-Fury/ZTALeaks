# Audit ZTALeaks — criticità aperte (2026-06-01)

Audit eseguito sullo stack avviato in locale, testando ogni punto dal vivo.
Già risolti in questa sessione: race boot business-logic (#4) e hardening avvio
Envoy (#5). Restano i 3 punti sotto, **da discutere coi compagni** prima di toccarli.

---

## #1 — mTLS NON imposto dal PEP (Envoy)  🔴 Alta

**Cosa:** `infra/envoy/envoy.yaml` → `require_client_certificate: false`.
Una connessione senza certificato client completa comunque l'handshake TLS e
arriva fino all'orchestrator con `cert_present:false`. Il certificato è validato
solo dall'identity-service al login, non dal proxy. Contraddice il principio
Zero Trust (e il CLAUDE.md indica `true`).

**Test eseguito:**
```
curl -sk https://localhost:8443/...           # senza cert -> handshake OK, HTTP 403 (da OPA, non dal TLS)
```

**Fix proposto:** `require_client_certificate: true`.

**Perché è in pausa:** i certificati client li gestisce un compagno e li usa per
altri tipi di test; abilitare l'obbligo va coordinato con lui.

---

## #2 — `network_location` falsificabile (spoofing X-Forwarded-For)  🔴 Alta

**Cosa:** `services/security-orchestrator/internal/handler/handler.go:187`
`clientIPFromRequest` prende il **primo** elemento di `X-Forwarded-For`, che è
controllabile dal client. Envoy ha `use_remote_address: true` e appende l'IP
reale in coda, ma l'orchestrator legge la testa → bug lato orchestrator.

**Test eseguito:**
```
curl ... -H 'X-Forwarded-For: 10.0.0.99'
# orchestrator logga -> ip_address: 10.0.0.99 | network_location: internal
```
Un client esterno si dichiara "internal" e altera il rischio nelle policy.

**Fix proposto:** in Envoy usare `xff_num_trusted_hops`; nell'orchestrator
fidarsi solo dell'IP impostato da Envoy (ultimo hop affidabile), non del primo
elemento dell'header.

**Caveat da verificare insieme:** in Docker l'IP "vero" che Envoy vede è quello
del gateway della rete bridge → controllare che `network_location` continui a
classificare sensatamente il traffico di test (potrebbe risultare tutto
"perimeter"). Trasparente per il flusso normale via Envoy; blocca solo lo spoof
manuale.

---

## #3 — Ramo anonimo scarta il certificato verso OPA  🟡 Media

**Cosa:** `handler.go:91` — nel ramo "nessun token" il codice ha già parsato il
certificato (`cc := cert.Parse(...)`) ma invia a OPA `CertPresent: false`
hardcoded e `Claims: nil`. Per le richieste senza JWT, OPA non sa mai che c'era
un certificato. Il cert viene loggato ma non usato nella decisione.

**Probabile intenzione:** per accedere serve comunque il JWT, quindi forse è
voluto. Resta un'incoerenza (parso + loggo + scarto).

**Fix proposto (se confermato bug):** passare `CertPresent: cc.Present` e
`CertSubject: cc.Subject` anche nel ramo anonimo, lasciando a OPA la decisione.

---

## Note demo
- Stack avviato con `docker compose -f deployments/docker/docker-compose.yaml --env-file .env up -d --build`.
- Frontend (`:3000`) NON incluso in questo compose: dimostrabile solo il backend di auth.
- MailHog UI: http://localhost:8025 (mail OTP). Utenti seed: password `admin123`.
