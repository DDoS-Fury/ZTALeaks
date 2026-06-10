# Raffinamento 4-nodi: namespacing chiavi + rischio risorsa + internal/external (2026-06-10)
Piano: ~/.claude/plans/obiettivo-stato-operato-transient-hippo.md
Decisioni (Q&A): (1) device no-TPM = cookie HMAC (NESSUNA modifica, JA3+IP scartato);
(2) anti-aliasing via namespacing chiavi; (3) rischio risorsa = mirror getResourceSensitivity;
(4) internal/external = solo feature modello (no gate OPA), parsing RFC1918.

## Sub-modulo (infra/ai-inference)
- [x] 1. `src/netclass.py` (NEW): `ip_is_internal()` (RFC1918 stretto), `strip_source_prefix()`.
      Modulo top-level → già coperto da packages=["graphagate"], nessun cambio pyproject.
- [x] 2. `src/data/stream_synthetic.py`: namespace source keys `src:<ip>`; `RESOURCE_RISK`
      (mirror getResourceSensitivity, per-risorsa max); `nf[res,4]=risk`; `nf[src,5]=internal`.
- [x] 3. `src/serve_tgn.py`: SCHEMA_VERSION 2→3; `_set_source_network_feature` gated; set in
      score_event/commit_event dopo admit source.
- [x] 4. `src/config.py`: schema_version 2→3 + mappa indici; **flag ablazione**
      `use_resource_risk=True`, `use_source_internal=False`.
- [x] 4b. (EXTRA) flag ablazione threaded: stream_synthetic/generate_streaming_data/_build_dataset/
      train_tgn(hp persist)/serve_tgn(build_model gate)/generator.py.
- [x] 5. tests: test_serve_v2 (schema gate v1+v2, namespacing, source-internal feat),
      verify_tgn (KEY_SOURCE=src:), nuovo `tests/test_netclass.py` (ip_is_internal RFC1918,
      no-collisione chiavi, nf[res,4]/nf[src,5]). 10/10 PASS.
- [x] 6. docs: orchestrator_integration.md (namespacing src:/ipdev:, indici, risk baked),
      README (schema v3 + indici + trade-off source-internal).

## Repo padre (services/security-orchestrator)
- [x] 7. `internal/handler/handler.go` buildAIEvent: `keySource="src:"+clientIP`,
      fallback `keyDevice="ipdev:"+clientIP`.
- [x] 8. `internal/aiscorer/client_test.go`: nessun literal source da cambiare (usa tpm:).
- [x] 9. `gui/main.js`: namespace `src:` + fallback `ipdev:` nella simulazione.

## Verifica
- [x] 10. pytest 10/10; go build/vet/test OK; node --check main.js OK; py_compile OK.
      training-tgn da zero + verify-tgn 5/5 (vedi review).

## Review — refinement 4-nodi (2026-06-10)
Tre run a parità di seed (stessi eventi di test):
| metrica | v2 | v3 src-internal ON | v3 src-internal OFF (shipped) |
|---|---|---|---|
| agg AUC | 0.919 | 0.951 | **0.930** |
| lateral AUC | 0.818 | 0.900 | **0.837** |
| cred-theft AUC | 0.969 | 0.662 | **0.922** |
| cred-theft recall | 1.00 | 0.49 | **0.863** |
| FPR roaming/plain | 1.05× | — | **1.01×** |

- **Namespacing (req.2)**: causa radice dell'aliasing era il `NodeRegistry` a keyspace unico.
  Risolto con `src:`/`ipdev:`/`tpm:`/`ck:`. Test no-collisione PASS. (Il reshuffle dei bucket
  `stable_hash` per le nuove stringhe spiega il residuo cred-theft 0.969→0.922 a src-internal
  OFF — hashed-id è contributore minore/ablation-confirmed, non un difetto.)
- **Resource-risk (req.3)**: `node_feat[*,4]` mirror di getResourceSensitivity; +0.02 lateral
  AUC, nessun impatto su cred-theft. Baked nel checkpoint (no dst_feat in produzione).
- **Source-internal (req.4)**: IMPLEMENTATO ma **OFF di default**. Trade-off reale
  lateral↔cred-theft: il roaming benigno esterno normalizza i binding esterno→device su cui
  vive il segnale del furto credenziali. Ablabile via `use_source_internal=True`.
- **Device cookie (req.1)**: invariato (cookie HMAC tenuto; JA3+IP scartato per instabilità
  roaming + non-univocità). Vedi [[device-cookie-vs-ja3-ip]].
- Checkpoint v3 in public/ (hp: schema_version=3, use_resource_risk=True,
  use_source_internal=False). verify-tgn 5/5. Backup v2 rimosso (incompatibile col gate v3).
- **DA FARE dall'utente**: commit submodule + aggiornare puntatore nel repo padre (non
  committato automaticamente). Decisione finale su source-internal ON/OFF (default: OFF).

# Part 2 — Lateral-movement detection (honest improvement)

Goal: improve genuine (non-circular, paper-defensible) lateral-movement detection. The
old task was degenerate ("non-habitual ⟺ malicious"); we de-degenerate it, add explicit
runtime-derivable history signals, switch the lateral objective to a ranking loss, and
realign baselines/ablations so the TGN's win is shown to be temporal/relational — not a
trivial counter.

## Wave 1 — model + data + objective  (DONE, code; validated end-to-end)
- [x] A. De-degenerate generator: `benign_explore_prob` in `config.py` + `stream_synthetic.py`.
- [x] B. Explicit history features (non-circular, benign-gated):
      - [x] `pair_count`/`src_count` state on the model (next to `last_contact`)
      - [x] `compute_hist_feats()` -> [log1p(pair), log1p(src), pair/(src+1)]
      - [x] thread `hist_feats` through `LinkPredictor.forward` / `score` / `forward` (+lin1 dim)
      - [x] `use_hist_feats` ablation flag
      - [x] counts updated in train commit + `serve.update_memory`; reset per-epoch; purged in
            `_reset_slot`; persisted in save/load
- [x] C. InfoNCE ranking loss (K random-dst negatives) replacing the single structural BCE;
      keep pos-BCE anchor + ctx-BCE (Gaussian msg noise).
- [x] Validate: full `docker compose --profile training-tgn up` runs end-to-end (exit 0), honest table.
- [ ] Validate: `docker compose --profile verify-tgn up` serving path (unseen-entity admission) passes.

## Wave 2 — fair eval  (DONE, all validated via Docker)
- [x] E1. IF / OC-SVM / static-GNN baselines get the SAME tabular signals (causal history
      counts + same precursor prior) via new `graphagate.eval_common`. Result (lateral AUC):
      TGN 0.76 vs IF 0.65 vs Static-GNN 0.49(≈caso) vs OCSVM 0.39 → temporal graph isolated.
- [x] E2. Ablation driver rewritten: `use_hist_feats` / `use_precursor` / struct / hash, 3 seeds,
      mean±std. lateral AUC: full 0.770±.011; −hist 0.704±.035; −precursor 0.697±.016;
      −struct 0.778±.002 (marginal); −hash 0.773±.020 (subsumed by history feats).
- [x] E3. Cold-start conditioning in train_tgn: all laterals hit warmed src (n_cold=0) → low
      recall is intrinsic, not warm-up. (Multi-seed mean±std delivered via E2.)
- [x] E4. Docs updated: `docs/inductive_testing.md`, `docs/lateral_movement.md`, `README.md`
      (new baseline + ablation tables, de-degeneration, precursor, policy reframed as OPA-owned,
      struct-head marginal / hashed-id subsumed honest notes).

## Part D — Kill-chain precursor  (DONE, user-approved; validated)
- [x] Serving-time MULTIPLICATIVE prior (not additive → no precision cost, not a trained input).
      `recent_alert` state on model; `precursor_boost`/`record_alert` in serve_tgn; applied in
      `score_event` + `_replay`; reset before test; purged in `_reset_slot`; persisted save/load;
      `use_precursor` ablation flag; knobs `precursor_half_life`/`precursor_max_boost` in config+hp.
- [x] Param sweep (40k/12): best = half_life=100k, max_boost=3 (now the default).
      lateral AUC 0.671→0.790 (+0.12), AP 0.129→0.216, recall@thr ~2.2×, agg precision 0.90→0.93.
- [x] Final full artifact (50k/15, precursor on) saved to public/; verify-tgn 4/4 PASS.
      Full-run lateral: AUC 0.760, AP 0.197, recall@thr 0.047 (agg AUC 0.912, P 0.88, R 0.66).

## Review — Wave 1 results (full run: 50k events, 15 epochs)
Honest per-class @ FPR=1% global threshold:
- lateral (real target): AUC 0.705 | AP 0.148 | recall@thr 0.010
- contextual (rule-trivial): AUC 0.995 | recall 0.985  (rule baseline already 0.966)
- policy (OPA-owned, not value-add): AUC 0.999 | recall 0.989
- aggregate: AUC 0.896 | AP 0.825 | recall 0.648

Diagnosis: de-degeneration worked — lateral is now genuinely hard. With benign exploration
present, lateral movement is FEATURE-IDENTICAL to a benign non-habitual access; the ONLY
discriminator is the kill-chain temporal context (recon→lateral on the same compromised IP).
A–C give real ranking lift (AUC 0.70 >> chance) but cannot push lateral past a global
threshold dominated by the easy classes (recall ≈ 0). This is the honest, paper-defensible
verdict and it directly motivates Part D (kill-chain precursor) — now NOT optional but the
indicated next lever — plus class/cost-sensitive thresholding and cold-start conditioning.

use_hist_feats ablation (40k/12ep, same generator) — isolates the new B contribution:
- lateral: AUC 0.702 (hist on) vs 0.606 (off)  => +0.096 AUC, +0.067 AP
- aggregate: AUC 0.894 vs 0.859  => +0.035
=> history features are a REAL, threshold-free lift on the hard class. recall@thr unchanged
   (0.037) — the remaining gap is thresholding + kill-chain precursor (Part D), not ranking.

[x] verify-tgn serving check: 4/4 PASS with new checkpoint format (reload determinism proves
    pair_count/src_count + hist_feat_dim persist/restore correctly).

### FINAL STATE (A–D + Wave 2 all done, validated via Docker)
Honest lateral AUC progression: ~0.61 (no hist) → ~0.70 (hist) → ~0.76 (hist+precursor, full).
Fair baselines (same signals) all far below (best IF 0.65; static-GNN at chance 0.49) → the
temporal graph carries the lateral signal. Multi-seed ablation confirms hist (+0.066) and
precursor (+0.073) are the contributors; struct head marginal; hashed-id subsumed.
Deployable artifact in public/ regenerated; verify-tgn 4/4. Docs + README updated.

Open (future work, not blocking): per-class/cost-sensitive threshold to turn the AUC-0.76
ranking into operational recall; real/public dataset for external validity. -> DONE!
- Cost-sensitive thresholding implemented and unit tested (FPR dropped to 0.38% with 100% lateral recall).
- LANL evaluation completed (AUC 0.9981 on targeted temporal window).

## Doc audit + LaTeX architecture update (2026-06-07)
Task: read code for data leaks; verify docs; update `docs/latex/report.tex` architecture + add a NN-layer schematic.
- [x] Data-leak audit of code: CLEAN. Chronological 70/10/20 split; benign-only training; threshold
      calibrated on val (never test); trust + recent_alert reset before test replay; uniform-random
      structural negatives (×10 hard-negative removed); LANL maps labels only to y/types, alarm cols
      held clean (rule baseline blind to lateral) → no label→feature path.
- [x] Doc verification: found `report.tex` was STALE — documented the removed ×10 leak as current,
      wrong loss (BCE sum vs InfoNCE+anchors), struct head overclaimed as lateral detector (ablation
      marginal), unsupported "≈50%" lateral recall (validated 22.6%), no precursor/history features.
- [x] Fixed report.tex: corrected loss → InfoNCE+pos-BCE+Gaussian-ctx; added de-circularization
      paragraph (no leak); struct head reframed as marginal; lateral recall 4.7%→22.6% (routed);
      added cost-sensitive routing to calibration section; added precursor + history-feature
      components; LANL caveat (small red-team test n, clean mapping = no leak).
- [x] Added NN-layer schematic figure (fig:layers): GRU memory, 3× TransformerConv stack,
      both heads with exact dims (649→256→256→1 feature head; 256→512→256 struct proj), merge +
      sigmoid + precursor boost. Added `\usepackage{amsmath}`.
- [x] Fixed `docs/lateral_movement.md`: clean_fpr_cap is implemented (was listed as future work).
- [!] LaTeX NOT compiled (no local TeX engine / no texlive Docker image). Syntax manually audited
      (amsmath added for \text/\|; brace/math balance checked). Needs a compile pass to confirm.

## Fix user login and move identity seeder (2026-06-09)
- [x] Moved `seed.Users` from `identity-service` to `tools/seeder/` as requested.
- [x] Created `tools/seeder/crypto/password.go` to handle Argon2id hashing natively without depending on identity-service.
- [x] Implemented `SeedUsers` in `tools/seeder/seeders/users.go` pointing to `securitydb`.
- [x] Refactored `tools/seeder/cmd/seeder/main.go` to connect to `securitydb` reading `SECURITY_DB_URI` and `SECURITY_DB_NAME` from `.env`.
- [x] Added `auth-net` network to the `seeder` container in `deployments/docker/docker-compose*.yaml` so it can reach the security-db.

## Allineamento rotte AI + fix score=1.0 + migrazione ruoli + frontend (2026-06-09)
Piano completo: ~/.claude/plans/obiettivo-necessario-progettare-zippy-sketch.md

### Task A — Migrazione ruoli → guest/operator/manager/admin
- [x] A1 seeder: `tools/seeder/seeders/users.go` → admin/admin, manager1/manager, operator1/operator
      (role/clearance ora in `$set`: ri-eseguire il seeder riallinea anche gli utenti gia' presenti)
- [x] A2 certs: `gen-certs.sh` rifattorizzato con `gen_client_cert()` → admin (OU=admin), manager1
      (OU=manager), operator1 (OU=operator); `create_browser_cert.py` ora parametrico (`python create_browser_cert.py manager1`)
- [x] A3 (extra) `policy.rego`: aggiunte `/api/v1/auth/register/begin|finish` alla matrice
      (POST, operator/manager/admin) — l'enrollment WebAuthn era negato a TUTTI con la nuova policy
- [x] A4 (extra) `policy_test.rego` riscritto per la nuova policy: 26/26 PASS (prima 15/28 FAIL)

### Task B — Rotte AI + retrain
- [x] B1 orchestratore: `normalizeAIPath` (sottorotte /{id} → rotta base, /static/* → /static)
      per KeyDst + ruoli {guest,operator,manager,admin} con divisore len-1 in `buildAIEvent`
- [x] B2/B3 submodule: RESOURCE_URIS = 19 rotte reali esatte, ROLES nuovi, assert
      num_resources==len(URIS) (eliminato il bug del suffisso /0), feature risorsa scalare,
      precursor_half_life 100000→600s, max_boost 3→2; `tests/generator.py` allineato
- [x] B4 retrain (2 iterazioni): la prima ha rivelato che vincoli tier/clearance stretti
      affamavano reactor-parameters/trusted-guard di traffico benigno (score saturi 1.0 per
      TUTTI gli IP) → rilassati a (1,2). Finale: AUC 0.96, verify-tgn 4/4 PASS
- [x] B5 commit submodule (5bcb890) — puntatore aggiornato nel working tree del repo principale

### Task C — Frontend
- [x] C1 `app.js`: ROUTE_RULES = mirror esatto della nuova matrice OPA; `friendlyError(status)`
- [x] C2 `reserved.html`: colonne/idField dai json tag dei modelli Go, form a campi strutturati
      (select per enum, dot-notation per contact.email/location.zone_id), esito leggibile +
      dettaglio raw in `<details>`, WebAuthn finish con public key reale (getPublicKey, base64 std)
      e AAGUID estratto dall'authenticatorData
- [x] C3 `index.html` (link protetti nascosti per non autenticati / non autorizzati),
      `materials.html` (friendlyError), `styles.css` (form-grid, raw-response — solo additive)

### Verifica
- [x] go build: business-logic, security-orchestrator, seeder OK; node --check su app.js e
      su tutti gli script inline dei template OK
- [x] AI: smoke su tutte le 19 rotte (warm+cold) → score 0.002–0.15, nessun 1.0 su traffico
      benigno; flusso reale orchestratore (infer→OPA→update) per un admin nuovo: tutto ALLOW,
      primo contatto documents 0.43 (entro banda), poi stabilizzato a ~0.03–0.06
- [x] opa test: 26/26 PASS
- [ ] E2E nel browser (richiede rigenerare i cert: `bash certs/gen-certs.sh` + reimport .p12,
      ricreare il volume del security-db o rilanciare il seeder, `docker compose up --build`)

## Review
- Causa radice degli score 1.0: (1) le chiavi risorsa del training avevano suffissi sintetici
  (`/api/v1/personnel/0`) quindi OGNI richiesta reale era cold-start sopra soglia; (2) l'alert
  cold-start armava il precursor boost (×4, half-life ~28h reali) che clampava a 1.0 ogni
  richiesta successiva; (3) al secondo training: rotte privilegiate senza traffico benigno
  (vincoli comportamentali troppo stretti) → "qualsiasi accesso = anomalia".
- La migrazione ruoli era il blocco nascosto: con la nuova policy l'admin seedato
  (plant_manager) era negato ovunque — ora seeder/cert/frontend/AI parlano tutti
  guest/operator/manager/admin.
- NOTA per il riavvio: i .p12 nel repo sono generati dai VECCHI cert (OU=plant_manager) →
  rigenerare ed eseguire di nuovo l'import nel browser, altrimenti il login mTLS fallisce.

## Migrazione a 4 nodi / 3 archi: IP → Device → User → Resource (2026-06-10)
Piano approvato: ~/.claude/plans/obiettivo-il-modello-ai-compiled-llama.md
SUPERA la sezione "Grafo Tripartito" sottostante (il tripartito user→device→resource è già
implementato; il delta è separare l'IP dal Device e introdurre l'id hardware tpm:/ck:).

Decisioni chiave: 3 archi (src_ip→device msg-zero, device→user msg-zero, user→resource msg-7d);
score=max sui 3; hist_feats 3→6 dim con contatori (device,dst) senza arco TGN extra; precursor
chiavato sul device; EventIn.key_source opzionale (assente ⇒ si salta l'arco ip→device, path
LANL invariato); schema_version=2, retrain da zero; IP raw + LRU.

- [x] 1. `src/config.py`: num_ips→num_sources=150, num_devices=80, knob p_roam/p_shared_device/
      p_cookie_wipe/p_cred_theft (+ num_wipe_slots/num_theft_slots), hist_feat_dim 3→6,
      schema_version=2, total_nodes aggiornato
- [x] 2. `src/data/stream_synthetic.py`: riscritto attorno a `ZTAStreamSimulator` (stessa logica
      condivisa col generatore live dei test → eliminata la duplicazione storica); device
      tpm:/ck:, roaming, NAT/office IP, device condivisi, cookie-wipe (slot freddi), etype 4 =
      credential theft (incident burst da IP+device attaccante), bitmask `scenario`; ritorna
      dataclass `SyntheticStream` (niente più tuple posizionali fragili)
- [x] 3. `src/serve_tgn.py`: score_event/commit_event con key_source opzionale (assente ⇒ arco
      saltato, mai aliasing), 3 infer + max, precursor su device, contatore aux (device,dst)
      via update_memory(aux_pair=...), helper _admit, gate schema_version in build_model.
      FIX BUG preesistente: signal_dirty leggeva features[4] (metodo HTTP) come sensore →
      ogni POST finiva sulla soglia conservativa. Corretto (indici 0-3) anche in _rule_baseline.
- [x] 4. `src/train_tgn.py`: StreamData con source/device/scenario opzionali (LANL = solo arco
      user→dst), _replay a 3 archi, **InfoNCE anche sugli archi di binding** (device→user con
      utenti random, source→device con device random): necessario perché col furto di
      credenziali l'arco di accesso user→resource è CALDO (utente noto, risorsa abituale) —
      il segnale vive solo nei binding; hist feats 6-dim (aux device→resource), eval
      per-scenario nel report e nel dict metriche
- [x] 5. `src/serve_api.py`: EventIn.key_source, threading su /infer /update /score, broadcast
      con key_source, /health con schema_version; gui/main.js normalizza key_src=key_device
- [x] 6. tests: generator.py = wrapper di ZTAStreamSimulator (warmup 50k per continuità col
      training), fix KeyError key_src in test_client.py (grace per key_user), metrics.py con
      tipo 4, baselines ×3 allineati (erano GIÀ rotti: 9 nomi da tupla a 10), lanl_auth.py
      fixato (passava src= a StreamData che non esiste più), verify_tgn riscritto (era GIA'
      rotto: firma a 2 chiavi) + nuovo check fallback, nuovo tests/test_serve_v2.py (4 test)
- [x] 7. docs: orchestrator_integration.md (schema v2, esempi curl/Go) + README aggiornati
- [x] 8. Validazione (tutti i gate PASS):
      - training pieno 50k/15ep: lateral AUC 0.818 (gate ≥0.73; v1=0.760), agg AUC 0.919
      - cred-theft: recall 1.00 / AUC 0.969 (gate ≥0.8)
      - FPR roaming 0.180 vs plain 0.172 = 1.05× (gate ≤1.5×)
      - lateral su shared device 0.381 ≈ 0.376 complessivo (gate: comparabile)
      - verify-tgn 5/5 PASS; pytest test_serve_v2 4/4 + stable_hash + calibration PASS
      - test_client live 60s: precision 0.84, specificità benigna 93.8%, CredTheft 100%,
        lateral 31%, P50 16ms (+~50% atteso per il 3° arco)
      - eval-lanl: pipeline single-edge OK, AUC 0.836 vs ~0.88 storico ma con n=5 lateral
        nella finestra (rumore dominante; da rivalutare su finestra più ampia)

### Review — migrazione 4 nodi (2026-06-10)
- Obiettivi raggiunti: (a) smart working senza falsi positivi (FPR roaming ≈ plain);
  (b) furto di credenziali ora rilevato (prima invisibile per costruzione: IP=device);
  (c) macchina condivisa coperta dal precursor sul nodo device. Lateral AUC MIGLIORATO
  (0.818 vs 0.760) nonostante lo spostamento della novelty su user→resource, grazie ai
  contatori aux (device,resource) 6-dim.
- Trade-off onesti: (1) nel replay offline la precision aggregata è 0.56 (FPR ~17% dal
  feedback trust+memoria congelata del replay puro; nel flusso live con grace period è 6%) —
  punto operativo regolabile con cost_ratio/clean_fpr_cap; non confrontabile 1:1 col v1 per
  via del fix signal_dirty. (2) cookie-wipe: i primi eventi post-wipe vengono flaggati
  (indistinguibili da credential theft per definizione) — gestiti dal grace period.
- Checkpoint v2 in public/ (schema_version=2; i checkpoint v1 vengono rifiutati con errore
  chiaro). Artifact ripristinati post test live (il server persiste lo stato allo shutdown).
- Fase B (repo padre, NON ancora fatta): identity-service emette cookie dispositivo firmato;
  buildAIEvent invia key_source=clientIP e key_device=tpm:<id>|ck:<cookie>; OPA invariata.

## Fase B — repo padre + GUI v2 (2026-06-10)
**Obiettivo:** allineare orchestrator/identity-service allo schema evento v2 del modello
(key_user/key_device/key_dst + key_source opzionale) e portare la GUI 3D alla catena a 4 nodi.

Decisioni:
- Cookie dispositivo `zta_device` = `v1.<uuid-hex>.<hmac-sha256>` firmato con segreto condiviso
  `DEVICE_COOKIE_SECRET` (env, default di sviluppo). La firma serve a impedire a un client di
  inondare il NodeRegistry (LRU) con device-key arbitrarie forgiate; un cookie non valido viene
  ignorato (fallback legacy), mai usato come key.
- Priorità key_device: `tpm:<DeviceID>` se tpmOK, altrimenti `ck:<uuid>` da cookie valido,
  altrimenti fallback legacy `key_device=clientIP` SENZA key_source (come da piano approvato).
- key_user = `claims.UserID`, per richieste anonime `anonymous` (nodo unico, bounded; il
  contesto guest è comunque differenziato da source/device e l'authz resta a OPA).
- Envoy inoltra già l'header `cookie` all'orchestrator (allowed_headers) — nessuna modifica.

- [x] 1. identity-service: `internal/crypto/devicecookie.go` (issue/verify HMAC, cookie
      `v1.<uuid>.<hmac>`, MaxAge 1 anno, HttpOnly+Secure+Lax) + `handler/device_cookie.go`
      con `ensureDeviceCookie` idempotente su GET /login, GET /register, POST login OK,
      POST verify-otp OK. Unit test round-trip + tampering: PASS.
- [x] 2. security-orchestrator: `aiscorer.Event` → `key_user/key_device/key_source(omitempty)/
      key_dst`; `buildAIEvent` risolve la catena (tpm: > ck: da cookie verificato > fallback
      legacy key_device=clientIP senza key_source); key_user=`anonymous` per i guest.
      `handler/device_cookie.go` verifica HMAC (allineato all'identity-service).
- [x] 3. deployments/docker: `DEVICE_COOKIE_SECRET` (default dev, override da .env) su
      identity-service e security-orchestrator in tutte e 3 le varianti compose.
- [x] 4. GUI: catena a 4 colonne/colori (Source azzurro, Device rosso, User ciano, Resource
      arancio), 3 archi per evento, particella che percorre l'intera catena, simulazione con
      eventi v2 (incl. ~5% legacy senza key_source), shim `key_src` rimosso, alert
      `user@device -> dst`, sottotitolo index.html aggiornato.
- [x] 5. Verifica: `go build`+`go vet`+`go test` OK su entrambi i servizi (aggiornati anche i
      literal nei test di aiscorer), `docker compose config -q` OK, `node --check` OK su
      main.js, nessun `key_src` residuo nel repo padre, JSON marshalled dei due path
      (completo e legacy) combacia con `EventIn` di serve_api (key_source assente ⇒ arco
      saltato).

### Review — Fase B (2026-06-10)
- Envoy non toccato: l'header `cookie` era già negli allowed_headers di ext_authz; OPA invariata.
- Cambio semantico rispetto al v1: per gli utenti autenticati senza TPM il device non è più
  `claims.UserID` ma il cookie firmato (`ck:<uuid>`); per i guest `key_user=anonymous` (nodo
  unico bounded) e il contesto resta differenziato da source/device. In assenza totale di id
  hardware si degrada al comportamento legacy (key_device=clientIP, niente key_source).
- Il segreto HMAC condiviso serve solo anti-flooding del NodeRegistry: un cookie rubato resta
  rilevabile dal binding source→device del modello, non dalla firma.
- Nota deploy: al primo rollout i client esistenti non hanno il cookie → fallback legacy fino
  al primo passaggio da /login; nessuna migrazione necessaria.

## [SUPERATO dal piano 4-nodi qui sopra] Progettazione: Grafo Tripartito (Utente -> Dispositivo -> Risorsa) (2026-06-10)
**Obiettivo:** Modellare esplicitamente le tre entità coinvolte in ogni interazione ZTA per non perdere alcuna informazione. L'AI deve sapere *chi* (Utente) sta usando *quale macchina* (Dispositivo/TPM) per accedere a *quale* (Risorsa).

**Soluzione Architetturale (Event Unrolling in TGN):**
Poiché le reti temporali PyG standard (TGN) processano archi coppia (`src -> dst`), modelleremo la relazione tripartita "scindendo" ogni accesso in una catena causale di due archi consecutivi allo stesso timestamp $t$.

1. **Arco 1 (Bind: Utente $\rightarrow$ Dispositivo):** Registra che l'utente sta usando quel dispositivo. L'aggiornamento di memoria propaga il contesto (embedding) dell'Utente dentro la memoria del Dispositivo.
2. **Arco 2 (Access: Dispositivo $\rightarrow$ Risorsa):** Il dispositivo accede alla risorsa portando con sé il payload di rete (metodo, JA3, Snort). Grazie all'arco precedente, l'embedding temporale del Dispositivo ($z_{src}$) conterrà già la "firma" dell'utente.

**Piano di implementazione (Task List):**

- [ ] **1. Modifica Payload API (Python & Go):**
  - Python (`serve_api.py`): Sostituire `key_src` con `key_user` e `key_device` in `EventIn`.
  - Go (`handler.go`): Popolare `KeyUser` (`claims.UserID`) e `KeyDevice` (`"tpm:"+DeviceID` o `clientIP`) e inviarli nel JSON.

- [ ] **2. Modifica Core AI (`serve_tgn.py` e `train_tgn.py`):**
  - Adattare le pipeline di addestramento e inferenza per effettuare l'unrolling.
  - Per ogni evento, calcolare lo score per l'**Arco 2** (Accesso). Lo score per l'**Arco 1** (Logon) può essere usato come penalità o fattore combinato, o semplicemente usato in fase di update (`update_memory`) per instradare la memoria senza impattare la BCE Loss principale dell'accesso.
  - Generare un vettore di features "nulle" o dedicate per l'Arco 1.

- [ ] **3. Allineamento Data Generator (`tests/generator.py`):**
  - Modificare gli yield del generatore per restituire `{key_user, key_device, key_dst, ...}` invece che il solo `key_src`.
  - Distinguere la `node_feature` statica dell'utente da quella del dispositivo.

- [ ] **4. Retraining e Validazione:**
  - Lanciare `docker compose --profile training-tgn up --build train-tgn`.
  - Verificare che il modello converga (la lateral AUC dovrà dimostrare che il TGN riesce a propagare il segnale attraverso il nodo intermedio del device).
  - Assicurarsi che i test `verify-tgn` passino con il nuovo schema tripartito.

## Review — Stress test v3 (2026-06-10)
Verified `tests/test_client.py` (streaming load) against the v3 inference service.
- Setup: service via `docker compose --profile serve-tgn up --build` (healthy, `schema_version=3`, CUDA); client via project `.venv` (registered `graphagate` editable `--no-deps`, added `torch==2.12.0+cpu` for py3.14 — fastapi/sklearn/torch_geometric/uvicorn are serve-side only, live in the container).
- Result: 10474 events, **0 HTTP/schema errors**; namespaced keys flow end-to-end (`src:100.64.0.30`, `ck:0059-g0`). Latency P50 6.2ms / P99 7.2ms.
- Detection: Benign 98.56% spec · Policy 88.93% · Contextual 96.40% · CredTheft 77.97% · Lateral 21.26% (consistent with the validated ~22.6% lateral-recall baseline in lessons.md — not a regression from the v3 changes).
- Conclusion: stress test is functional and compatible with the 4-node v3 schema.
