# Fix: train/serve feature skew (device tier scritto nel nodo utente)

## Diagnosi (verificata empiricamente, 2026-06-23)
Un admin appena registrato (TPM ok) viene bloccato con `ai_score≈0.98`. Sonda A/B/C
in-process sul checkpoint reale (stesse chiavi cold, unica variabile `src_feat`):

| src_feat | docs | reactor |
|---|---|---|
| `[role=1,clr=1,tier=1]` (prod oggi) | 0.461 | **0.959** ≈ log 0.982 |
| `[0,0,0]` (utente training-consistent) | 0.132 | 0.249 |
| `[0,0,tier=1]` | 0.457 | 0.963 |
| `[role=1,clr=1,0]` | 0.134 | 0.239 |

- Driver unico: edge `access user→res`; binding edge ≈0.
- Colpevole: **`srcFeat[2]`=device tier scritto nel nodo UTENTE**. In `stream_synthetic.py`
  `node_feat[2]`≠0 solo per i nodi *device*; per gli utenti è sempre 0. `score_event`
  applica lo stesso `src_feat` a utente E device → l'utente diventa OOD.
- Role/clearance (`[0]/[1]`) sono innocui (viaggiano già nel messaggio).
- Lo skew è presente anche in `tests/generator.py:55` (`src_feat = nf[device]`), quindi nel
  path di eval HTTP. L'eval **offline** (`_replay`) è pulito (non usa `src_feat`).

## Parte 1 — Fix (Option B: contratto feature per-tipo-di-nodo) — DA IMPLEMENTARE
Obiettivo: il serving riproduce esattamente il contratto del training — nodo utente = zeri,
nodo device = tier in `[2]` — senza rinunciare a una feature appresa (scelta pubblicabile).

- [x] `infra/ai-inference/src/serve_tgn.py`: in `score_event` e `commit_event` sostituire il
      singolo `src_feat` (applicato a utente+device) con `user_feat` e `device_feat`;
      applicare `user_feat`→nodo utente, `device_feat`→nodo device, `dst_feat`→risorsa.
      Aggiornare docstring.
- [x] `infra/ai-inference/src/serve_api.py`: `EventIn` → sostituire `src_feat` con
      `user_feat`/`device_feat` (mantenere `dst_feat`); aggiornare `_validate_dims` e le 3
      chiamate (`/infer`, `/update`, `/score`).
- [x] `services/security-orchestrator/internal/aiscorer/client.go`: struct `Event` →
      `UserFeat`/`DeviceFeat` (json `user_feat`/`device_feat`) al posto di `SrcFeat`.
- [x] `services/security-orchestrator/internal/handler/handler.go` `buildAIEvent`:
      costruire `deviceFeat` con solo `[2]=tier`; `userFeat` = zeri. Rimosso role/
      clearance dalle feature di nodo (restano nel messaggio `Features[5],[6]`).
- [x] `infra/ai-inference/tests/generator.py`: manda `user_feat = nf[ev["user"]]` (zeri) e
      `device_feat = nf[ev["device"]]`.
- [x] Test che passano `src_feat`: nessuno (i test serve passano i feat solo come kwarg
      opzionale, mai `src_feat`; le baseline usano `src_feat` come variabile locale, non l'API).

### Verifica Parte 1
- [x] Sonda A/B in-process sul checkpoint reale (GPU): admin cold benigno, single-key.
      docs OLD 0.42→BLOCK / NEW 0.107→ALLOW; reactor OLD 0.985 (≈log 0.982)→BLOCK / NEW 0.018→ALLOW.
- [x] Sonda aggregata (60 identità cold, isola il segnale dal rumore dell'hash embedding):
      reactor tier=1.0 (TPM) OLD block 87% → NEW block 27%; docs ~invariato a livello di gate.
      Il bias sistematico colpiva soprattutto l'admin TPM su risorse TOP_SECRET (il caso prod).
- [x] `pytest` (test_serve_v2, test_policy_blp, calibration, netclass, stable_hash): 20 passed.
- [x] `go build ./...` + `go test ./...` orchestratore: OK (aiscorer pass).
- [x] Eval offline (`_replay`) invariato: la fix tocca solo il path di serving; il replay
      legge `model.node_feat` diretto e non inietta mai feature statiche per-evento.

## Review (2026-06-23)
**Fix applicato** (Option B, contratto feature per-tipo-di-nodo): 5 file, 2 servizi.
serve_tgn.py / serve_api.py / client.go / handler.go / generator.py. Build+test verdi.

**Metriche online rigenerate** (test client live cold-start, checkpoint corrente, GPU
RTX 5070 Ti, run da 90 s, ~8 k eventi). Confronto pulito old-skew vs fix sullo *stesso*
checkpoint (old-skew emulato via branch diagnostico env-gated, poi rimosso):

| Path | Lateral recall | Specificità benigna | Latenza P50/P99 |
|---|---|---|---|
| OLD skew (device ≈ no-device) | 86.7% | 32.7% | 9.4 / 10.6 ms |
| NEW fixed (device ≈ no-device) | 82.1% | 43.4% | 9.5 / 10.8 ms |

- La fix **migliora** la specificità benigna in cold-start (32.7%→43.4%, meno falsi
  positivi) a fronte di un piccolo calo di recall laterale (86.7%→82.1%): lo skew
  faceva apparire ogni utente cold come OOD (tier sul nodo utente) → più flagging.
- device-edge vs no-device: ora **identico** in puro cold-start (il device cold non
  porta storia) — la fix non lo cambia; aggiornata di conseguenza la sezione serving.
- I numeri online preesistenti nel report (lateral ~47%, specificità ~76%, latenza
  v3 a 3 archi/6.0 ms) erano **stantii**: descrivevano lo schema v3 e/o un checkpoint
  precedente, NON il checkpoint deployato. Aggiornati a v4 + fix.

**Metriche offline**: NON toccate dalla fix (path di serving isolato). Non re-verificabili
indipendentemente senza un retrain completo (train_tgn non ha modalità eval-only; ri-eseguire
produrrebbe un *nuovo* checkpoint non-deterministico, non validerebbe quello attuale).
Lasciate invariate; la non-influenza è argomentata in report (replay non usa src_feat).

**Report aggiornato**: `infra/ai-inference/docs/latex/report.tex` §serving (sola sezione
con numeri online) + PDF ricompilato (latexmk, exit 0).

## Parte 2 — Residuo cold-start su reactor-parameters — DA DECIDERE (poi plan)
Anche col fix, admin *davvero* nuovo su reactor = ~0.25 vs gate OPA `≤0.10` → ancora bloccato.
È vero cold-start (piccolo) + gate strettissimo. Opzioni:
- **(consigliata) Astensione/confidence-gating**: il servizio AI espone un segnale di cold-start
  reale (es. src senza storia benigna; oggi `confidence` è solo "rete ha risposto"). OPA, in
  assenza di evidenza, defer alla policy deterministica (BLP+cert+TPM) invece di lasciar negare
  uno score senza evidenza. Story Zero-Trust pulita e pubblicabile.
- Enrollment warmup: seed di eventi benigni alla registrazione TPM (fabbrica baseline — più
  debole per un paper).
- Ritaratura `rischio_accettato` reactor (rozza, indebolisce la sicurezza).
- [ ] Decidere l'approccio, poi entrare in plan mode dedicato.

## Note di pubblicazione
- Solo le metriche **offline** (`train_tgn._replay`) sono pulite; numeri "online" dal test
  client sono contaminati dallo stesso skew → da rigenerare dopo il fix se citati.
- Aggiornata `tasks/lessons.md` con la lezione "verifica empirica dello skew train/serve".
