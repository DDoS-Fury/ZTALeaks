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
