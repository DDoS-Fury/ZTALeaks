# Task Management

## [~] Align AI training data + model with the new BLP `policy.rego`

Goal: verify the AI model in `infra/ai-inference/` is trained in compliance with the
rewritten BLP `infra/opa/policy.rego`; verify tests reflect it; if non-compliant, fix the
synthetic training data and retrain.

### Findings
- **NON-COMPLIANT.** `policy.rego` was rewritten from flat RBAC to Bell-LaPadula
  (clearance-from-role, per-route classification + compartments, no-read-up / no-write-down,
  trusted-guard sanitized write-down). The generator `src/data/stream_synthetic.py` still
  encoded the old RBAC model (random clearance, no categories, no write-down), so the
  benign manifold included OPA-denied accesses and `etype=1` events were tier-failures, not
  real policy violations.
- `RESOURCE_RISK` (+ `test_netclass.py`) mirrors `handler.go::getResourceSensitivity`, a
  separate source of truth — left untouched.

### Steps
1. [x] Plan (approved): mirror `policy.rego` BLP in the generator; add BLP tests; full retrain.
2. [x] Rewrite authorization model in `stream_synthetic.py`:
   - `SECURITY_LEVELS`/`ROLE_CLEARANCE`/`ROLE_CATEGORIES`/`SECURITY_MATRIX`/`ROUTE_METHODS`
     as 1:1 mirrors of the rego; new `policy_allows(role, method, uri)` decision function.
   - clearance derived from role; tier demoted to realism only (never a policy gate).
   - benign = `_policy_valid_actions`; `etype=1` = `_policy_violations`; theft loot + lateral
     stolen-identity clearance made BLP-consistent. `/auth/register/{begin,finish}` → public.
3. [x] New `tests/test_policy_blp.py` (BLP truth table + generated-stream compliance invariant).
4. [x] Verify: `test_policy_blp.py` (13) + `test_netclass.py` + `test_serve_v2.py` +
   `test_calibration.py` + `test_stable_hash.py` all green. Generated stream: 0 benign
   denied, 0 fake violations.
5. [x] Full retrain on **GPU via docker compose** (`docker compose --profile training-tgn up
   train-tgn`, RTX 5070 Ti, 200k×15) — NOT the local CPU venv (corrected mid-task).
   Regenerated `public/tgn_checkpoint.pt` + `tgn_stats.json`.
6. [x] Reviewed metrics (below); checkpoint loads via `serve_tgn.load_model`; thresholds finite.
7. [ ] Decide on the checkpoint "commit": `public/*.pt|*.json` are GITIGNORED (160 MB blob,
   intentionally out of git) — needs user decision before any `git add -f`. Source/test
   changes ARE committable.

### Review
- **Compliance restored.** Generator `policy_allows()` is a 1:1 port of the BLP `policy.rego`.
  Invariant on a generated stream: 0 benign events OPA would deny, 0 `etype=1` that OPA would
  allow; clearance == role's clearance for every user.
- **Retrain metrics (200k×15, GPU, seed 42), no regression / no saturation:**
  - aggregate AUC 0.957, AP 0.910 (routed precision 0.846 / recall 0.748)
  - policy (OPA-owned sanity): AUC 0.984, recall 0.957 — now genuine BLP violations
  - contextual: AUC 0.994, recall 0.981 ; lateral (value-add): AUC 0.895, cost-routed recall 0.319
  - benign val score mean 0.0033 / p95 0.0089 → no score saturation (as predicted once
    clearance derives from role and tier no longer gates)
  - thresholds: clean 0.0089, dirty 0.0123 (finite, sane)
- **Tests:** `test_policy_blp.py` (new, 8 cases) + existing `test_netclass/serve_v2/calibration/
  stable_hash` → 18 passed. Serving path unaffected.
- **Files changed:** `src/data/stream_synthetic.py` (auth model rewrite),
  `tests/test_policy_blp.py` (new). `RESOURCE_RISK`/`test_netclass.py` left as-is (mirror
  `handler.go`, not the rego). Regenerated artifacts in `public/` (gitignored).
