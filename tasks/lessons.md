# Self-Improvement Lessons

## Docker Command Documentation
**Mistake**: I attempted to guess the standard `docker compose` command (`docker compose --profile training-tgn up --build train-tgn`) instead of reading the provided documentation.
**Correction**: The user pointed out the existence of `docs/docker.md` which specified the exact command (`docker compose --profile training-tgn up`).
**Rule**: Always check for specific documentation (e.g. `docs/docker.md`, `README.md`) in the component folder before attempting to run services or scripts. Do not assume standard commands apply directly without checking documentation.

## Data-leak audits: check the docs, not just the code
**Mistake pattern**: When asked to "check for data leaks", the instinct is to read only the code paths. But a clean codebase can ship with documentation (`docs/latex/report.tex`) that still describes a *removed* leaky technique as if it were current.
**Finding (2026-06-07)**: The code was leak-free (de-circularized uniform negatives, val-only calibration, benign-only training), yet `report.tex` still documented the removed `×10 hard-negative on non-habitual resources` (the exact circular leak), a wrong loss (`BCEWithLogitsLoss` sum instead of InfoNCE + anchors), the struct head as the lateral detector (ablation says marginal), and an unsupported "≈50% lateral recall" (validated: 22.6%).
**Rule**: A data-leak / correctness review must cross-check documentation against the *current* code. Stale docs that present a removed leak as a live feature are themselves a defect — flag and fix them. When citing numbers in docs, trace each to a validated run (todo.md review section), never to an aspirational target.

## LaTeX edits without a local engine
**Mistake risk**: Added `\text{}`, `\|`, `\hat` in math mode to `report.tex` whose preamble lacked `amsmath`.
**Rule**: When editing `.tex` and no compiler is available locally, audit every new macro against the loaded packages (add `\usepackage{amsmath}` if using `\text`/`\|`/aligned envs), and state explicitly that the file was not compiled.
