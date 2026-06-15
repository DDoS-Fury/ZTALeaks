# Self-Improvement Lessons

## Docker Command Documentation
**Mistake**: I attempted to guess the standard `docker compose` command (`docker compose --profile training-tgn up --build train-tgn`) instead of reading the provided documentation.
**Correction**: The user pointed out the existence of `docs/docker.md` which specified the exact command (`docker compose --profile training-tgn up`).
**Rule**: Always check for specific documentation (e.g. `docs/docker.md`, `README.md`) in the component folder before attempting to run services or scripts. Do not assume standard commands apply directly without checking documentation.

## Addestramento/inferenza: USA SEMPRE il `docker compose` del componente (GPU), MAI il venv locale
**Mistake (2026-06-15)**: per il retrain del TGN ho lanciato `python -m graphagate.train_tgn` nel
`.venv` locale (torch CPU build) — girava su CPU a ~9 it/s (ETA ~2h), mentre la macchina ha una
RTX 5070 Ti e `infra/ai-inference/docker-compose.yml` definisce già il servizio `train-tgn`
(profilo `training-tgn`) con riserva GPU nvidia e i bind-mount `./src` + `./public`. Sul percorso
Docker corretto il training ha girato su `cuda` (~40 it/s, retrain completo in pochi minuti).
**Regola**: per QUALSIASI run di training/eval/serve di un componente containerizzato, lanciare
sempre il servizio `docker compose` previsto (`docker compose --profile training-tgn up train-tgn`),
che porta GPU + dipendenze + volumi corretti. Non ricreare l'ambiente nel venv locale. Indizio
diagnostico già nel repo: gli artifact `public/*.pt` erano `root`-owned → prodotti in container.
Verificare `nvidia-smi` e i profili compose PRIMA di scegliere come eseguire. Collegata alla
lezione "Docker Command Documentation" sopra: leggere `docker-compose.yml` / `docs/docker.md` prima.

## Compliance del modello AI = il manifold benigno DEVE essere l'insieme che OPA consente
**Contesto (2026-06-15)**: `policy.rego` riscritta da RBAC a Bell-LaPadula (clearance dal ruolo,
classificazione+compartimenti per rotta, no-read-up/no-write-down, eccezione trusted-guard). Il
generatore sintetico `stream_synthetic.py` codificava ancora l'RBAC vecchio (clearance random
indipendente dal ruolo, niente categorie, niente write-down) → il TGN imparava come "normali"
accessi che la policy NEGA (es. admin POST /documents = write-down) e marcava come `etype=1` dei
fallimenti di *tier* che OPA non controlla nemmeno.
**Regola**: quando la policy di autorizzazione cambia, i dati sintetici di training vanno allineati
1:1 alla decisione di allow reale (qui un `policy_allows()` che è un port diretto del rego), così il
manifold benigno = traffico consentito da OPA e gli `etype=1` sono violazioni reali. Aggiungere un
test-invariante sullo stream generato (0 eventi benigni negati, 0 falsi `etype=1`) e ritrainare.
Distinguere ciò che è gate di policy (OPA) da ciò che è solo realismo (il device *tier*): il
realismo non deve mai rietichettare un accesso consentito come violazione. NB: `RESOURCE_RISK`
rispecchia `handler.go::getResourceSensitivity`, una fonte di verità DIVERSA dal rego — non toccarla
solo perché "sta nel dominio policy".

## Data-leak audits: check the docs, not just the code
**Mistake pattern**: When asked to "check for data leaks", the instinct is to read only the code paths. But a clean codebase can ship with documentation (`docs/latex/report.tex`) that still describes a *removed* leaky technique as if it were current.
**Finding (2026-06-07)**: The code was leak-free (de-circularized uniform negatives, val-only calibration, benign-only training), yet `report.tex` still documented the removed `×10 hard-negative on non-habitual resources` (the exact circular leak), a wrong loss (`BCEWithLogitsLoss` sum instead of InfoNCE + anchors), the struct head as the lateral detector (ablation says marginal), and an unsupported "≈50% lateral recall" (validated: 22.6%).
**Rule**: A data-leak / correctness review must cross-check documentation against the *current* code. Stale docs that present a removed leak as a live feature are themselves a defect — flag and fix them. When citing numbers in docs, trace each to a validated run (todo.md review section), never to an aspirational target.

## LaTeX edits without a local engine
**Mistake risk**: Added `\text{}`, `\|`, `\hat` in math mode to `report.tex` whose preamble lacked `amsmath`.
**Rule**: When editing `.tex` and no compiler is available locally, audit every new macro against the loaded packages (add `\usepackage{amsmath}` if using `\text`/`\|`/aligned envs), and state explicitly that the file was not compiled.

## Una feature "di contesto" può mascherare un attacco (valida ogni feature contro TUTTE le classi)
**Contesto (2026-06-10)**: aggiunta una feature `source-internal` (bit RFC1918 interno/esterno
sul nodo rete) come da richiesta utente. Il primo retrain mostrava lateral AUC SU (0.818→0.900)
e quindi sembrava un successo — ma la cred-theft era CROLLATA (AUC 0.969→0.662, recall 1.00→0.49).
**Mistake da evitare**: giudicare una nuova feature solo sulla metrica aggregata o sulla classe
che si intendeva migliorare. La feature "esterno benigno" (roaming/CGNAT) normalizza i binding
`esterno→device`, che sono ESATTAMENTE l'arco su cui vive il segnale del furto di credenziali →
la feature ha mascherato l'attacco.
**Regola**: ogni nuova node/edge feature va valutata contro TUTTE le classi di anomalia (metriche
per-tipo a parità di seed = stessi eventi di test), non solo l'aggregato. Rendere ogni feature
nuova ABLABILE con un flag (come `use_hist_feats`/`use_precursor` già nel progetto), persisterlo
in `hyperparams` del checkpoint e gatarlo a serve-time. Default OFF finché non passa il gate
della classe che potrebbe regredire. Quando una richiesta utente introduce un trade-off di
sicurezza, implementarla dietro flag + riportare il trade-off, non spedirla di nascosto.

## In caso di regressione: STOP, isola con un'ablation, non accettare il "netto positivo"
**Contesto (2026-06-10)**: davanti al miglioramento lateral + regressione cred-theft, la
tentazione era spedire ("AUC aggregata su, va bene"). Invece: STOP, ipotesi sul meccanismo,
ablation controllata (retrain con la sola feature sospetta disattivata, stesso seed) → conferma
che `source-internal` era il colpevole (cred-theft 0.662→0.922) e che `resource-risk` era
innocuo/benefico. Tre run a parità di seed danno attribuzione pulita.
**Regola**: alla prima regressione di una metrica di sicurezza, fermarsi e isolare con
un'ablation a parità di seed prima di concludere. Un seed fisso rende gli eventi di test
identici tra i run → i delta per-classe sono attribuibili, non rumore.

## Entity mapping in AI models
**Mistake**: Assuming that creating distinct entity IDs (`tpm:<deviceId>`) for different devices of the same user preserves user identity for the AI model. It does not. The TGN model treats distinct strings as completely disconnected nodes, meaning the historical profile of the user is split and lost across their devices.
**Rule**: When designing graph-based AI models (like TGN), the primary entity identifier (`KeySrc`) must remain the core entity (the `User`), while device characteristics (like TPM presence or device tier) should be passed as edge features or dynamic node features. Do not branch the core entity ID based on the authentication mechanism unless you explicitly want a disconnected graph node.

## Validazione Payload: Go (JSON/Structs) vs MongoDB (BSON)
**Mistake pattern**: Aggiungere una validazione superficiale lato backend (es. `validate:"required"`) senza controllare i vincoli dello schema MongoDB sottostante (es. Regex pattern su campi chiave). Ancora peggio, trascurare la conversione da slice Go `nil` a BSON `null`, che causa la rottura dei vincoli `bsonType: "array"` in MongoDB.
**Finding (2026-06-14)**: L'API restituiva 500 in POST a causa di payload che superavano la validazione Go ma fallivano quella di MongoDB. Le slice opzionali mancanti venivano scritte come `null` e i campi ID non rispettavano il pattern richiesto, mandando in panico il database e nascondendo all'utente il vero errore 400 Bad Request.
**Rule**: Assicurarsi sempre che la validazione lato backend copra gli stessi vincoli di dominio, tipo e pattern imposti dallo schema Database. Usare il tag `omitempty` nei campi `bson` per le slice opzionali, di modo che se sono vuote (nil) in ingresso non vengano inserite nel DB come `null`. Registrare custom validators per garantire la congruenza delle espressioni regolari prima della chiamata al DB. Includere test per assicurarsi che i payload con campi mancanti/malformati vengano rifiutati correttamente.
