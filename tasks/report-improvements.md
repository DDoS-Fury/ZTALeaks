# Piano: miglioramenti al report e al rigore sperimentale

> Origine: emersi durante la verifica/riconciliazione delle metriche di `infra/ai-inference/docs/latex/report.tex`
> (audit + rigenerazione Pannello A e Pannello B `tab:v3v4`). Data: 2026-06-23.
> Contesto: il report era un collage di run storiche; la rigenerazione paired v3→v4 ha
> mostrato che il "dominio uniforme di v4" era un artefatto del confronto contro un v3 debole
> (ora corretto in trade-off). Vedi `tasks/lessons.md` e la memoria `report-tables-historical-runs`.

## Priorità

### [P1] Eliminare i numeri single-run dai titolari (multi-seed su Pannello A e B)
**Problema.** Pannello A (`tab:baselines`) e Pannello B (`tab:v3v4`) sono single-run (seed 42),
rumore ammesso ±0.01–0.03. Diversi Δ commentati nel testo sono DENTRO il rumore (es. v3→v4
AUC aggregata −0.008, AUC laterale +0.004). È la radice dei problemi: la run "fossile"
0.947/0.900 non riproducibile, la narrazione v4 ribaltata.
**Fix.** Rigenerare Pannello A e B in **multi-seed (3 seed [42,7,123], media±std)**, come già
fatto per `tab:theft` e `tab:archsweep`. Aggiornare tabelle + prosa con media±std e ricalcolare
quali Δ sopravvivono al rumore.
**Vincoli.** `save=False` (NON sovrascrivere `public/tgn_checkpoint.pt`). ~6 run da ~10 min.
**Done quando.** Ogni cella titolare ha media±std; ogni Δ commentato è > banda di rumore o è
dichiarato non significativo; log in `tasks/runs/`.

### [P2] Rendere il report un artefatto riproducibile
**Problema.** Numeri da run storiche, copiati a mano nelle tabelle → da qui la deriva.
**Fix.**
- (a) Output **JSON delle metriche** da `train_tgn` (oltre ai `print` su stdout).
- (b) Script unico (`make report-data` o `tests/regen_report_tables.py`) che rigenera ogni
  tabella da zero con seed fissati, scrivendo in `tasks/runs/`.
- (c) Mappa "tabella → log sorgente" nel report (o in un README accanto al .tex).
**Done quando.** `make report-data` rigenera tutti i numeri delle tabelle senza copia manuale;
ogni tabella cita il log che la genera.

### [P3] Sciogliere il protocollo misto del Pannello A
**Problema.** Riga TGN = v3 per-cookie; baseline = guest. Due configurazioni diverse nella stessa
tabella (oggi coperto solo da nota di provenienza). Inoltre il deployable reale è **v4+guest**,
che non è la riga presentata come "TGN".
**Fix.** Scegliere UNA configurazione canonica (deployable = v4+guest) e misurare TGN **e** tutte
le baseline sotto quella. Una tabella, un protocollo, niente note di scusa.
**Nota decisionale.** Comporta rivedere la scelta storica "tieni v3 per-cookie per continuità".
Decidere DOPO P1. Richiede conferma utente (cambia l'identità della riga TGN titolare).

## Minori (reali ma a basso sforzo)

### [m1] Bug packaging XGBoost
`xgboost` è in `requirements.txt` ma NON in `pyproject.toml` → l'immagine non lo include
(workaround usato: `pip install` a runtime). Aggiungerlo a `pyproject.toml`/Dockerfile così la
baseline XGBoost è riproducibile out-of-the-box.

### [m2] Semplificare/rimuovere la struct head
Contributo marginale (+0.007 AUC, ablation multi-seed Cap.1). Già segnata tra i next-step in
memoria. Rimuoverla/semplificarla riduce parametri a parità di risultato → modello più difendibile.

### [m3] Cold-start FPR (~43% specificità benigna)
Costo operativo reale. Aggiungere una frase esplicita su come l'orchestratore lo mitiga
(grace period a 5 eventi già citato) per non lasciare il dubbio al lettore.

## Raccomandazione
Partire da **P1** (massima credibilità / minimo sforzo, infra già pronta). P3 è il più "pulito"
ma rivede scelte già prese → decidere dopo P1. m1 è un quick win indipendente.

## Stato
- [x] P1 — multi-seed Pannello A/B (3 seed [42,7,123]). Esito: headline TGN rivisto a valori
  onesti (lateral AUC 0.913±0.014 vs 0.932 single-run; agg AUC 0.965±0.007 vs 0.973). Su v3→v4
  ora l'AUC laterale (+0.017) E il recall laterale instradato (+0.227) sono significativi;
  AUC/AP aggregate restano entro il rumore. report.tex compila (latexmk exit 0).
- [x] P2 — riproducibilità: `src/report_metrics.py` + `train_tgn` ritorna `agg_recall_global` +
  baseline ritornano dict + `tests/regen_report_tables.py` (profilo `regen-report`) →
  `tasks/runs/panel{A,B}.json` + `docs/latex/generated/*.tex` + `docs/latex/PROVENANCE.md`.
- [ ] P3 — protocollo unico Pannello A (richiede conferma) — RIMANDATO
- [x] m1 — xgboost in pyproject.toml (verificato import dall'immagine, v3.3.0)
- [ ] m2 — semplificare struct head — RIMANDATO
- [ ] m3 — frase su cold-start FPR — RIMANDATO (non selezionato in questa sessione)
