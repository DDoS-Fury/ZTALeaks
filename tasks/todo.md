# Fix AI Default Score on Public Routes

## Goal
Resolve the discrepancy noted by the AI reviewer regarding the default AI score of 0.5 on public routes.

## Context & Finding
- The AI reviewer noted that the default score on public routes is `0.5`, ma `infra/ai-inference` non lo imposta.
- L'analisi del codice ha confermato che:
  1. `infra/ai-inference` non restituisce `0.5`.
  2. Il **Security Orchestrator** (`services/security-orchestrator/internal/aiscorer/client.go`) implementa una logica *fail-suspicious*: se il modello AI è irraggiungibile, restituisce `0.99`.
  3. L'ambiguità nasce dal **Security Orchestrator (in particolare da OPA)**: in `infra/opa/policy.rego` (riga 69) c'è un fallback hardcoded `ai_score := object.get(input, ["ai", "score"], 0.50)` per le rotte pubbliche.
- Poiché l'orchestrator passa *sempre* la chiave `ai.score` (al massimo passandola a `0.99` se il microservizio fallisce), OPA non utilizzerà mai quel `0.50` di default. Tuttavia, questo valore è inconsistente col resto della policy (che usa `0.99` a riga 185) e con il design *fail-suspicious* descritto nella tesi.

## Plan
- [x] 1. Modificare `infra/opa/policy.rego`: cambiare `object.get(input, ["ai", "score"], 0.50)` in `0.99` per coerenza con la sezione BLP e la documentazione.
- [x] 2. Aggiornare `tasks/todo.md` segnando il task come completato e inserire una section di Review.

## Review
Il default per l'AI score sulle rotte pubbliche all'interno della policy OPA è stato corretto. È passato da `0.50` a `0.99`, rispettando pienamente il design "fail-suspicious" della Zero Trust Architecture documentato nella tesi. La discrepanza segnalata è risolta.
