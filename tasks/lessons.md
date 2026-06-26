# Lessons

## Decidere invece di richiedere conferma a oltranza
- **Contesto**: dopo "correggi entrambi" ho corretto i bug ma ho continuato a chiedere "opzione A o B?" per OPA. L'utente si è spazientito.
- **Causa**: avevo informazioni sufficienti per indagare e decidere (bastava leggere il `command` del servizio OPA nel compose).
- **Regola**: quando l'utente ha già dato il via libera ("correggi", "fai"), non riproporre la stessa scelta. Indaga fino alla root cause e prendi la decisione difendibile; chiedi solo se manca un'informazione che non posso recuperare da solo.

## Verificare il flusso reale dei log, non solo la presenza della stanza
- OPA non scrive su `/var/log/ztaleaks/opa`: usa `decision_logs.service=orchestrator` e spinge via HTTP all'orchestrator, che scrive `opa_decision.jsonl` in `/var/log/ztaleaks/orchestrator` (già raccolto da Splunk).
- **Regola**: prima di aggiungere un monitor Splunk, verificare che qualcuno scriva davvero in quel path (compose `command`, `LOG_DIR`, Dockerfile), non solo che il volume sia montato.
