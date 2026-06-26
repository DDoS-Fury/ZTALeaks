#!/bin/bash
# =============================================================================
# Entrypoint wrapper per i container DB (business-db / security-db)
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# Avvia in background il tailer del profiler (che produce db_access.jsonl) e poi
# cede il controllo all'entrypoint ufficiale di MongoDB con `exec`, cosi' mongod
# resta PID 1 e mantiene intatta la gestione dei segnali / shutdown pulito.
# Il tailer e' un processo figlio: alla terminazione del container viene chiuso
# insieme a mongod.
# =============================================================================
set -e

# Lancia il tailer in un subshell in background (attende mongod internamente).
/usr/local/bin/profile-tailer.sh &

# Cede a mongod come processo principale (PID 1).
exec docker-entrypoint.sh "$@"
