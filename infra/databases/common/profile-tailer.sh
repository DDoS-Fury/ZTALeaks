#!/bin/bash
# =============================================================================
# Profiler tailer launcher (eseguito dentro il container DB, in background)
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# Attende che mongod sia pronto e autenticabile, poi avvia il tail del profiler
# (profile-tailer.js) redirigendo l'output JSONL su $LOG_FILE — la dir e' gia'
# montata come volume e monitorata dalla Splunk Universal Forwarder.
#
# Variabili attese (impostate via ENV nel Dockerfile/compose):
#   TAILER_URI  connessione mongosh (utente con read su <db>.system.profile)
#   TARGET_DB   database da osservare (passato al .js via env)
#   LOG_FILE    file di output JSONL
# =============================================================================
set -u

# HOME dedicato e scrivibile per mongosh: senza, mongosh tenta di creare la sua
# cache sotto /data/db (EACCES) e — peggio — la dir creata in anticipo manderebbe
# in errore il parser di config di mongod nell'entrypoint ufficiale.
export HOME=/tmp/mongosh-tailer
mkdir -p "$HOME"

TAILER_JS="/usr/local/bin/profile-tailer.js"
LOG_FILE="${LOG_FILE:?LOG_FILE non impostato}"
TAILER_URI="${TAILER_URI:?TAILER_URI non impostato}"
ERR_FILE="${LOG_FILE%.jsonl}.tailer.err"

mkdir -p "$(dirname "$LOG_FILE")"

# Attendi che mongod sia su e che le credenziali del tailer funzionino
# (su primo avvio le init-scripts devono prima creare l'utente profiler_reader).
until mongosh "$TAILER_URI" --quiet --eval 'db.adminCommand("ping").ok' >/dev/null 2>&1; do
    sleep 2
done

echo "[profile-tailer] mongod pronto, avvio tail di ${TARGET_DB}.system.profile -> ${LOG_FILE}" >&2

# exec: il tailer diventa il processo di questo subshell (background del wrapper).
exec mongosh "$TAILER_URI" --quiet --file "$TAILER_JS" >> "$LOG_FILE" 2>> "$ERR_FILE"
