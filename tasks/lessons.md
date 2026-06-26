# Lessons

## L1 — Non mutilare i dati per risolvere un problema di trasporto
**Contesto:** ho proposto di loggare solo il campo `allow` di OPA per ridurre il peso degli eventi.
**Correzione utente:** "i log servono per essere analizzati; se metti solo `allow` non si capisce
un cazzo. Devono essere mandati interi, sticazzi se sono pesanti."
**Regola:** i log servono interi per l'analisi (l'`input` è il contenuto utile). Il peso non è una
scusa per ridurre/filtrare il contenuto. Per i problemi di dimensione usare rotazione/segmentazione,
mai troncamento semantico dei dati.

## L2 — Verificare la catena end-to-end con prove runtime prima di dichiarare una causa
**Contesto:** avevo attribuito il problema alla dimensione degli eventi e ipotizzato un problema di
mount, senza verificare.
**Correzione utente:** "prima funzionava (i log venivano letti), quindi non è quello. Hai verificato
il mount dei volumi?"
**Regola:** non fermarsi alla prima ipotesi plausibile. Verificare ogni stadio con evidenze concrete:
file su disco (size/mtime/fd), inode dei mount condivisi, checkpoint/offset della Splunk-uf,
`avg_age` in metrics.log, conteggi `count` vs `dc()` sull'indexer. "Prima funzionava" = cercare cosa
è **cambiato** (qui: stato UF su volume anonimo perso al recreate + file mai ruotato), non una
proprietà statica del sistema.
