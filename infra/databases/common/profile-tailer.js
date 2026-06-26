// =============================================================================
// Profiler tailer — MongoDB system.profile -> JSONL access log
// Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
// =============================================================================
// Esegue un tail del profiler (`<TARGET_DB>.system.profile`, alimentato da
// operationProfiling.mode=all) e per ogni operazione di dati ricevuta dal DB
// emette su stdout una riga JSON con lo schema richiesto:
//   { timestamp, service, utente_connesso, tipo_operazione, collezione }
//
// L'entrypoint del container redirige questo stdout su db_access.jsonl, che la
// Splunk Universal Forwarder gia' monitora come sourcetype _json.
//
// MongoDB profila le operazioni con `op` ∈ {query, insert, update, remove,
// getmore, command}. Le scritture moderne (update/delete) e molte read passano
// per `op:"command"`, col verbo reale dentro `command` (es. command.delete =
// "<collezione>"): per questo si ispeziona il comando, non solo `op`.
//
// Identita':
//   - `service`         = prefisso del command.comment "<service>|<impiegato>",
//                         altrimenti l'appName della connessione, altrimenti "-".
//   - `utente_connesso` = suffisso del comment (impiegato finale dal JWT),
//                         altrimenti "-" (op senza identita' applicativa).
//
// Variabili d'ambiente lette (passate dal container):
//   TARGET_DB        nome del database da osservare (es. nuclear_plant_db)
//   POLL_INTERVAL_MS intervallo di polling (default 1000)
// =============================================================================

const TARGET_DB = (typeof process !== "undefined" && process.env.TARGET_DB) || "test";
const POLL_MS = parseInt((typeof process !== "undefined" && process.env.POLL_INTERVAL_MS) || "1000", 10);

const target = db.getSiblingDB(TARGET_DB);

// Verbi di comando che rappresentano operazioni sui dati (da loggare). Tutto il
// resto su op:"command" (createIndexes, create, drop, ping, hello, ...) e' DDL
// o amministrativo e viene scartato.
const DATA_VERBS = {
    find: "find",
    insert: "insert",
    update: "update",
    delete: "delete",
    findAndModify: "findAndModify",
    findandmodify: "findAndModify",
    aggregate: "aggregate",
    count: "count",
    distinct: "distinct"
};

// Estrae il nome della collezione da un namespace "db.collection".
function collectionOf(ns) {
    if (!ns) return "-";
    const i = ns.indexOf(".");
    return i >= 0 ? ns.substring(i + 1) : ns;
}

// Determina { op, coll } per una entry, oppure null se va scartata (getmore,
// comandi non-dati, collezioni di sistema, db interni).
function describe(entry) {
    const ns = entry.ns || "";
    const cmd = entry.command || {};
    let op = entry.op;
    let coll = collectionOf(ns);

    if (/^(admin|config|local)\./.test(ns)) return null;

    switch (op) {
        case "query": op = "find"; break;
        case "insert": op = "insert"; break;
        case "update": op = "update"; break;
        case "remove": op = "delete"; break;
        case "getmore": return null;
        case "command": {
            let verb = null;
            for (const k in cmd) {
                if (Object.prototype.hasOwnProperty.call(DATA_VERBS, k)) { verb = k; break; }
            }
            if (!verb) return null; // comando non sui dati (DDL/admin)
            op = DATA_VERBS[verb];
            // Per i comandi il namespace e' spesso "db.$cmd": la collezione reale
            // e' il valore del verbo (es. command.delete = "personnel").
            if (typeof cmd[verb] === "string" && cmd[verb] !== "") coll = cmd[verb];
            break;
        }
        default: return null;
    }

    // Scarta le collezioni di sistema (incluse le letture del profiler stesso).
    if (coll.indexOf("system.") === 0 || ns.indexOf(".system.") >= 0) return null;

    return { op: op, coll: coll };
}

// Ricava (service, utente_connesso) da comment + appName.
function identity(entry) {
    let service = entry.appName || "-";
    let user = "-";
    const c = entry.command && entry.command.comment;
    if (typeof c === "string" && c.indexOf("|") >= 0) {
        const parts = c.split("|");
        if (parts[0]) service = parts[0];
        if (parts[1]) user = parts[1];
    }
    return { service: service, user: user };
}

// Punto di ripartenza: solo gli eventi da adesso in poi (la capped collection
// puo' contenere storico gia' inoltrato in run precedenti).
let last = new Date();

while (true) {
    try {
        const cur = target.system.profile
            .find({ ts: { $gt: last } })
            .sort({ ts: 1 });

        while (cur.hasNext()) {
            const e = cur.next();
            if (e.ts && e.ts > last) last = e.ts;

            const d = describe(e);
            if (!d) continue;

            const id = identity(e);
            print(JSON.stringify({
                timestamp: e.ts ? e.ts.toISOString() : new Date().toISOString(),
                service: id.service,
                utente_connesso: id.user,
                tipo_operazione: d.op,
                collezione: d.coll
            }));
        }
    } catch (err) {
        // Non interrompere il tail per un errore transitorio (es. reconnessione).
        print(JSON.stringify({
            timestamp: new Date().toISOString(),
            service: "db-profiler-tailer",
            utente_connesso: "-",
            tipo_operazione: "error",
            collezione: String(err)
        }));
    }
    sleep(POLL_MS);
}
