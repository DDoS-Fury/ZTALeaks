# Progetto Zero-Trust Architecture
Note e appunti delle esercitazioni sul progetto di Advanced Cybersecurity for IT, che ha come tema principale una ZTA distribuita su 6 container (in questa specifica declinazione del progetto).

## Documentazione
Sia su learn che qui ["dispense"](docs/project_theme.pdf) sono disponibili le dispense sul progetto con diagrammi delle sequenze e UML con i componenti da utilizzare.

## Esercitazione del 27/03/2026
- **Firewall di Rete**: interposto tra il client ed il sistema principale, cioè l'unido punto di accesso alla rete. I log del firewall saranno raccolti e inviati a SPLUNK. Si può usare NFTables.

- **Envoy**: sarà utilizzato sia come PEP che come firewall di livello applicazione.

- **snoRT**: sistema software per l'analisi dei pacchetti di rete, è un network intrusion detection and prevention system. Si dovranno posizionare correttamente le "sonde" di snoRT, che consentono di analizzare i pacchetti catturati.

- **test**: per testare il corretto funzionamento dell'architettura si dovranno generare scenari di attacco e utilizzo "legale" del sistema. Si dovrà generare anche una storia che permetta di valutare se una nuova richiesta è troppo rischiosa (e.g. in base alle azioni passate dell'utente). 

- **Attacchi da testare**: la tipologia di attacco più semplice che snoRT è in grado di rilevare è la scansione delle porte (che dovrà essere permessa lato firewall).

