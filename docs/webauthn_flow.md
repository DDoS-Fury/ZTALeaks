# Flusso di Registrazione e Autenticazione WebAuthn

Il presente documento descrive in maniera dettagliata e professionale l'implementazione del flusso WebAuthn (FIDO2), con un focus particolare sulle interazioni tra Client e Server, sulle informazioni salvate nel database (DB) e sui meccanismi di verifica per la sicurezza dell'identità (inclusa la gestione TPM e i controlli anti-clonazione).

---

## 1. Processo di Registrazione (Enrollment del Dispositivo)

L'enrollment avviene in due fasi: inizializzazione (`begin`) e finalizzazione (`finish`). In questa fase, l'utente dimostra di essere legittimamente autenticato (es. tramite un token preesistente) e associa un nuovo dispositivo (authenticator) al proprio account.

### 1.1 Inizializzazione della Registrazione (`/register/begin`)

**Trigger:** L'utente, già autenticato (il cui identificativo arriva tramite l'header sicuro `X-Current-User` passato da un orchestratore a monte), richiede di registrare un dispositivo (es. un modulo TPM o una security key).

- **Payload inviato al Server:**
  Un payload JSON contenente, ad esempio, un `access_token` e un `device_name` (es. "TPM-Device").
- **Elaborazione Server:**
  1. Il sistema verifica l'esistenza dell'utente nel database tramite l'`user_id`.
  2. Genera un identificativo di sessione univoco (`session_id`) opaco da 128 bit.
  3. Genera una `challenge` crittografica randomica sicura da 256 bit.
- **Memorizzazione su DB:**
  Viene creata un'entità temporanea nella tabella `webauthn_challenges` contenente:
  - `SessionID`: per tracciare la sessione.
  - `Challenge`: la stringa causale che l'authenticator dovrà firmare.
  - `UserID`: il collegamento forte all'utente.
  - `CeremonyType`: impostato esplicitamente su `"registration"` (per evitare attacchi di replay o mix-up tra login e registrazione).
  *Questa challenge ha tipicamente un Time-To-Live (TTL) limitato, es. 5 minuti.*
- **Risposta (Server -> Client):**
  Il server restituisce un oggetto `publicKeyCredentialCreationOptions` contenente:
  - Le informazioni del Relying Party (RP) e dell'utente.
  - I parametri crittografici accettati (es. algoritmi `ES256`, `RS256`).
  - La `challenge` e il `session_id`.

### 1.2 Conclusione della Registrazione (`/register/finish`)

**Trigger:** L'authenticator locale dell'utente firma la challenge generata dal server e l'applicazione invia i dati crittografici per la validazione.

- **Payload inviato al Server:**
  L'applicazione client invia un payload contenente: `session_id`, `credential_id`, `public_key` (esportata in base64), `attestation_type`, e l'`aaguid` (identificativo del modello dell'authenticator).
- **Verifica e Validazione:**
  1. Il server interroga il DB cercando la challenge associata al `session_id` e verifica che sia in corso una cerimonia di `"registration"`.
  2. *(Nota Implementativa Lab vs Production)*: In un ambiente enterprise di produzione, in questo step si verifica rigorosamente:
     - L'hash del `clientDataJSON` rispetto alla challenge attesa.
     - La validità della firma crittografica sull'`authenticatorData`.
     - La decodifica e validazione dell'oggetto di attestazione (Attestation Object).
- **Memorizzazione su DB:**
  Se valido, i dati vengono consolidati:
  1. **Dispositivi (`device_fingerprints`):** Viene salvata la nuova credenziale associandola all'utente (CredentialID, UserID, PublicKey, AAGUID, AttestationType, DeviceName). Viene inoltre inizializzato il contatore delle firme (`sign_count = 0`).
  2. **Utenti (`users`):** Il profilo dell'utente viene aggiornato marcandolo con l'enrollment completato (`has_tpm = true`) e la chiave pubblica viene talvolta inserita anche sul profilo utente.
  3. **Pulizia:** La challenge temporanea viene definitivamente rimossa dalla tabella `webauthn_challenges`.

---

## 2. Processo di Autenticazione (Login)

Come la registrazione, anche l'autenticazione è un processo asincrono a due fasi (challenge-response) che assicura che il client possieda la chiave privata associata al dispositivo enrollato senza mai trasmetterla in rete.

### 2.1 Inizializzazione del Login (`/login/begin`)

**Trigger:** L'utente inserisce il proprio `username` (passwordless) o intende fare un upgrade della sessione.

- **Payload inviato al Server:**
  Username dell'utente.
- **Elaborazione Server:**
  1. Ricerca l'utente nel DB tramite lo `username`.
  2. Recupera tutti i dispositivi registrati (`device_fingerprints`) associati a quell'utente. Se non vi sono dispositivi, la cerimonia viene interrotta.
  3. Genera un nuovo `session_id` e una nuova `challenge` crittografica.
- **Memorizzazione su DB:**
  Salva nella tabella `webauthn_challenges`:
  - `SessionID` e `Challenge`.
  - `UserID`.
  - `CeremonyType`: impostato su `"authentication"`.
- **Risposta (Server -> Client):**
  Il server restituisce un oggetto `publicKeyCredentialRequestOptions` che contiene la `challenge` e una lista `allowCredentials` contenente gli ID di tutti i dispositivi (`CredentialID`) autorizzati a completare l'accesso, oltre al `session_id`.

### 2.2 Conclusione del Login (`/login/finish`) e Multi-Factor (OTP)

**Trigger:** L'authenticator dell'utente riceve l'ok per procedere (spesso dopo una verifica biometrica o PIN locale) e firma la challenge, restituendo i dati al server.

- **Payload inviato al Server:**
  Payload contenente il `session_id`, il `credential_id` utilizzato dal client e il `sign_count` (contatore interno all'authenticator).
- **Verifica e Validazione:**
  1. **Match Sessione:** Si recupera la challenge dal DB tramite `session_id` assicurandosi che sia per `"authentication"`.
  2. **Match Credenziali:** Si cerca il dispositivo nel DB usando il `credential_id` fornito, assicurandosi che appartenga effettivamente all'utente tracciato nella challenge.
  3. **Clone Detection (Anti-Clonazione):** L'authenticator mantiene internamente un contatore delle firme effettuate (`sign_count`) che deve essere strettamente crescente. Il server verifica che il `sign_count` inviato dal client sia strettamente maggiore del `sign_count` salvato a DB. Se è minore o uguale (e il contatore DB è > 0), il server rileva un sospetto di clonazione della chiave hardware.
  4. *(Nota Implementativa Production)*: Analogamente alla registrazione, in produzione viene validata crittograficamente la firma ricevuta tramite la `PublicKey` memorizzata a DB durante l'enrollment.
- **Memorizzazione su DB (Aggiornamento Stato):**
  1. Il campo `sign_count` del dispositivo viene aggiornato nel DB con il nuovo valore ricevuto.
  2. La challenge viene cancellata.
- **Workflow Multifactore (OTP Fallback/Injection):**
  Nel design architetturale del sistema in esame, il superamento della sfida FIDO2 innesca automaticamente un secondo fattore di sicurezza (MFA):
  1. Il sistema genera un codice OTP criptograficamente sicuro.
  2. Esegue un hashing dell'OTP legandolo al contesto di sessione (es. assieme al `session_id`).
  3. **Memorizzazione OTP:** Salva il record in `otp_sessions` (`SessionToken` derivato dal session_id, `UserID`, `OTPHash`, e resetta gli `Attempts = 0`).
  4. **Invio Notifica:** Invia l'OTP via email all'utente.
- **Risposta Finale (Server -> Client):**
  Ritorna lo stato dell'operazione. Piuttosto che un JWT finale, il sistema segnala `"status": "otp_required"`, informando il frontend di procedere con lo step di verifica OTP per ottenere l'accesso completo, segnalando inoltre la validità della firma hardware ed eventuali flag di sospetta clonazione.

---

## Sintesi della Sicurezza dei Dati Delle Entità DB

1. **`webauthn_challenges`**: Essenziale per mantenere stato e mitigare i replay attack. Isolando `ceremony_type`, impedisce che una challenge emessa per un login possa essere ingannata e utilizzata per una registrazione.
2. **`device_fingerprints`**: Memorizza solo la `PublicKey` (mai la chiave privata). Contiene il `CredentialID` per l'identificazione e traccia il `SignCount` per rilevare furti e clonazioni delle chiavette fisiche.
3. **`otp_sessions`**: Conserva solo l'`OTPHash`, rendendo vano un eventuale dump del DB durante un tentativo di login in corso. Utilizza il concetto di "tentativi massimi" (`Attempts`) per prevenire attacchi di bruteforcing sull'OTP inviato via mail.

---

## 4. Esempi Pratici di Interazione (Client / Server)

### Esempio: Registrazione Begin (`/api/v1/auth/register/begin`)

**Client invia:**
L'utente è già loggato e la richiesta è autenticata a monte (il server legge ad esempio `X-Current-User`).
```json
{
  "access_token": "eyJhbGciOiJIUz...",
  "device_name": "Il mio nuovo TPM"
}
```

**Server esegue:**
- Identifica l'utente dal contesto o dall'header.
- Genera una challenge (`cmFuZG9tX2NoYWxsZW5nZV9yZWdpc3RyYXRpb24`) e un `session_id` (`9876zyxw-1234`).
- Salva la challenge in `webauthn_challenges` col flag `"registration"`.

**Server risponde:**
```json
{
  "session_id": "9876zyxw-1234",
  "publicKey": {
    "challenge": "cmFuZG9tX2NoYWxsZW5nZV9yZWdpc3RyYXRpb24",
    "rp": {
      "id": "ztaleaks.local",
      "name": "ZTALeaks Nuclear Plant"
    },
    "user": {
      "id": "user_id_123",
      "name": "operatore_centrale",
      "displayName": "operatore_centrale"
    },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "attestation": "direct"
  }
}
```

### Esempio: Registrazione Finish (`/api/v1/auth/register/finish`)

L'authenticator genera la coppia di chiavi e firma la challenge, restituendo i dati.

**Client invia:**
```json
{
  "session_id": "9876zyxw-1234",
  "credential_id": "cred_id_9876xyz",
  "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
  "attestation_type": "platform",
  "aaguid": "00000000-0000-0000-0000-000000000000"
}
```

**Server esegue:**
- Trova la challenge tramite `session_id`.
- Analizza la `public_key` e controlla l'attestazione.
- Salva il nuovo hardware in `device_fingerprints` (impostando `sign_count = 0`).
- Marca il record dell'utente (`has_tpm = true`).
- Distrugge la challenge temporanea.

**Server risponde:**
```json
{
  "status": "registered",
  "credential_id": "cred_id_9876xyz"
}
```

### Esempio: Login Begin (`/api/v1/auth/login/begin`)

**Client invia:**
```json
{
  "username": "operatore_centrale"
}
```

**Server esegue:**
- Cerca l'utente "operatore_centrale" nel database.
- Recupera l'elenco dei dispositivi fisici enrollati per questo utente.
- Genera una challenge sicura (`c29tZV9yYW5kb21fY2hhbGxlbmdlX2hlcmU`) e un `session_id` (`1234abcd-5678`).
- Memorizza la challenge in `webauthn_challenges`.

**Server risponde:**
```json
{
  "session_id": "1234abcd-5678",
  "publicKey": {
    "challenge": "c29tZV9yYW5kb21fY2hhbGxlbmdlX2hlcmU",
    "rpId": "ztaleaks.local",
    "timeout": 60000,
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "cred_id_9876xyz"
      }
    ],
    "userVerification": "preferred"
  }
}
```

### Esempio: Login Finish (`/api/v1/auth/login/finish`)

L'authenticator locale riceve le istruzioni, richiede l'eventuale biometria dell'utente e firma la challenge.

**Client invia:**
```json
{
  "session_id": "1234abcd-5678",
  "credential_id": "cred_id_9876xyz",
  "sign_count": 42
}
```

**Server esegue:**
- Recupera la challenge tramite `session_id`.
- Recupera il dispositivo `cred_id_9876xyz` da `device_fingerprints`.
- Verifica che gli utenti combacino.
- Verifica il `sign_count` (es. si accerta che `42` sia strettamente maggiore dell'ultimo valore registrato, es. `41`) per escludere clonazioni dell'hardware.
- Aggiorna il `sign_count` a DB e cancella la challenge consumata.
- Genera un codice OTP di fallback/MFA, ne fa l'hash e lo salva in `otp_sessions`.
- Invia l'OTP in chiaro tramite e-mail.

**Server risponde:**
```json
{
  "status": "otp_required",
  "session_token": "1234abcd-5678",
  "message": "Firma Hardware corretta. OTP inviato via email.",
  "credential_id": "cred_id_9876xyz",
  "clone_suspected": false
}
```
