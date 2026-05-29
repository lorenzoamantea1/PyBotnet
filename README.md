# pyBotnet

## Panoramica

`pyBotnet` è un progetto Python organizzato in tre componenti indipendenti con architettura hub-and-spoke:

- **`controller/`** — shell interattiva che si connette a uno o più nodi, invia comandi di flood/controllo.
- **`node/`** — server TCP che autentica il controller, gestisce i client e inoltra i comandi crittografati.
- **`client/`** — si collega al nodo, riceve comandi AES-GCM ed esegue attacchi flood, exec, download, upload.

> Questo repository è destinato all'analisi del codice. L'esecuzione in ambienti non autorizzati può violare leggi o policy.

## Architettura

```
                    TCP con RSA auth + AES-GCM
  Controller ──────────────────────────────► Node ──────────────────────────────► Client
       ▲                                         │                                    │
       │                                         ▼                                    │
       └────── JSON response (se expect_response) ──────┘◄────── ACK / risultato ─────┘
```

## Struttura del progetto

```
pyBotnet/
├── client/
│   ├── main.py              # Avvio client, connessione al nodo
│   └── core/
│       ├── connect.py        # Ciclo di connessione, autenticazione, ricezione comandi
│       ├── constants.py      # BUFFER_SIZE_LENGTH = 2
│       ├── crypto.py         # Crittografia lato client (RSA-OAEP, AES-256-GCM)
│       ├── layers.py         # Tutti i metodi flood: L7Async, L4Raw, H2Reset, WSFlood, DNSFlood, MCPing/MCHandshake/MCLogin
│       ├── logger.py         # Logger colorato
│       └── utilities.py      # _decode_str(), parse_url(), NetworkUtilities
├── controller/
│   ├── main.py               # Carica nodi da nodes.json e avvia shell interattiva
│   └── core/
│       ├── commands.py       # Logica comandi shell: Commands + Functions
│       ├── connect.py        # Connessione ai nodi, autenticazione RSA-PSS, invio messaggi
│       ├── constants.py      # BUFFER_SIZE_LENGTH = 2
│       ├── crypto.py         # Gestione chiavi RSA, firma PSS, wrapping OAEP
│       ├── errors.py         # Eccezioni custom
│       ├── logger.py         # Logger uniforme con colorama
│       ├── payloads.py       # Costruttori JSON per ogni tipo di comando
│       └── shell.py          # Classe Shell interattiva (readline, cronologia, autocomplete)
├── node/
│   ├── main.py               # Carica config.json e avvia il server TCP
│   └── core/
│       ├── crypto.py         # Crittografia lato nodo
│       ├── errors.py         # Eccezioni custom
│       ├── logger.py         # Logger del nodo
│       └── server.py         # Server asincrono: autenticazione, forwarding, gestione client
├── requirements.txt          # cryptography, colorama, scapy, aiohttp, h2
├── AGENTS.md                 # Guida per agenti AI
└── LICENSE                   # GNU GPL v3
```

## Setup

```bash
pip install -r requirements.txt
mkdir -p node/data/keys
cp controller/data/keys/pub.key node/data/keys/pub.key   # obbligatorio per l'auth
```

Dipendenze: `cryptography`, `colorama`, `scapy`, `aiohttp`, `h2`.

## Chiavi e autenticazione

### Controller

Genera automaticamente le chiavi RSA-2048 in `controller/data/keys/` al primo avvio:

- `pub.key` — chiave pubblica (da copiare sul nodo)
- `priv.key` — chiave privata (firma dei messaggi di auth con RSA-PSS)

### Nodo

Richiede la chiave pubblica del controller in `node/data/keys/pub.key`. Il nodo invia la propria chiave effimera a ogni nuova connessione TCP e verifica la firma del controller tramite RSA-PSS.

### Client

Invia la propria chiave effimera al nodo; riceve indietro la chiave di sessione AES-256-GCM cifrata con RSA-OAEP.

## Esecuzione

Tutti i comandi vanno eseguiti dalla directory del componente (working directory = radice del componente):

```bash
python node/main.py              # Binds 0.0.0.0:547
python controller/main.py        # Si connette ai nodi da data/nodes.json
python client/main.py            # Si connette a 127.0.0.1:547
```

## Configurazione

### Controller — `controller/data/nodes.json`

```json
[
  ["127.0.0.1", 547]
]
```

### Nodo — `node/data/config.json`

```json
{
  "address": { "host": "0.0.0.0", "port": 547 },
  "clients": { "max_clients": 25, "client_overflow_sleep_s": 3600 },
  "debug": false
}
```

## Comandi del controller (shell)

La shell ha livelli di permesso: `root` = livello 3, altri utenti = livello 1.

| Comando | Descrizione | Livello |
|---|---|---|
| `help [command]` | Mostra aiuto | 1 |
| `quit` / `exit` | Esce dalla shell | 1 |
| `methods` | Elenca i metodi flood supportati | 1 |
| `ping` | Ping a tutti i nodi connessi | 2 |
| `nodes list` | Elenca nodi connessi | 2 |
| `nodes status` | Stato connessione nodi | 2 |
| `nodes sync` | Sincronizza lista nodi | 2 |
| `nodes disconnect <node_id>` | Disconnette un nodo | 2 |
| `clients list` | Elenca client per nodo | 2 |
| `clients count` | Conteggio totale client | 2 |
| `clients find <id\|ip>` | Cerca client per ID/IP | 2 |
| `clients show <client_id>` | Dettagli client | 2 |
| `clients disconnect <node_id> <client_id>` | Disconnette client | 2 |
| `flood <url> [duration(30)] [method(GET)] [threads(100)]` | Lancia attacco flood (conferma y/N richiesta) | 3 |
| `exec <node_id> <client_id> <command>` | Esegui comando shell su client remoto | 3 |
| `download <node_id> <client_id> <path>` | Scarica file dal client (base64 → salvato localmente) | 3 |
| `upload <node_id> <client_id> <local_file> <remote_path>` | Carica file sul client | 3 |
| `payload <list\|send\|add\|remove> [...]` | Gestione payload binari | 3 |
| `! <command>` | Esegue comando shell locale | 3 |

Il comando `flood` chiede conferma prima di procedere (`y/N`).

## Metodi flood supportati

- **L7**: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `SLOWLORIS`, `H2RESET`, `WS`
- **L4**: `ACK`, `SYN`, `FIN`, `RST`, `TCP`, `UDP`, `DNSAMP`
- **MC**: `MCHANDSHAKE`, `MCLOGIN`, `MCPING`

I metodi MC targettano server Minecraft (porta predefinita 25565).
- `MCHANDSHAKE`: connessioni handshake rapide
- `MCLOGIN`: login completo con keepalive
- `MCPING`: richieste status + ping

## Protocollo di comunicazione

- Ogni messaggio ha un prefisso di 2 byte big-endian con la lunghezza (`BUFFER_SIZE_LENGTH` in `*/core/constants.py`).
- Scambio chiavi: chiavi pubbliche RSA-2048 in formato PEM.
- Autenticazione: JSON con `role` + firma RSA-PSS.
- Comandi verso i client: chiave di sessione AES-256-GCM cifrata con RSA-OAEP.
- Risposte dai client (exec/download/upload/shell): stesso schema AES-GCM invertito (client → nodo).
- `send_to()` accetta flag `expect_response`; le azioni che generano risposta sono: `exec`, `download`, `upload`, `shell`.
- I comandi possono targettare un client specifico (`"target": "<uuid>"`) o essere broadcast.
- Il nodo accetta sia ruoli `controller` che `client` sulla stessa porta TCP (547).

## String obfuscation

Nel client, le stringhe letterali sono codificate in base64 e decodificate a runtime tramite `_decode_str()` in `client/core/utilities.py`. Esempio: `_decode_str("MTI3LjAuMC4x")` corrisponde a `"127.0.0.1"`.

## Comportamento client

- Si riconnette con backoff esponenziale in caso di perdita di connessione.
- Massimo 5 reindirizzamenti.
- Comandi gestiti: `flood` (esegue attacco), `wait` (sleep + riprova), `redirect` (riconnessione a nodo diverso), `exec`/`download`/`upload`/`payload`.
- IP spoofato nei flood L4 via scapy (può richiedere root).
- Il whitelist di IP privati/riservati in `parse_url()` è **commentato** — nessuna protezione.

## Dati su disco

| File | Scopo |
|---|---|
| `controller/data/nodes.json` | Lista nodi target `[[host, port], ...]` |
| `controller/data/banners.json` | Banner casuali per la shell |
| `controller/data/keys/` | Chiavi RSA del controller (auto-generate) |
| `node/data/config.json` | Config runtime del nodo |
| `node/data/keys/pub.key` | Chiave pubblica del controller (copia manuale) |
| `node/data/nodes.network` | Lista nodi sincronizzata (auto-populata) |

## Licenza

GNU General Public License v3. Vedi `LICENSE`.
