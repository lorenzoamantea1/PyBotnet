# pyBotnet — Agent Guide

## Project structure

Three standalone Python components in a hub-and-spoke topology:

```
controller/  →  node/  →  client/     (TCP, RSA auth, AES-GCM cmds)
```

| Component | Entrypoint | Role |
|-----------|-----------|------|
| `controller/main.py` | Interactive shell, connects to node(s) | Sends flood/control commands |
| `node/main.py` | TCP server, authenticates controller, relays to clients | Bridge |
| `client/main.py` | TCP client, connects to node, executes flood attacks | Worker |

Each component has a `core/` subdir with its own copy of crypto, logger, and error modules — **don't assume shared code**.

## Setup

```bash
pip install -r requirements.txt   # cryptography, colorama, scapy, aiohttp, h2
mkdir -p node/data/keys
cp controller/data/keys/pub.key node/data/keys/pub.key   # mandatory for auth
```

## Running

```bash
python node/main.py         # binds 0.0.0.0:547
python controller/main.py   # connects to nodes from controller/data/nodes.json
python client/main.py       # connects to 127.0.0.1:547
```

All components must be run from their own directory (working dir = component root).

## Protocol quirks

- Every message has a 2-byte big-endian length prefix
- Key exchange: PEM RSA-2048 pubkeys, then auth JSON with `role` + RSA-PSS signature
- Commands to clients: AES-256-GCM session key wrapped with RSA-OAEP
- Node auto-accepts both `controller` and `client` roles in the same TCP listener (port 547)
- Default port = 547

## Controller shell

- Permission levels by OS username: `root` = level 3, others = level 1
- Tab-completion via readline; history saved to `~/.shell_history`
- `flood <url> [duration(30)] [method(GET)] [threads(100)]` requires level 3
- Methods: L7 (GET/POST/PUT/DELETE/HEAD/SLOWLORIS/H2RESET/WS), L4 (ACK/SYN/FIN/RST/TCP/UDP/DNSAMP)
- Controller prompts for confirmation before sending flood commands
- `flood` commands require confirmation prompt (`y/N`)

## String obfuscation

Throughout the codebase, string literals are base64-encoded and decoded at runtime via `_decode_str()` from `client/core/utilities.py`. If you see `_decode_str("MTI3LjAuMC4x")`, that's `"127.0.0.1"`.

## Key files & auth flow

- Controller generates `controller/data/keys/{pub,priv}.key` on first run (auto-creates dir)
- Node loads `node/data/keys/pub.key` at startup — **file must exist** or node crashes
- Node sends its ephemeral RSA pubkey to every new TCP connection
- Node verifies controller's signature against the stored pubkey
- Client sends its ephemeral RSA pubkey, gets back AES-encrypted commands

## Node config

`node/data/config.json` — bind host/port, max_clients (25), overflow_sleep_s (3600), debug bool.

## Client behavior

- Reconnects with backoff on connection loss; max 5 redirects
- Can receive `wait` (sleep + retry) or `redirect` (reconnect to different node) commands
- Flood execution: L7 uses `aiohttp`, L4 uses raw `asyncio` sockets, H2 uses `h2` lib, DNS uses `scapy`, WS uses `aiohttp`
- Spoofed IP in L4 flood uses `scapy` (may need root)
- Private/reserved IP whitelisting is **commented out** in `parse_url()` — no protection

## Data files

| File | Purpose |
|------|---------|
| `controller/data/nodes.json` | Target node list as `[[host, port], ...]` |
| `node/data/config.json` | Runtime config |
| `node/data/nodes.network` | Synced node list (auto-populated) |
| `controller/data/banners.json` | Random startup banners for shell |

## Conventions

- No tests, no CI, no formatter/linter config, no type checker
- `.gitignore` excludes `__pycache__/`, `*.pyc`, `*.key`, `*/builder.py`, `*/onefile.py`
- No shared library between components — each has its own `core/` with duplicate code
- No `__init__.py` except `client/core/__init__.py`
- `sys.excepthook` overridden by both `controller` and `node` with custom handlers
- Controller `shell.py` was refactored into `commands.py` (command logic), `payloads.py` (JSON builders), and `shell.py` (Shell class only)
- Client now has `core/logger.py` (same format as node/controller counterparts)
- License: GPL v3
