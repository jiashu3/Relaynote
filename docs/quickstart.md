# Relaynote quickstart

Zero to a working hub with two connected peers in five commands. Everything
here is local; nothing contacts an external service. Stop the hub before
running `connect`, `doctor`'s local checks, or any other local administration
(the database lock is exclusive).

## 1. Initialize the hub

```sh
relaynote hub init --dir hub
```

Creates `hub/hub.db`, prints the **admin token once** (only its hash is
stored — save it), a TLS hint, and the next steps. Loopback serving needs no
certificate; listening beyond loopback requires
`--allow-remote --tls-cert server.crt --tls-key server.key`.

## 2. Connect peers

One command per peer. `--platform` picks the wake adapter; common agent
platforms are aliases (`chatgpt`/`dot` → mcp, `cursor`/`grokbot` → webhook,
`codex`/`claude-code` → exec, `generic-poll`/`cue` → poll).

```sh
relaynote --db hub/hub.db connect --peer cursor --platform webhook --allow admin --webhook-url http://127.0.0.1:9000/wake
relaynote --db hub/hub.db connect --peer cue --platform poll --allow admin
```

Each prints a paste-ready snippet: webhook URL + HMAC signature key, MCP URL +
OAuth registration note, a one-line exec command, or the long-poll URL — plus
a short agent prompt fragment using only the four verbs `inbox`, `reply`,
`send`, `status`. The peer token is also written to `hub/<peer>.token`
(mode 0600).

## 3. Verify

```sh
relaynote --db hub/hub.db doctor --peer cursor
```

`doctor` prints one `OK`/`FAIL`/`SKIP` line per check — token, ACL edges,
adapter reachability (webhook dry-run, exec path) — and exits nonzero on any
failure. With `--token-file hub/cursor.token` and a running hub it also
reports the last recorded wake decision and its outcome.

## 4. Serve and talk

```sh
relaynote --db hub/hub.db serve --listen 127.0.0.1:8787 --wake-config hub/wake.json --longpoll
```

Agents then need only four verbs:

```sh
relaynote --token-file hub/cursor.token inbox                              # check for new messages
relaynote --token-file hub/cursor.token reply --parent ID --body TEXT --client-id KEY
relaynote --token-file hub/cursor.token send --to admin --body TEXT --client-id KEY
relaynote --token-file hub/cursor.token status                             # own wake/delivery status
```

Wake notices carry only a message ID and metadata; bodies are fetched on
demand. Reuse `--client-id` when retrying an uncertain send.
