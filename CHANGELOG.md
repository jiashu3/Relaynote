# Changelog

## Unreleased

### Added (P3 CLI/onboarding, additive; existing subcommands unchanged)

- The global `--url` default now comes from `RELAYNOTE_URL` when set, else
  `http://127.0.0.1:8787`.
- `relaynote hub init --url URL` records the hub's public/listen URL to
  `hub.url` next to `hub.db` (mode 0600).
- `relaynote connect --url URL` overrides the hub URL used in snippets and
  prompt fragments; resolution order is connect `--url`, an explicit global
  `--url`, `RELAYNOTE_URL`, the URL recorded by `hub init --url`, then the
  built-in default. Nothing changes when none of these are set.
- `connect --platform poll` now records wake adapter `poll` (accepted by the
  wake config as an alias of `none`), and `doctor` reports it as
  `adapter poll: long-poll ...` instead of `none`.
- `relaynote doctor` now works while a live hub holds the database lock: it
  opens bbolt read-only with a short timeout and, when that fails, falls back
  to the hub HTTP status API (`--url` + `--token-file` against
  `/v1/wake/status`) for the token check — ACL edges are not exposed by the
  API, so that check skips. Token/ACL/wake lines name the source used
  (`local database` or `hub API`).

### Added (P3 CLI/onboarding, additive; existing subcommands unchanged)

- `relaynote hub init [--dir DIR]`: creates `DIR/hub.db` (mode 0700
  directory), provisions an `admin` peer (allowed `*`), and prints the admin
  token once — only its SHA-256 hash is stored. Refuses to overwrite an
  existing hub.db. Prints a TLS hint (loopback needs none; remote requires
  `--allow-remote --tls-cert --tls-key`) and the next-step commands.
- `relaynote connect --peer NAME --platform P [--allow a,b]`: creates the peer
  token (written to `<db-dir>/NAME.token`, mode 0600, never overwritten) and
  ACL edges, upserts the peer's wake config entry (default `wake.json` next to
  the database), and prints a paste-ready snippet rendered from embedded
  templates. Platforms: `mcp` (aliases `chatgpt`, `dot`), `webhook` (`cursor`,
  `grokbot`; requires `--webhook-url`, generates an HMAC signature key),
  `exec` (`codex`, `claude-code`; requires `--exec`), `poll` (`generic-poll`,
  `cue`) and `none`. Snippets show the MCP URL + OAuth registration note, the
  webhook URL + signature key, the one-line exec command, or the long-poll
  URL, plus a fixed agent prompt fragment (well under 300 tokens) that uses
  only the four verbs `inbox`/`reply`/`send`/`status`.
- `relaynote doctor --peer X [--allow a,b]`: prints OK/FAIL/SKIP lines and
  exits nonzero on any FAIL. Checks the peer token exists and is enabled
  (read-only bbolt open; while a live hub holds the lock it falls back to the
  hub API when `--token-file` is given, otherwise skips with a note), ACL
  edges (`--allow` entries, or at least one edge), and adapter reachability
  (webhook HEAD with a POST dry-run fallback on 405, bounded by
  `--adapter-timeout`; exec command existence; mcp-event/poll/none are
  config-only OKs). With `--token-file` it also queries a live hub's
  `/v1/wake/status` and prints the last wake decision and outcome;
  unreachable means SKIP, not FAIL.
- Client verbs `relaynote inbox` (alias of `claim`) and `relaynote status`
  (`GET /v1/wake/status`), completing the four-verb set `inbox`/`reply`/
  `send`/`status` as thin wrappers over the existing v1 client.
- New `store.NewReadOnly` and `store.PeerInfo` support doctor's diagnostics;
  the read-write open path is unchanged.
- `docs/quickstart.md`: the five-command zero-to-messaging walkthrough.

### Added (P2 MCP + OAuth, all opt-in and default off)

- New `internal/oauth` package: an OAuth 2.1 authorization server ported
  generically from dot-bridge's `oauth.py`, with the same error codes and
  statuses. PKCE S256 only; public clients via dynamic registration
  (`redirect_uris` restricted to an allow-list) and client-id metadata
  document allow-listing; authorization codes; refresh token rotation with
  whole-family revocation on refresh-token or code replay; login rate
  limiting (5 failures per IP/IPv6-/64/trusted-device in 15 min locks for
  15 min, plus a lenient global throttle that never applies to trusted
  devices). Tokens are opaque random strings (`rna_`/`rnr_`); only SHA-256
  hashes are stored. Passwords use PBKDF2-SHA256 (stdlib) instead of scrypt —
  the auth file format is Relaynote's own. State lives in new bbolt buckets
  of the hub database. Served under `/oauth/*` and `/.well-known/oauth-*`
  with `relaynote serve --oauth-issuer <base URL> --oauth-config <file>`;
  per-endpoint per-IP minute limits answer `429 {"error":"slow_down"}`.
- New `internal/mcp` package: a Streamable HTTP MCP endpoint at `/mcp`
  (`relaynote serve --mcp`, requires the OAuth flags), ported from
  dot-bridge's `server.py`: `initialize`/`server/discover`/`ping`,
  `tools/list`, `tools/call`, `events/*`, scope checks (insufficient scope on
  a tool call renders an `isError` result with an `mcp/www_authenticate`
  hint, otherwise JSON-RPC `-32001`), Origin check, no batching, `Mcp-Method`
  header consistency, 401 `invalid_token` with a `WWW-Authenticate`
  resource-metadata challenge. Generic tools `read_messages`, `send_message`
  and `status` map onto the hub store and ACL as the OAuth-configured peer
  (`store.SendAs`/`GetAs`/`PeekInboxAs`); dot-bridge's approval gating, task
  JSON, hop/rate gates and Cue/OTP logic are deliberately not ported.
- New `internal/events` package: MCP `message.created` subscriptions
  (events.py port) — deterministic idempotent subscription IDs, single-use
  signed verification challenge, Standard Webhooks v1 signatures with a
  24 h dual-secret rotation window, a durable bbolt outbox with bounded
  retry/backoff (30 s…2 h), no retry on 410/413 (410 also deletes the
  subscription), 256 KiB body cap, HTTPS-only callbacks to allow-listed
  hosts with the resolved public IP pinned at connect time, no redirects.
  Wired as the P1 wake `mcp-event` sink: an effective wake notice for an
  mcp-event peer publishes the event and delivers it synchronously; a
  background loop (15 s) drives retries.

With the flags off, HTTP API v1 behavior, routes and responses are
unchanged: the OAuth/MCP routes do not exist.

Acceptance: `internal/golden` replays the OAuth error branches, MCP methods
and login rate limits extracted from dot-bridge's golden transcript
(`golden/out/baseline.json`) against Relaynote and compares status code and
JSON shape field-by-field (volatile tokens/ids/timestamps wildcarded).
Intentional divergences are documented in `internal/golden/testdata/README.md`.

### Added (P1 wake layer, all opt-in and default off)

- New `internal/wake` package: a unified `Adapter` interface
  (`Wake(ctx, Notice) error`) with four adapters — `webhook` (POSTs JSON
  `id`/`kind`/`from`/`conv`, optional `preview` truncated to 200 characters
  and off by default, optional `X-Relaynote-Signature` HMAC-SHA256 header),
  `exec` (runs a local argv command, no shell, with the path to a JSON notice
  file appended), `mcp-event` (pluggable `SinkFunc` hook for P2, no MCP
  server yet), and `none` (enqueue only).
- Per-peer wake gate: `min_interval`, `per_hour` and `per_day` caps, local
  quiet hours (notices deferred and flushed when the window ends, never
  dropped), a circuit breaker (opens after N consecutive failures, half-open
  trial after cooldown), pause/resume, and a hop limit. Every decision
  records requested/effective/reason; delivery retries with bounded doubling
  backoff. Configured via a JSON file passed to
  `relaynote serve --wake-config`; peers absent from the file are never
  woken. When enabled, each newly persisted message triggers an asynchronous
  wake notice for its recipient (idempotent replays do not).
- `GET /v1/wake/status` (only with `--wake-config`) returns the caller's own
  gate snapshot: adapter, breaker state, counters, and the last decision with
  outcome and attempts.
- `GET /v1/inbox/wait?timeout=<s>&after=<cursor>` long-poll (only with
  `--longpoll`) for push-less agents: returns immediately with up to 100
  unacknowledged, unexpired messages after the cursor, otherwise blocks until
  a new message arrives or the timeout elapses (empty result, cursor
  unchanged). Reconnecting with the last cursor never misses messages
  delivered during a disconnect. The peek never leases messages; claim/ack is
  unchanged.

With both flags off, HTTP API v1 behavior and responses are unchanged: the
new routes return 404 like any other unknown route.

### Added (P0 protocol, all opt-in and default off)

- Native optional envelope fields `kind`, `conv`, `hop` on messages
  (`store.SendRequest` / `store.Message`, JSON `omitempty`). The HTTP layer
  accepts them only with `relaynote serve --envelope`; otherwise they are
  rejected as unknown keys, exactly like any other unknown v1 field.
- Legacy dot-bridge JSON-in-body envelope (`v`/`kind`/`conv`/`hop`/`text`) is
  still accepted when the envelope option is enabled: it is parsed and mapped
  onto the native fields wherever the native field is absent. The body itself
  is stored unchanged; a body that is not a legacy envelope stays plain text.
- Request lifecycle tracking for `kind=request` messages, enabled with
  `relaynote serve --lifecycle` (`store.Store.Lifecycle`). States:
  `received → running → final | timed_out`, plus `late` for a result that
  arrives after the deadline. Each request carries a monotonically increasing
  `seq` and a `deadline` (the message expiry). A timed-out request can never
  be re-run: `StartRequest` after the deadline is rejected with 409. New store
  API: `StartRequest`, `CompleteRequest`, `GetRequest`.
- Delivery acknowledgment stays independent from lifecycle outcome: `Ack`
  never changes request state, and lifecycle transitions never touch
  `acked_at`.

HTTP API v1 is unchanged and backward compatible: all new fields are optional
and omitted when absent.
