# Golden replay fixtures (P2)

`scenario.json` is a hand-extracted, sanitized subset of the dot-bridge golden
transcript `team/gateway-src/golden/out/baseline.json` (produced by
`team/gateway-src/golden/scenario.py`). Each step carries its original
transcript index in `golden` for traceability back to that file. The subset
covers the behaviors P2 ports: OAuth metadata and error branches, dynamic
client registration, PKCE failures, refresh rotation with family revocation
on replay, the MCP protocol methods and tool argument errors, the 401
challenges, login rate limiting (per-IP lockout) and the authorize Origin
check.

`../replay_test.go` drives the same request sequence against Relaynote's
`internal/oauth` + `internal/mcp` on an `httptest` server and compares status
code, headers and JSON body field-by-field, like `compare.py` does.

Placeholders in the fixture:

- `{BASE}` — substituted with the test issuer URL before comparison.
- `{CID}`, `{TOKEN}`, `{CODE}`, `{ANY}` — whole-value wildcards for volatile
  fields (client IDs, tokens, authorization codes, timestamps); the actual
  value must be non-empty and of the same JSON type.
- `html_err` — for HTML responses, the message extracted from
  `<p class="err">…</p>` (login form) or `<h2>…</h2><p>…</p>` (message page);
  page chrome is not compared.
- `mode: "shape"` — recursive key-set/type comparison (scalar values ignored
  except keys listed in `exact_keys`).
- `mode: "tools"` — checks only that the listed tools exist with the same
  OAuth scopes.
- `ignore_keys` — keys dropped from comparison at any depth.

## Intentional divergences from the golden baseline

- `resource_name`, `serverInfo`, `instructions`, tool titles/descriptions and
  the login page chrome are Relaynote-generic, not dot-bridge branded
  (compared by shape or wildcard).
- `tools/list` adds a `status` tool and drops `include_sent` from
  `read_messages` (the hub store has no sender index; P0/P1 added none).
  `unreplied_only` maps onto the hub's acknowledgement state.
- Tool error `message` texts that embed dot-specific facts are wildcarded
  (`ignore_keys`): `recipient_not_allowed` (the golden text lists dot's
  allow-list; Relaynote reports the hub ACL message) and `unknown_message`
  for `reply_to` (golden says "this dot"). Error codes match exactly.
- Password hashing in the auth file is PBKDF2-SHA256 (Go stdlib) instead of
  scrypt, to avoid a new module dependency; the file format is Relaynote's
  own. Token prefixes are `rna_`/`rnr_` instead of `dba_`/`dbr_`; the trusted
  device cookie is `rndev` instead of `dbdev` (attributes identical).
- dot-bridge's send-side gates (min_interval / per_hour / per_day rate limits,
  hop exhaustion, circuit breaker, task-JSON validation, `hub_unavailable`
  retry) and its wake/inbound pipeline are dot-specific bridge logic, not part
  of the hub's MCP layer — Relaynote enforces the hub ACL and message expiry
  instead. The corresponding golden entries (34's peers, 38–58, 70–83's read
  results, 100–138) are therefore not replayed here; Relaynote-native send,
  read, reply, idempotency and scope behavior is covered by unit tests in
  `internal/mcp` and `internal/oauth`.
- The golden entries `GET /healthz` and `GET /nope` are not replayed: the hub
  has no `/healthz`, and unknown paths on Relaynote fall through to the v1
  handler (401 without a Bearer token), whereas dot-bridge's front returns
  404 `not_found` unauthenticated.
- Login rate limiting keeps oauth.py's exact semantics (5 failures / 15 min /
  per IP-or-device, lenient global throttle) and Chinese user-facing messages
  verbatim, so the lockout entries compare exactly.
- The events flow (subscribe challenge, signed delivery, retry/backoff) has no
  golden coverage upstream; it is tested in `internal/events` and
  `cmd/relaynote` (sink wiring) instead.
