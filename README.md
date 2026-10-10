# 捎信 · Relaynote

捎信（Relaynote）由涟漪工场有限公司（Ripplelab Limited）开发。

Relaynote (捎信) is developed by **Ripplelab Limited**. [Official website](https://www.ripplelab.hk/)

A small durable messaging hub and CLI for cloud servers, Linux, macOS and Windows. Send addressed messages, receive replies, survive process restarts, and distinguish delivery acknowledgement from Agent execution.

**Preview software.** Runtime verification currently targets isolated Linux processes. Consult [verification status](docs/TEST_REPORT.md) before relying on a platform claim. Android is deferred. There is no remote shell, automatic command execution, GUI, service installer, real Agent integration or guaranteed Agent wake-up.

## Architecture

Routing is any-to-any among authorized nodes, not a fixed pair of workflows. Each sender must still have permission to address the destination. A four-node test exercises every directed pair and return results, plus an explicitly denied direction.

One hub holds transactional message queues; clients connect outbound over HTTPS. Tailscale is optional network transport, not a required runtime dependency. Explicit HTTP(S) proxy support accommodates restricted cloud environments. Plain HTTP is permitted only for literal loopback IPs.

The JSON v1 protocol preserves the earlier Python prototype's message semantics. Go uses **bbolt**, a pure-Go transactional database, with its normal synced commits and exclusive file lock. This is a new database format: do not point it at a legacy SQLite database. The original Python implementation remains a separate reference, not a bundled interpreter dependency.

## Quick local demo

Use the executable for your platform (Windows: `relaynote.exe`). From a private working directory:

```sh
relaynote --db state/hub.db provision --peer A --allow B --out state/A.token
relaynote --db state/hub.db provision --peer B --allow A --out state/B.token
relaynote --db state/hub.db serve --listen 127.0.0.1:8787
```

In a second terminal:

```sh
relaynote --token-file state/A.token send --to B --body "synthetic ping" --client-id request-1
relaynote --token-file state/B.token claim --lease 60
relaynote --token-file state/B.token ack --id MESSAGE_ID --receipt=RECEIPT
relaynote --token-file state/B.token reply --parent MESSAGE_ID --body "synthetic pong" --client-id reply-1
relaynote --token-file state/A.token claim
```

Global flags appear before the subcommand. Claim changes queue state and returns a lease receipt. Save/process received messages safely before acknowledging; never execute body text as commands. A valid receipt may start with `-`; use `--receipt=VALUE`.

`send` and `reply` first commit a local pending entry in `state/outbox.db`. They remove it only after the hub returns success. If the connection fails or a process stops, the pending entry remains:

```sh
relaynote --token-file state/A.token flush
```

Inspect pending keys with `outbox-list`. Explicitly discard one with `outbox-drop --key KEY`; this permanently cancels that pending submission. Flush reports failed entries and continues with others, leaving failures for review.

Flush resends only entries matching the configured endpoint and token hash. It runs once; it is not a background retry daemon. Reuse the same `--client-id` when retrying an uncertain submission. Rotating a token changes the outbox identity filter: existing pending entries need an explicit reviewed recovery procedure; they are not automatically reauthorized under a new token.

## HTTPS and proxies

A remote hub requires a valid TLS certificate and explicit non-loopback opt-in:

```sh
relaynote --db state/hub.db serve --listen 0.0.0.0:8787 --allow-remote --tls-cert server.crt --tls-key server.key
relaynote --url https://relay.example.invalid:8787 --token-file state/A.token send --to B --body "hello" --client-id remote-1
```

These are configuration examples, not a request to deploy or expose a service. Actual hosts, ports, credentials and temporary firewall/service changes require explicit operational authorization. There is no insecure-TLS option.

Use `--ca-file TEST_OR_PRIVATE_CA.pem` only to deliberately trust that CA. Use `--proxy http://proxy.example.invalid:8080` or `--env-proxy` to opt in to environment proxy settings. These choices are mutually exclusive. The default ignores environment proxies, and redirects are always rejected so bearer tokens stay with the configured origin. The tool does not join a tailnet or change network settings.

## Identity and administration

Each node has a random independent bearer token. The hub stores token hashes, not raw tokens, and enforces per-node destination ACLs. Sender identity is derived from authentication. Status reads are participant-only; claims, reply targets and acknowledgements are recipient-scoped.

Local administrative commands require exclusive database access: **stop the hub first**. They are deliberately not exposed over HTTP:

```sh
relaynote --db state/hub.db manage --peer A --action revoke
relaynote --db state/hub.db manage --peer A --action rotate --out state/A-new.token
relaynote --db state/hub.db manage --peer A --action permissions --allow B
```

Rotation re-enables a revoked identity. Empty `--allow` denies sending. Revocation cannot retract previously received data. On Windows, protect the state directory with an appropriate per-user ACL; POSIX permission bits are not a Windows security boundary. Tokens, database payloads, receipts and outbox messages are local sensitive state; this preview does not provide encryption at rest or a credential vault.

## Semantics and limits

- Commit before acceptance response; stable sender-scoped idempotency keys; changed request with the same key returns 409
- At-least-once delivery; concurrent claims are serialized transactionally; expired leases redeliver with a fresh receipt
- `queued`, `leased`, `acknowledged`, `expired` describe hub/delivery state. `agent_awakened` remains `unverified`; HTTP success does not prove processing or task completion
- TTL starts when the hub first accepts the message, not when a client queues it offline; an old unsent outbox entry can still be accepted later. TTL governs delivery, not deletion or participant reads. Message/dedupe storage currently has no cleanup or quotas
- Single hub process owns each database. No high availability, multiwriter cluster or online admin API
- Consumers must deduplicate side effects by message ID. No exactly-once execution guarantee
- No automatic reconnection listener, background service installation, real Agent adapter or notification delivery
- Bounded request/response size, request timeouts and bounded active HTTP handlers are initial controls, not production DoS certification

See [protocol](docs/PROTOCOL.md), [security and operations](docs/SECURITY.md), [adapter roadmap](docs/ADAPTERS.md) and [verification](docs/TEST_REPORT.md).

## Build and test

With an official Go 1.25+ compiler (this build used Go 1.27.2):

```sh
go mod download
go test ./...
go test -race ./...
go vet ./...
go build -buildvcs=false -trimpath -o relaynote ./cmd/relaynote
sh scripts/build.sh
```

Cross-compilation does not prove runtime support. macOS and Windows require their own runtime/security/distribution validation before production use. No code-signing/notarization or OS installer is included.

## Mock task lifecycle

```sh
go run ./examples/mocktasks
```

The isolated [echo-only mock](examples/mocktasks/README.md) uses four synthetic nodes and verifies all 12 directed task requests, running statuses and completed replies. It explicitly reports `agent_execution: "mock-only"`; it does not call a model, start a real Agent, execute commands or demonstrate production task control. Status messages never create new tasks.

## License

No open-source license has been selected for the original Relaynote code. Company attribution does not itself grant a distribution license. Third-party modules retain their own licenses; see `go.mod`, `go.sum` and `THIRD_PARTY_NOTICES.md`.
