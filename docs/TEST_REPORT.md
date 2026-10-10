# Relaynote 0.3.0-preview verification

Developed by 涟漪工场有限公司（Ripplelab Limited） — https://www.ripplelab.hk/

Date: 2026-10-10 UTC. Scope: isolated cloud workspace; synthetic identities; loopback processes and fixtures only. No real devices, servers, accounts or Agents were used.

## Verified result

- 48 top-level Go tests plus table/subtests passed across six packages
- All six packages passed the race detector; go vet passed
- go mod verify: all modules verified
- Compiled Linux amd64 HTTPS hub: unknown test CA rejected before delivery; explicit test-CA trust allowed send/claim/ack; SIGTERM exited cleanly
- Compiled Linux amd64 CLI: A→B→A, ACKs, forced hub process kill/restart, same-ID send replay, lease redelivery with a new receipt and increased attempts passed
- Four-node any-to-any: all 12 directed request paths, correlated reverse results, and a denied ACL direction with reverse direction still permitted passed
- Go CLI against the separate Python reference hub, and Python reference client against the Go hub, passed bidirectional reply/ACK interoperability tests. Database formats are intentionally different; no migration is implied
- TLS unknown-CA and hostname rejection, extra trusted CA, HTTPS CONNECT proxy, explicit environment-proxy opt-in, zero-follow redirects, fixed-origin paths, response bounds and cancellation tested locally
- HTTP loopback rejects every proxy mode to prevent loopback credentials being sent to a remote proxy
- A maximally escaped valid 100-message claim (~39 MB) fits the 48 MiB response cap; limit+1 rejected
- Strict Unicode, duplicate/unknown JSON fields, malformed bodies, sender spoofing, identity/ACL checks, sender-scoped idempotency and current receipt checks covered
- Durable outbox recovery, conflicting pending key, identity/endpoint isolation, explicit list/drop, and continued flush after a failed entry covered
- bbolt concurrent claims, transaction rollback, token hashes, schema refusal, exclusive process ownership and killed-process persistence covered

- Mock-only task lifecycle: four synthetic nodes, all 12 directed task requests, 12 running and 12 completed status replies, 36 transport acknowledgements; correlation, unsupported operation/hop/TTL/text rejection, no status ping-pong and redelivery idempotency tested. No real Agent execution occurred

Raw output: GO_TEST_OUTPUT.txt, GO_RACE_OUTPUT.txt, GO_VET_OUTPUT.txt, MODULE_VERIFY.txt, MOCK_DEMO_OUTPUT.json. The compiled-binary smoke test is reproducible with `python3 scripts/smoke.py dist/relaynote-linux-amd64` after building.

## Build matrix

Cross-built with CGO_ENABLED=0 and trimpath/VCS stamping disabled:

- Linux amd64: build passed; runtime tests and compiled CLI smoke passed
- Linux arm64: build passed; runtime not tested
- macOS amd64: build passed; runtime not tested
- macOS arm64: build passed; runtime not tested
- Windows amd64: build passed; runtime not tested
- Windows arm64: build passed; runtime not tested

Build success is not native runtime certification. No installers, code signing, notarization or background OS services were produced.

## Build provenance

Official Go 1.27.2 linux-amd64 archive; 70590635 bytes; SHA-256 `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5`, checked against https://go.dev/dl/?mode=json before extracting into an isolated build directory. No system Go installation was modified.

Runtime third-party dependencies: go.etcd.io/bbolt v1.5.0 and golang.org/x/sys v0.45.0. Module checksums are in go.sum; module verification passed. Standard syncing is enabled, no unsafe NoSync option. See THIRD_PARTY_NOTICES.md.

## Independent review

Independent read-only review found and prompted fixes for large-claim response limits, HTTP-loopback proxy leakage, outbox privacy and failed-entry handling, and shutdown draining. The reviewer reran the transport packages normally and under the race detector successfully. A subsequent read-only review of the mock example found no real-Agent, process or external invocation; independent normal and race tests passed all six packages. The final full six-package normal/race/vet run also passed. The mock nodes are logical adapters in one local process, not native platform Agent processes.

## Explicitly unverified

Real cloud-to-server protocol traffic; native macOS/Windows/arm64 execution and filesystem ACL behavior; physical power loss; load/DoS certification; retention/quotas; backup/migration; HA; real Agent wake/task execution, platform adapters or cancellation APIs. Transport ACK is never task completion. The preview uses a new bbolt database, not legacy SQLite. No permanent service or external credentials are bundled.
