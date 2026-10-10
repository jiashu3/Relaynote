# Mock task lifecycle example

This isolated example demonstrates an application-level task/result exchange over
Relaynote's real shared HTTP client, API, and temporary bbolt store. It is an
**echo-only mock**, not a real Agent adapter, task execution engine, or complete
adapter product. It does not wake a terminal Agent. Relay messages continue to
report `agent_awakened: "unverified"`; the example reports
`agent_execution: "mock-only"`.

## Run

From the repository root, using the Go version required by `go.mod`:

```sh
go run ./examples/mocktasks
go test ./examples/mocktasks
```

Expected summary:

```json
{"nodes":4,"verified_directions":12,"requests":12,"running":12,"completed":12,"failed":0,"acknowledged":36,"delivery_ttl_seconds":60,"max_hop":1,"agent_execution":"mock-only"}
```

The four synthetic nodes are `alpha`, `bravo`, `charlie`, and `delta`. Each has an
explicit send ACL listing the other three nodes; no wildcard permission is used.
Each directed pair sends exactly one explicit request. Its destination sends a
running reply followed by a completed echo reply. The original requester claims
and acknowledges those replies. All messages are acknowledged through the shared
HTTP client, and the demo verifies task IDs, parent message IDs, direction, thread
IDs, results, and the final totals before printing success.

## Task envelope and correlation

A request body is JSON serialized as the relay message's opaque `body` string:

```json
{"kind":"task.request","task_id":"task:alpha:bravo","operation":"echo","text":"hello from alpha to bravo","hop":0,"ttl":60}
```

The example recognizes these kinds:

- `task.request`: an explicit request for a literal, in-memory echo
- `task.running`: a mock lifecycle status with no result
- `task.completed`: a mock lifecycle status whose `result` is the original text
- `task.failed`: a bounded rejection with a constant `error` code

Every status preserves `task_id` and uses `/v1/messages/{original-message-id}/reply`,
so the relay records the original message as `reply_to` and preserves its
`thread_id`. A receiver must check all of those values and the authenticated
sender/recipient metadata together. A task ID alone is not proof of origin.

Only root `task.request` envelopes with `operation: "echo"`, `hop: 0`, and
`ttl: 60` can reach the mock string assignment. Text must be nonempty, valid UTF-8,
at most 256 bytes, and contain no control characters. Request bodies larger than
2,048 bytes, undecodable JSON, unknown fields, missing/invalid task IDs, and unknown
message kinds are acknowledged without a reply. A recognized, correlatable
request with an unsupported operation, exhausted/negative hop, invalid TTL,
invalid text, result/error fields, or a reply parent produces one `task.failed`
reply. Failures contain constant error codes and do not echo rejected text or
operation names.

Delivery TTL is fixed at 60 seconds in the relay send/reply calls as well as in the
envelope. A request consumes the only permitted hop; every status has `hop: 1`.
Statuses are acknowledged and **never trigger a task or another status reply**,
even if their other fields look like a request. The demo also has finite drain
pass and message-count guards.

## What idempotency proves

A status `client_id` is deterministically formed from the received relay message
ID and status kind, for example `mock:{message-id}:task.completed`. Retrying the
original send uses the same request client ID. The tests also simulate a crash
after status replies commit but before the request is acknowledged, advance the
delivery lease, reclaim the same request, and repeat processing. The repeated
status sends return the same message IDs rather than creating duplicate records.

This is safe for a pure echo calculation. It **does not guarantee exactly-once
execution of real tasks or side effects**. Relay delivery is at least once. A
real adapter would need an authorized integration, durable task state, side-effect
idempotency, cancellation/recovery semantics, permission enforcement, and verified
Agent lifecycle reporting. None is implemented or claimed by this example.

## Isolation and test scope

- Only an `httptest` loopback HTTP server is contacted
- A new private temporary directory and bbolt database are deleted on normal exit
- Fresh synthetic bearer credentials stay in memory and are never printed
- No real URLs, credentials, models, devices, services, or Agent processes are used
- No shell, subprocess, received-command execution, forwarding, or external task
  dispatch exists; command-looking text is just a string
- No external-target flags or environment configuration are read
- Production CLI and core protocol behavior are unchanged

Tests cover all 12 directions; request/result correlation; terminal
acknowledgements; no status ping-pong; operation, hop, TTL and text rejection;
request/status idempotency across real lease redelivery; explicit ACL rejection;
and literal echo of command-looking text. The CLI's successful run contains no
failed requests; rejected cases are exercised separately by the tests.

Relaynote is an isolated prototype by [Ripplelab Limited](https://www.ripplelab.hk).
