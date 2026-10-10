# Protocol v1

Every route requires one Bearer Authorization header. Requests use JSON; unknown/duplicate fields, invalid UTF-8/surrogate escapes and nonobject envelopes are rejected. POST requests require Content-Length. Browser Origin requests are rejected; no CORS interface exists.

- POST /v1/messages: to, body, client_id, optional ttl (integer seconds; default604800;1..2592000)
- POST /v1/inbox/claim: optional limit1..100 (default10), lease1..3600 (default300)
- GET /v1/messages/{id}: sender/recipient status, never includes a lease receipt
- POST /v1/messages/{id}/reply: body,client_id,optional ttl; only recipient may reply to original sender; preserves thread_id
- POST /v1/messages/{id}/ack: receipt; only current recipient lease receipt succeeds

UTF-8 body max65536bytes; request envelope400000bytes; client response48MiB (bounded above the worst valid 100-message JSON-escaped claim). Message fields: id,sender,recipient,client_id,thread_id,reply_to,body,created_at,expires_at,acked_at,attempts,state,agent_awakened. Timestamps are UNIX seconds. Claim alone adds receipt and lease_until.

Idempotency is scoped to authenticated sender/client_id. Fingerprint includes destination, body, TTL and reply parent. Same request returns the original ID; different semantic request conflicts. Current ACL and active destination checks precede replay, so a later permission change may reject replay of an earlier accepted submission. Expiration does not remove the dedupe entry. TTL starts at first hub acceptance, not local outbox enqueue. Never decrement TTL on an ambiguous retry, because that changes the idempotency fingerprint.

A claim commit increments attempts and creates a lease. Lost claim response is indistinguishable from a dropped consumer; the lease must expire before redelivery. A new receipt fences an earlier claim. Successful ACK can be repeated with its own receipt, even after original TTL; an unacknowledged message cannot be newly ACKed after lease/TTL expiration.

The protocol transfers messages only. It does not authorize external Agent communications, wake a personal Agent, or execute a shell command. Future adapters require platform-specific verified APIs and explicit action scope.

## Future task adapters, separate from transport

Messages may carry a task request or its result between any authorized pair; the transport is not limited to named platforms or prewired routes. Actual personal-Agent integration is not implemented. A future adapter must declare supported capabilities and recipient policy, validate structured task input, and report its own accepted/started/completed/failed/cancelled lifecycle with correlation IDs. Delivery ACK remains distinct. Unsupported or unauthorized tasks must be rejected, and no generic received text is executable code. Real Agent wake and execution can only be claimed after a verified platform interface and an explicit bounded authorization.
