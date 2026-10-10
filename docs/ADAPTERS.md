# Agent adapter roadmap: documented interfaces, not shipped integrations

Relaynote routes between any authorized identities through a hub. No pair of named Agents is a fixed controller/worker topology, and no N×N tunnel mesh is required. An endpoint should eventually identify device + Agent + profile/workspace, rather than assume a machine name identifies one execution context.

A future adapter receives only permitted task kinds and capabilities; it owns task acceptance, running, completion, failure and cancellation. Transport queued/leased/acknowledged remains independent. Use task_id, correlation and parent message IDs, explicit envelope kinds, bounded hops and delivery/task time limits. A result or status message must never automatically create another task. Idempotent transport does not guarantee exactly-once task side effects.

## Documented integration routes to verify in a future bounded test

- Codex app-server: initialization, thread start/resume, turn start, streamed turn completion, turn interruption and approval events. Preserve approvals and workspace scope. Do not publicly expose raw app-server execution capabilities. [Official app-server documentation](https://learn.chatgpt.com/docs/app-server)
- Hermes gateway: capabilities discovery, run creation/status/events/stop/approval and durable idempotency keys. Restrict the wrapper to explicitly approved tasks; do not expose an unrestricted gateway. [Official API server documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server)
- Grok Bot: a routine can have a webhook POST URL and bearer key generated in its app; a documented remote HTTPS MCP path can support constrained outbound tool calls. A webhook acceptance response alone is not task completion. A generic result/status/cancel interface has not been established here. Proposed future pattern: notification carries task_id, Bot claims the authorized task and explicitly reports results through constrained tools. [Routine documentation](https://cursor.com/help/grok-bot/routines), [team-bot MCP documentation](https://docs.x.ai/grok-bot/team-bots)

These are integration research leads from official documentation, not implemented adapters or a report of account access. No actual Agent endpoint, credentials, external webhook or model call has been used in this release. Exact interface versions, permissions, account availability, wake behavior and error/retry semantics require separate verification. No missing API is invented.

## Mock example boundary

The isolated mock example exercises synthetic task requests and running/completed/failed results through the transport. Its only simulated capability is echo. It cannot prove a real Agent was awakened, accepted a task, obtained approval or completed work. Real integration remains the next explicitly scoped stage.
