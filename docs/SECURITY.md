# Security and operational boundaries

This preview has been developed with synthetic local peers. It does not install services, modify firewalls, discover credentials, join a network, scan hosts or execute received commands.

A remote deployment is a separate operational action. Agree exactly one test hub, allowed clients, endpoint, temporary directory/process, time window, synthetic identities and cleanup before testing. Generic HTTPS health reachability is not proof of protocol delivery, persistence, lease recovery or Agent wake.

Use normal validated TLS for remote connections; use a trusted per-user state directory. On Unix, provision directories0700 and files0600. On Windows, enforce owner-only access through filesystem ACLs; native runtime validation is still required. The source and compiled executable do not contain deployment credentials or certificates.

bbolt opens one database exclusively with a timeout. Stop the hub before local provisioning/rotation/revocation. This makes failure visible instead of allowing simultaneous independent writers. Normal transaction syncing is enabled; no unsafe NoSync mode is used. Process-crash tests do not establish power-loss guarantees on every filesystem/OS.

Outbox data contains endpoint, token hash, route and message body, never a raw token. Entries are bound to both endpoint and token hash; rotation does not automatically replay previous identity's pending data. Pending failures remain for review while flush continues with other entries. Use outbox-list to inspect keys and outbox-drop --key KEY only to explicitly discard a selected pending submission. This drop is permanent.

Revoke temporary node tokens, stop test processes and remove only authorized experiment resources at the end. Revocation cannot remove already-read copies. Cleanup of temporary data and firewall/route entries must stay inside the approved scope. Do not silently broaden visibility or exposure to make a test pass.

Unverified: macOS/Windows runtime, cloud-to-server protocol roundtrip, OS key vaults, physical power failure, load/DoS, retention/quotas, backup restore, schema migration, high availability, code signing and installers, real Agent integrations.
