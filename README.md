# kitsos-api

Kitsos API platform — API-first, RBAC + ReBAC, on Cloudflare Workers.

All public endpoints are versioned below `/v1` on their service-specific
hostname, for example `https://mail.api.kitsos.net/v1/send`.
See [`VERSIONING.md`](./VERSIONING.md) for the compatibility policy and the
criteria for introducing `/v2`.

## Structure

- `packages/auth` — `@kitsos/auth`, shared auth library used by every app worker
- `apps/` — individual app workers, including `mcp`, `hide-my-email`,
  `mail`, `utility`, `keys-api` and `verify`
- `web/` — frontends (Admin UI, per-app WebUIs)

## Infra

- D1: `kitsos-api` (`c5ccab68-5f60-4b28-8ce9-20c57b8622ea`)
- KV: `kitsos-api-auth-cache` (`86fb5bad46c6458d91cbb322b7178ccf`)
- KV: `kitsos-api-usage-counters` (`4823ab0d3fd6452e8437631a3717f2b5`)
- KV: dedicated MCP OAuth storage (create before the first MCP deployment)
- Auth: Clerk (`clerk.kitsos.net` / `accounts.kitsos.net`)
- Remote MCP: `https://mcp.api.kitsos.net/mcp`

See `packages/auth/README.md` for the auth model. The database schema is
defined by the ordered migrations `packages/auth/0001_init.sql` through
`packages/auth/0015_key_rotation_and_resource_deletion.sql`.

Migration 0006 invalidates pending legacy plaintext verification tokens;
migration 0007 adds atomic product counters and retention; migration 0008
registers the Utility API and its scopes; migration 0009 moves request-rate
counters to atomic D1 rows so KV write exhaustion cannot take APIs offline;
migration 0010 provisions the least-privileged Verify mail service principal,
sender grant, template, and isolated mail quota; migration 0011 moves that
sender to `verify@notify.kitsos.net`.
Migration 0012 adds canonical multi-app API-key permissions, MCP-exposable
scope metadata and authentication provenance in the audit log.
Migration 0013 replaces the legacy Utility umbrella policy with the four
concrete Utility scopes. Migration 0014 adds bounded, user-managed MCP
connections. Migration 0015 enforces dependency-safe verified resource
deletion; key rotation itself uses the existing schema.

See [`apps/mcp/README.md`](./apps/mcp/README.md) for the MCP authorization
model, deployment order and the explicit exclusion of Analytics, admin
functions and API-key management.

See [`LIMITS.md`](./LIMITS.md) for hard abuse caps, adjustable product limits,
and the proposed Cloudflare edge rule.
