# kitsos-api

Kitsos API platform — API-first, RBAC + ReBAC, on Cloudflare Workers.

All public endpoints are versioned below `/v1` on their service-specific
hostname, for example `https://mail.api.kitsos.net/v1/send`.
See [`VERSIONING.md`](./VERSIONING.md) for the compatibility policy and the
criteria for introducing `/v2`.

## Structure

- `packages/auth` — `@kitsos/auth`, shared auth library used by every app worker
- `apps/` — individual app workers (dns-manager, hide-my-email, mail, printing, keys-api, verify, cron, ...)
- `web/` — frontends (Admin UI, per-app WebUIs)

## Infra

- D1: `kitsos-api` (`c5ccab68-5f60-4b28-8ce9-20c57b8622ea`)
- KV: `kitsos-api-auth-cache` (`86fb5bad46c6458d91cbb322b7178ccf`)
- KV: `kitsos-api-usage-counters` (`4823ab0d3fd6452e8437631a3717f2b5`)
- Auth: Clerk (`clerk.kitsos.net` / `accounts.kitsos.net`)

See `packages/auth/README.md` for the auth model. The database schema is
defined by the ordered migrations `packages/auth/0001_init.sql` through
`packages/auth/0008_utility_api.sql`.

Migration 0006 invalidates pending legacy plaintext verification tokens;
migration 0007 adds atomic product counters and retention; migration 0008
registers the Utility API and its scopes.

See [`LIMITS.md`](./LIMITS.md) for hard abuse caps, adjustable product limits,
and the proposed Cloudflare edge rule.
