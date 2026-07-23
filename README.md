# kitsos-api

Kitsos API platform — API-first, RBAC + ReBAC, on Cloudflare Workers.

## Structure

- `packages/auth` — `@kitsos/auth`, shared auth library used by every app worker
- `apps/` — individual app workers (dns-manager, hide-my-email, mail, printing, keys-api, verify, cron, ...)
- `web/` — frontends (Admin UI, per-app WebUIs)

## Infra

- D1: `kitsos-api` (`c5ccab68-5f60-4b28-8ce9-20c57b8622ea`)
- KV: `kitsos-api-auth-cache` (`86fb5bad46c6458d91cbb322b7178ccf`)
- KV: `kitsos-api-usage-counters` (`4823ab0d3fd6452e8437631a3717f2b5`)
- Auth: Clerk (`clerk.kitsos.net` / `accounts.kitsos.net`)

See `packages/auth/README.md` for the auth model, `packages/auth/0001_init.sql`
for the schema (already applied to the D1 instance above).
