# @kitsos/auth

Shared auth library for all Kitsos API app workers. Not a standalone
worker — imported directly into each app (`dns-manager`, `hide-my-email`,
`mail`, `printing`, ...).

## What it does

1. **Credential validation** — either a Clerk session JWT (browser
   clients, e.g. Admin UI) or a `kitsos_...` API key (machine
   clients), via `authenticate()`.
2. **Scope check** — effective scopes are the intersection of what the
   API key was issued with and what the user's/group's policy allows
   for that app. A key can only narrow permissions, never widen them.
3. **Resource grants (ReBAC)** — `checkResourceGrant()` for
   per-resource authorization (e.g. "can this user manage DNS zone
   `domain.de`"), tied to a `resource_verifications` row so an
   expired-and-not-renewed verification revokes access after its
   grace period.
4. **Rate limiting** — fixed-window counter in KV
   (`kitsos-api-usage-counters`), cheap enough for Free Tier.
5. **Usage limits** — daily/period budgets per user+app+limit_type,
   configurable per user via `usage_limits.is_override`, with
   `limit_increase_requests` as the admin-approved increase flow (not
   yet wired into an endpoint — that's part of the Admin UI work).
6. **Audit log** — every allow/deny decision is written to
   `audit_log`, fire-and-forget so it never blocks the request.

## Typical app worker

```ts
import { authenticate, checkResourceGrant } from "@kitsos/auth";

export default {
  async fetch(request: Request, env: Env) {
    const auth = await authenticate(request, env, "dns:record:write", "dns-manager");
    if (!auth.allowed) {
      return new Response(auth.reason, {
        status: auth.status,
        headers: { "X-Forbidden-Reason": auth.reason ?? "" },
      });
    }

    const grant = await checkResourceGrant(
      env, auth.context!, "zone", "domain.de", "dns:record:write"
    );
    if (!grant.allowed) {
      return new Response(grant.reason, { status: grant.status });
    }

    // ... actual DNS logic
  },
};
```

## Why KV auth-cache instead of hitting D1 every request

At 60s TTL, one active key costs ~1,440 KV writes/day. KV Free Tier
allows 1,000 writes/day — so this design supports roughly 40
concurrently active keys before you need Workers Paid ($5/mo, which
also lifts the KV write cap). This was a deliberate tradeoff made
during the original design discussion — see [[kitsos-api-platform]].

## Not yet implemented here

- Admin UI for approving `limit_increase_requests`
- Cron worker for resource re-verification reminders / grace-period
  cutoffs (30d DNS zones, 90d email addresses)
- `verify.api.kitsos.net` (the actual DNS-TXT poll / magic-link
  delivery) — `@kitsos/auth` only reads `resource_verifications`,
  it doesn't create them
