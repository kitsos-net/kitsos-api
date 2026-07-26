# @kitsos/auth

Shared auth library for all Kitsos API app workers. Not a standalone
worker — imported directly into each app (`dns-manager`, `hide-my-email`,
`mail`, `printing`, ...).

## What it does

1. **Credential validation** — either a Clerk session JWT (browser
   clients, e.g. Admin UI) or a `kitsos_...` API key (machine
   clients), via `authenticate()`.
2. **Cross-app keys and scope check** — a key can be assigned to one or more
   apps. For each requested app its effective scopes are the intersection of what the
   API key was issued with and what the user's/group's policy allows
   for that app. A key can only narrow permissions, never widen them.
3. **Resource grants (ReBAC)** — `checkResourceGrant()` for
   per-resource authorization (e.g. "can this user manage DNS zone
   `domain.de`"), tied to a `resource_verifications` row so an
   expired-and-not-renewed verification revokes access after its
   grace period.
4. **Rate limiting** — fixed-window counter in KV
   (`kitsos-api-usage-counters`). App-wide or scope-specific rules from
   `rate_limit_rules` override each endpoint's safe default.
5. **Usage limits** — daily budgets per user+app+limit_type. Defaults live
   in `usage_limit_defaults`; a user row in `usage_limits` takes precedence.
   Increase requests are reviewable and approvable in the Keys API.
6. **Optional key resource allow-lists** — `api_key_resource_grants` can
   narrow a key to individual resources (currently used for mail templates).
7. **Audit log** — every allow/deny decision is written to
   `audit_log`, fire-and-forget so it never blocks the request.
8. **Per-user observability** — authenticated request spans include internal
   user, API-key, auth-method and scope identifiers for exact success/error
   aggregation in Axiom. See `docs/axiom-api-usage.md`.

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

## Scope conventions currently enforced

- Mail: `mail:send`, `mail:template:read|write|delete`,
  `mail:webhook:read|write|delete`
- Hide My Email: `hme:read|create|edit|delete`
- Verify: `verify:resource:read|create|verify|delete`

The legacy `*:manage` scopes remain accepted only for existing keys; issue the
granular scopes for new keys.

## Not yet implemented here

- Cron worker for resource re-verification reminders / grace-period
  cutoffs (30d DNS zones, 90d email addresses)
- `verify.api.kitsos.net` (the actual DNS-TXT poll / magic-link
  delivery) — `@kitsos/auth` only reads `resource_verifications`,
  it doesn't create them
