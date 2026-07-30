# @kitsos/auth

Shared auth library for all Kitsos API app workers. Not a standalone
worker — imported directly into each app (`dns-manager`, `hide-my-email`,
`mail`, `printing`, ...).

## What it does

1. **Credential validation** — a Clerk session JWT, a `kitsos_...` API key,
   or an environment-only MCP delegation accepted exclusively by named,
   private Worker entrypoints.
2. **Scope check** — effective scopes are the intersection of what the
   API key was issued with and what the user's/group's policy allows
   for that app. A key can only narrow permissions, never widen them.
3. **Resource grants (ReBAC)** — `checkResourceGrant()` for
   per-resource authorization (e.g. "can this user manage DNS zone
   `domain.de`"), tied to a `resource_verifications` row so an
   expired-and-not-renewed verification revokes access after its
   grace period.
4. **Rate limiting** — atomic fixed-window counters in D1.
5. **Usage limits** — daily/period budgets per user+app+limit_type,
   configurable per user via `usage_limits.is_override`, with
   `limit_increase_requests` as the admin-approved increase flow.
6. **Audit log** — every allow/deny decision is written to `audit_log` with
   authentication method, credential/grant id and OAuth client id where
   available; logging never blocks the request.

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

## API-key cache

API-key validation uses a short, app-specific KV cache. D1 remains the source
of truth and a KV write failure never rejects an otherwise valid key. Rate
limits are intentionally not stored in KV.

API keys can carry canonical `permissions: [{ appId, scopes }]` for several
apps. The legacy single `appId` plus `scopes` input is still accepted.

MCP calls never reuse or mint API keys. The MCP Worker authenticates the user
with Clerk during consent, issues an OAuth grant, and passes a narrowly scoped
identity only over private Worker service bindings.

The product-limit catalog, defaults, and hard maxima are documented in
[`../../LIMITS.md`](../../LIMITS.md). Daily product counters use atomic D1
upserts so concurrent requests cannot overshoot a quota.

## Not yet implemented here

- Cron worker for resource re-verification reminders / grace-period
  cutoffs (30d DNS zones, 90d email addresses)
