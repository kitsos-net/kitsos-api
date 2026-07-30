# keys-api

`keys.api.kitsos.net/v1` — the management API for the whole Kitsos API
platform: users, groups, apps, policies, API keys, usage limits, and
audit log. Every other app worker depends on this having real data
before `@kitsos/auth` can validate anything.

## Auth model

- `/admin/*` — requires a Clerk session belonging to a user in the
  admin group (`env.ADMIN_GROUP_ID`). Full CRUD over everything.
- `/me/*` — requires any valid Clerk session. Self-service: users can
  create their own API keys, but only with scopes their existing
  policy already grants (checked server-side, not just at issuance —
  `@kitsos/auth` re-checks the intersection on every request too).

Raw API keys (`kitsos_...`) are only ever returned once, at creation
or rotation time. Only the SHA-256 hash is stored.

Keys may authorize several applications through
`permissions: [{ appId, scopes }]`. The original single-app
`appId`/`scopes` input remains accepted for compatibility; list responses
always include canonical `permissions`.

`POST /me/session-api-key` is the API Console-specific convenience flow.
It accepts one or more of `mail`, `hide-my-email`, `verify`, and `utility`,
derives each app's scopes from the signed-in user's current policies, and
returns a single key with a server-enforced five-minute expiry. Issuing a
new Console session key revokes the user's previous one.

`POST /me/api-keys/:keyId/rotate` and the corresponding admin route perform
an atomic one-for-one replacement. App permissions, name, description,
expiry, and `auto_roll_at` are copied; the old credential is revoked in the
same D1 batch. Rotation shares the hard daily creation-churn budget and is
blocked for MCP delegation. Cache hits re-check the compact D1 key-status row,
so rotation and revocation do not leave a 60-second acceptance window.

- `/analytics/*` — machine-to-machine endpoints for Grafana. They accept
  **only** a `kitsos_` API key for the `analytics` app with the
  `analytics:read` scope whose owner is an active member of
  `env.ADMIN_GROUP_ID`; Clerk JWTs and keys owned by non-admins are rejected.
  Admin membership is checked against D1 on every request, so removal takes
  effect immediately. The endpoints expose fixed, aggregated queries and
  never accept raw SQL.

## Setup

```bash
npm install
wrangler secret put CLERK_SECRET_KEY
wrangler secret put CLERK_PUBLISHABLE_KEY
wrangler secret put ADMIN_GROUP_ID   # create an admin group via
                                       # a one-off D1 insert first,
                                       # then put its id here
wrangler deploy
```

## Bootstrapping the first admin

There's a chicken-and-egg problem: `/admin/groups` needs an admin to
call it, but you don't have a group yet. Run this once by hand:

```sql
INSERT INTO groups (id, name) VALUES ('admins', 'Kitsos Admins');
INSERT INTO group_members (group_id, user_id) VALUES ('admins', '<your-clerk-user-id>');
```

Then set `ADMIN_GROUP_ID=admins` as a secret.

## Endpoints

| Method | Path | |
|---|---|---|
| GET/POST | `/admin/apps` | |
| DELETE | `/admin/apps/:appId` | |
| POST/DELETE | `/admin/apps/:appId/scopes[/:scope]` | |
| GET | `/admin/users` | |
| PATCH | `/admin/users/:userId` | status change |
| GET/POST | `/admin/groups` | |
| DELETE | `/admin/groups/:groupId` | |
| POST/DELETE | `/admin/groups/:groupId/members[/:userId]` | |
| GET/POST | `/admin/policies` | |
| DELETE | `/admin/policies/:policyId` | |
| GET/POST | `/admin/api-keys` | POST returns raw key once |
| DELETE | `/admin/api-keys/:keyId` | revoke |
| POST | `/admin/api-keys/:keyId/rotate` | rotate; returns replacement raw key once |
| GET/POST | `/admin/usage-limits` | |
| GET | `/admin/limit-increase-requests?status=pending` | |
| POST | `/admin/limit-increase-requests/:id/approve` \| `/deny` | |
| GET | `/admin/audit-log?userId=&limit=` | |
| GET | `/analytics/overview` | API key: `analytics:read` |
| GET | `/analytics/top-users?metric=&limit=` | API key: `analytics:read` |
| GET | `/analytics/top-apps?limit=` | API key: `analytics:read` |
| GET | `/analytics/api-calls?from=&to=&groupBy=app\|user` | API key: `analytics:read` |
| GET | `/me` | own user row |
| GET | `/me/limits` | effective limits and current usage |
| GET/POST | `/me/api-keys` | self-service, scope-limited |
| POST | `/me/api-keys/:keyId/rotate` | rotate own active key |
| POST | `/me/session-api-key` | five-minute multi-app API Console key |
| DELETE | `/me/api-keys/:keyId` | own keys only |
| GET/POST | `/me/limit-increase-requests` | |

Apply `packages/auth/0005_analytics.sql`, then create a policy and an API
key for a Grafana service account that is a member of `ADMIN_GROUP_ID` under
the `analytics` app. Configure Grafana's JSON/Infinity data source with
`Authorization: Bearer kitsos_...`.

Pagination and bounded request validation are applied to the public list and
write routes without introducing a separate validation service.
