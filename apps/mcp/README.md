# Kitsos MCP Server

Remote MCP endpoint for ChatGPT, Claude and other OAuth-capable MCP clients:

```text
https://mcp.api.kitsos.net/mcp
```

The same Worker hosts the OAuth authorization screen at `/authorize` and the
revocation UI at `/connections`. Clerk authenticates the human in the browser;
the Cloudflare Workers OAuth Provider issues a separate, short-lived MCP access
token to the client. Clerk session tokens are never handed to the MCP client.

## Exposed products

- Account self-service: profile, limits and limit-increase requests
- Verify: own resource verifications
- Mail: templates, webhooks and sending
- Hide My Email: aliases
- Utility: cryptographic helpers, time, geo and DNS

Analytics, every `/admin/*` route and all API-key list/create/revoke routes are
deliberately absent. Product Workers also reject API-key management when called
through their private MCP entrypoint, so this is not only a UI restriction.

## Authorization model

1. The MCP client discovers OAuth metadata and dynamically registers itself.
2. `/authorize` validates the OAuth request and stores it for at most 10 minutes.
3. The user signs in through Clerk and selects scopes. Read scopes are
   preselected; write/send scopes are opt-in.
4. The OAuth Provider issues a one-hour access token and a refresh token that
   expires after 30 days.
5. Every MCP request recomputes the intersection of the token grant and the
   user's current D1 policies. Removing a policy therefore takes effect without
   waiting for the OAuth grant to expire. Account self-service scopes are the
   intentional exception: every active Clerk user already has those rights
   without an admin-created policy, and OAuth consent can only narrow them.
6. Tools are only registered when their current effective scope is present.
7. Product calls use named Worker service-binding entrypoints. Those entrypoints
   attach an environment-only delegation and re-run scope, rate, usage and
   resource-grant checks.

`mail:manage`, `hme:manage` and `verify:manage` imply their corresponding
read scope. OAuth grants can be revoked at
`https://mcp.api.kitsos.net/connections`.

## First deployment

1. Apply D1 migration `packages/auth/0012_mcp_and_multi_app_keys.sql`.
2. Deploy `keys-api`, `verify`, `mail`, `hide-my-email` and `utility`, so their
   named `McpEntrypoint` service-binding entrypoints exist.
3. Create a dedicated OAuth KV namespace and configure its ID in
   `wrangler.toml`.
4. Configure the public Clerk publishable key in `wrangler.toml`.
5. Deploy this Worker and route `mcp.api.kitsos.net`.

The OAuth KV namespace must not be shared with `AUTH_CACHE`: it contains
registered clients, authorization grants, codes and tokens.

The MCP Worker deliberately owns no Clerk secret. Its consent UI sends the
Clerk session token to the private `McpIdentityEntrypoint` service binding on
`keys-api`, where the already configured `CLERK_SECRET_KEY` verifies it.

## Local checks

```sh
npm run check
npm run dry-run
```
