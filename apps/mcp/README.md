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
   user's current D1 policies and the connection's current scope selection.
   Removing a policy or narrowing a connection therefore takes effect without
   waiting for the OAuth grant to expire. Account self-service scopes are the
   intentional exception: every active Clerk user already has those rights
   without an admin-created policy, and OAuth consent can only narrow them.
6. Tools are only registered when their current effective scope is present.
7. Product calls use named Worker service-binding entrypoints. Those entrypoints
   attach an environment-only delegation and re-run scope, rate, usage and
   resource-grant checks.

`mail:manage`, `hme:manage` and `verify:manage` imply their corresponding
read scope. At `https://mcp.api.kitsos.net/connections`, users can add a private
description, narrow or restore scopes within the originally approved grant, and
revoke a connection. A completely new scope still requires a fresh OAuth
authorization, so a connected client can never silently gain more access.

Each user can have at most 10 active MCP connections. Existing OAuth grants are
reconciled into D1 when the connection UI or a new consent flow is opened.

## Limits and input hardening

- MCP traffic: 120 requests/minute per connection and 300/minute per user,
  in addition to the product Workers' endpoint-specific limits
- Dynamic client registration: 10 requests/hour per source IP
- OAuth authorization: 30 requests/minute per source IP
- OAuth token endpoint: 60 requests/minute per source IP
- Client registration bodies: 32 KiB; OAuth token and Kitsos UI writes: 16 KiB
- MCP POST bodies with a declared size: 256 KiB
- Client names: 100 characters; private descriptions: 500 characters
- Registration arrays and URL metadata have explicit item and length bounds

The row-count limit is enforced with one conditional D1 insert, so concurrent
authorization attempts cannot both pass a separate read-then-write check.

## First deployment

1. Apply D1 migrations through `packages/auth/0014_mcp_connections.sql`.
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

## Design assets

The consent and connections pages follow the Kitsos design system. Every
external design asset — font, light and dark logos, and favicon — is loaded
from `cdn.kitsos.net` with a 1.5-second timeout. If that request fails or
exceeds the timeout, the browser chooses `cdn2.kitsos.net` or
`cdn3.kitsos.net` with equal probability. If the selected fallback fails, the
other fallback is attempted. If all three fail, the page keeps its local
placeholders and the existing Arial/Helvetica system-font stack.

## Local checks

```sh
npm run check
npm run dry-run
```
