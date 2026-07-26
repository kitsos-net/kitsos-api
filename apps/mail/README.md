# mail

`mail.api.kitsos.net` — email sending, both manual (`POST /send`) and
via user-managed webhooks with dot-notation payload → template
mapping (built to replace Certimate's broken `text/plain`-only HTML
emails, see [[kitsos-mail-api]]).

## Auth model

- `POST /webhook/:id` — public, gated by `X-Webhook-Secret` header
  (hashed, compared against `mail_webhooks.secret_hash`). No
  `@kitsos/auth` involved — the webhook secret *is* the credential.
- Everything else — `kitsos_...` API key via `@kitsos/auth`, scopes
  `mail:send` (for `/send` and webhook creation) and `mail:manage`
  (templates/webhooks CRUD).
- **`from` address must be verified** — its owner verifies the email
  address once through `verify.api.kitsos.net`; that ownership proof is
  reusable by Mail, HME, and every other Kitsos API.

## Templates

Not stored in D1 — too large, and no R2 upload yet. You give a URL,
the worker fetches it and caches the HTML for 1h in `AUTH_CACHE` KV
(keyed by template id, so `PATCH` invalidates it directly). Rendering
is `{{ variableName }}` substitution, same syntax Certimate itself
uses.

## Webhooks

```
POST /webhooks
{
  "name": "certimate-failures",
  "templateId": "tpl_...",
  "fromAddress": "certimate@kitsos.net",
  "toAddresses": ["dion@kitsos.net"],
  "mapping": {
    "workflowName": "workflow.name",
    "errorMessage": "error.message"
  }
}
→ { "id": "...", "secret": "...", "url": "https://mail.api.kitsos.net/webhook/..." }
```

The `secret` is only ever shown here. Point Certimate (or whatever)
at the returned `url` with `X-Webhook-Secret: <secret>`.

## Limits

Default 10 webhooks / 20 emails per day per user, overridable per-user
via a row in `mail_user_limits` (no self-service increase yet — insert
manually, or wire up `keys-api`'s `limit_increase_requests` flow to
write here later).

## Setup

```bash
npm install
wrangler secret put CLERK_SECRET_KEY
wrangler secret put CLERK_PUBLISHABLE_KEY
wrangler secret put BREVO_API_KEY
wrangler deploy
```

You'll also need, via `keys-api`:
1. An `apps` row for `mail` with scopes `mail:send`, `mail:manage`
2. A policy granting yourself those scopes
3. A verified ownership record for every `from` address
   (via `verify.api.kitsos.net`, `resourceType: "email_address"`)

## Known gaps

- No template variable validation against `mail_templates.variables`
  at send time — a mismatched mapping just renders blanks, doesn't
  error
- No retry/dead-letter handling if Brevo is down
- Certimate's Auth0-era HTML templates ([[kitsos-mail-api]]) aren't
  wired in as `mail_templates` rows yet — that's a one-time data
  migration, not code
