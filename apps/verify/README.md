# verify

`verify.api.kitsos.net` — resource ownership verification (DNS-TXT or
magic-link), the gate before any `resource_grants` row gets created.
`dns-manager`, `hide-my-email`, etc. all check grants via
`@kitsos/auth`'s `checkResourceGrant()` against what this worker
produces.

## Flow

**DNS-TXT** (e.g. verifying you own `domain.de`):

1. `POST /resources` with `{appId, resourceType: "zone", value: "domain.de", method: "dns_txt", scopes: [...]}`
   → returns the TXT record name + value to add
2. Add `_kitsos-verify.domain.de TXT "kitsos-verify=<token>"` at your DNS provider
3. `POST /resources/:id/check-dns` → polls via Cloudflare DoH, marks
   verified + creates the `resource_grants` row if the token matches
4. Re-verification due after 30 days, 7-day grace period after that
   before the grant is treated as expired (checked by
   `@kitsos/auth`'s `checkResourceGrant`, not enforced here)

**Magic link** (e.g. verifying an email address):

1. `POST /resources` with `method: "magic_link"` → sends an email via
   mail.api.kitsos.net with a confirm link
2. User clicks it → `GET /resources/:id/confirm?token=...` (public,
   no auth — the token itself is the credential) → marks verified +
   creates the grant
3. Re-verification due after 90 days, 14-day grace period

## Known gaps

- `mail.ts`'s call to `mail.api.kitsos.net/send` is a **best-guess
  contract** — mail.api.kitsos.net's actual OpenAPI spec doesn't exist
  yet (see [[kitsos-mail-api]]), confirm the real payload shape before
  relying on this in production
- No cron job yet to warn users before `reverify_due_at` /
  auto-expire grants past `grace_expires_at` — that's the planned
  `cron` worker's job
- No rate limiting on `/resources` POST — someone could hammer DNS
  lookups; add via `@kitsos/auth`'s `checkRateLimit` before this is
  public-facing beyond your own use
