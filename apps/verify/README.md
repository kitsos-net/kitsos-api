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
4. Delivery is limited to 15 emails per UTC day by default. Users can request
   a higher `verification_emails_per_day` limit through the Keys API's
   `/me/limit-increase-requests` endpoint; it takes effect after approval.

## Resource lifecycle

- A user has at most one verification attempt and one grant per resource.
  Starting another pending attempt replaces its token instead of creating a
  duplicate.
- `DELETE /resources/:id` removes the caller's verified ownership claim and
  associated grant. It requires `verify:resource:delete`; claims owned by
  other users are left untouched.
- The magic-link email source is
  `web/cdn/api/mail/templates/verify-email.html`, published as
  `https://cdn.kitsos.net/api/mail/templates/verify-email.html`. The internal
  Mail endpoint fetches it with the `resource` and `confirm_url` variables.

## Known gaps

- `mail.ts`'s call to `mail.api.kitsos.net/send` is a **best-guess
  contract** — mail.api.kitsos.net's actual OpenAPI spec doesn't exist
  yet (see [[kitsos-mail-api]]), confirm the real payload shape before
  relying on this in production
- No cron job yet to warn users before `reverify_due_at` /
  auto-expire grants past `grace_expires_at` — that's the planned
  `cron` worker's job
- Magic-link delivery has a daily budget, but DNS verification creation and
  lookup requests do not yet have a short-window request-rate limit
