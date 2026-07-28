# verify

`verify.api.kitsos.net/v1` — resource ownership verification (DNS-TXT or
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

1. `POST /resources` with `resourceType: "email_address"` and
   `method: "magic_link"` → sends an email via mail.api.kitsos.net to
   exactly the address supplied in `value`
2. User clicks it → `GET /resources/:id/confirm?token=...` (public,
   no auth — the token itself is the credential) → marks verified +
   creates the grant
3. Re-verification due after 90 days, 14-day grace period

Magic-link tokens are stored only as SHA-256 hashes and expire after
30 minutes. DNS challenges expire after 24 hours.

## Known gaps

- No cron job yet to warn users before `reverify_due_at` /
  auto-expire grants past `grace_expires_at` — that's the planned
  `cron` worker's job
