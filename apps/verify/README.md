# verify

`verify.api.kitsos.net/v1` — resource ownership verification (DNS-TXT or
magic-link), the gate before any `resource_grants` row gets created.
Ownership is global: one verification is reusable by every current and future
Kitsos app. App scopes still authorize product actions separately.
`dns-manager`, `hide-my-email`, etc. all check grants via
`@kitsos/auth`'s `checkResourceGrant()` against what this worker
produces.

## Flow

**DNS-TXT** (e.g. verifying you own `domain.de`):

1. `POST /resources` with `{resourceType: "zone", value: "domain.de", method: "dns_txt"}`
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

## Deletion semantics

`DELETE /resources/:resourceId` removes only the authenticated user's grant,
verification history, and legacy API-key resource links. A shared canonical
resource row remains while another user still owns it. The endpoint returns
`409 resource-in-use` when one of that user's mail webhooks uses the verified
address as its sender or an HME alias uses it as its forwarding destination.
There is deliberately no product-object cascade: reconfigure or delete those
objects first. The database trigger enforces the same rule if deletion races
with product-object creation. Admin deletion uses the same conflict rule.

Re-verification reminders are outside this closed platform increment; expiry
is already enforced by `@kitsos/auth` at use time.
