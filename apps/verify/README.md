# verify

`verify.api.kitsos.net` verifies ownership once for the whole Kitsos API
platform. API-key scopes control operations; verified resources do not
have app-specific scopes.

## Flow

**DNS-TXT** (e.g. verifying you own `domain.de`):

1. `POST /resources` with `{resourceType: "zone", value: "domain.de"}`
   → returns the TXT record name + value to add
2. Add `_kitsos-verify.domain.de TXT "kitsos-verify=<token>"` at your DNS provider
3. `POST /resources/:id/check-dns` → polls via Cloudflare DoH, marks
   verified platform-wide if the token matches
4. Ownership remains verified until the resource is explicitly removed.

**Magic link** (e.g. verifying an email address):

1. `POST /resources` with `{resourceType: "email_address", value: "you@example.com"}`.
   The worker always sends the confirmation link to that exact address.
2. User clicks it → `GET /resources/:id/confirm?token=...` (public,
   no auth — the token itself is the credential) → marks verified +
   makes the address available to every Kitsos API
3. Ownership remains verified until the resource is explicitly removed.
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
- Magic-link delivery has a daily budget, but DNS verification creation and
  lookup requests do not yet have a short-window request-rate limit
