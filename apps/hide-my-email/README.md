# hide-my-email

`hme.api.kitsos.net/v1` — manage random forwarding aliases like
`house.exclusive.15@hme.kitsos.net`. The actual mail relay runs via
Cloudflare Email Routing on the `hme.kitsos.net` **zone**, not
through the API route — see manual setup below.

## API (fetch handler)

Auth: `kitsos_...` API key with `hme:manage` scope (via `@kitsos/auth`).

- `GET /aliases` — list your own aliases
- `GET /destinations` — list forwarding destinations and their Cloudflare
  confirmation state
- `POST /destinations` `{forwardTo}` — requests Cloudflare's independent
  forwarding confirmation after Kitsos has verified the address. Cloudflare
  sends that confirmation directly to `forwardTo`; the user does not need a
  Cloudflare account.
- `POST /destinations/check` `{forwardTo}` — refresh the confirmation state
- `POST /aliases` `{forwardTo, label?}` → generates a random alias,
  returns `{id, email, forwardTo}`. `forwardTo` must be a
  `resource_grants` entry (`resourceType: "email_address"`, scope
  `hme:receive`) and have Cloudflare's forwarding confirmation — same
  verify-first pattern as `mail`'s `from` address, plus the confirmation
  required by the mail relay.
- `PATCH /aliases/:id` `{status?, label?, forwardTo?}` — disable/
  re-enable, rename, or change the forwarding target
- `DELETE /aliases/:id`

## Mail relay (email handler)

Incoming mail to `*@hme.kitsos.net` is handled by this Worker's
`email()` export, looked up by local part in `hme_aliases`, and
forwarded via `message.forward()`. Unknown or disabled aliases get a
proper SMTP reject (not a silent drop), so senders see a bounce
rather than mail vanishing.

**Current state:**

- Email Routing is already active on the `kitsos.net` zone — several
  `hme.kitsos.net` addresses already have individual forwarding rules
  (e.g. `test@hme.kitsos.net`, `namecheap.com_827@hme.kitsos.net`),
  created outside this system
- The zone-wide catch-all points to this Worker. The handler rejects
  recipients outside `hme.kitsos.net` and unknown/disabled aliases.

**Important:** the catch-all is zone-wide, not scoped to
`hme.kitsos.net` — Cloudflare's Email Routing rules only support exact
`to`-address matchers or one whole-zone catch-all, there's no
domain-suffix matcher. The Worker is therefore the fallback for *all*
unmatched mail across `kitsos.net`, not just `hme.kitsos.net`.

1. **Destination addresses** — after the user has verified an address in
   Kitsos, the API requests Cloudflare Email Routing to send its separate
   confirmation email. The user clicks that message and can then use the
   address for aliases. A Cloudflare account is not needed; this confirmation
   is enforced by Cloudflare itself, independent of the Kitsos resource grant.
2. **Catch-all → Send to a Worker** → `hide-my-email`

## Known gaps

- No "bring your own domain" (planned, per the original todo list)
- No abuse handling if a `forward_to` address gets un-verified in
  Cloudflare after aliases already point at it — forwards would start
  silently failing on Cloudflare's side

Default and hard limits are documented in
[`../../LIMITS.md`](../../LIMITS.md). Inbound messages are limited to 10 MiB;
forwarding is hard-capped per alias and per user per UTC day.
