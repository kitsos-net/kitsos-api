# hide-my-email

`hme.api.kitsos.net` — manage random forwarding aliases like
`house.exclusive.15@hme.kitsos.net`. The actual mail relay runs via
Cloudflare Email Routing on the `hme.kitsos.net` **zone**, not
through the API route — see manual setup below.

## API (fetch handler)

Auth: `kitsos_...` API key with `hme:manage` scope (via `@kitsos/auth`).

- `GET /aliases` — list your own aliases
- `POST /aliases` `{forwardTo, label?}` → generates a random alias,
  returns `{id, email, forwardTo}`. `forwardTo` must be an email address
  whose ownership the user verified once through `verify.api.kitsos.net`.
  The same verification works for every Kitsos API.
- `PATCH /aliases/:id` `{status?, label?, forwardTo?}` — disable/
  re-enable, rename, or change the forwarding target
- `DELETE /aliases/:id`

## Mail relay (email handler)

Incoming mail to `*@hme.kitsos.net` is handled by this Worker's
`email()` export, looked up by local part in `hme_aliases`, and
forwarded via `message.forward()`. Unknown or disabled aliases get a
proper SMTP reject (not a silent drop), so senders see a bounce
rather than mail vanishing.

**Current state (checked via the Cloudflare API):**

- Email Routing is already active on the `kitsos.net` zone — several
  `hme.kitsos.net` addresses already have individual forwarding rules
  (e.g. `test@hme.kitsos.net`, `namecheap.com_827@hme.kitsos.net`),
  created outside this system
- The **catch-all rule is currently disabled and set to `drop`** —
  anything not explicitly listed is silently dropped
- To make dynamically-generated aliases (from `POST /aliases`) actually
  receive mail without a manual per-alias rule, the catch-all needs to
  point to this Worker instead

**Important:** the catch-all is zone-wide, not scoped to
`hme.kitsos.net` — Cloudflare's Email Routing rules only support exact
`to`-address matchers or one whole-zone catch-all, there's no
domain-suffix matcher. Pointing catch-all at this Worker means it
becomes the fallback for *all* unmatched mail across `kitsos.net`, not
just `hme.kitsos.net`. The `email()` handler already rejects unknown
local parts with a bounce, so this is safe, but it's a zone-wide
behavior change worth being deliberate about — not done automatically
by this worker or by Claude without confirmation.

1. **Destination addresses** — every address you'll ever put in
   `forward_to` must be added and verified in Email Routing first
   (Cloudflare sends a confirmation email). Enforced by Cloudflare
   itself, independent of `@kitsos/auth`'s resource-grant check.
2. **Catch-all → Send to a Worker** → `hide-my-email` (see note above)

## Known gaps

- No per-user alias limit yet (unlike `mail`'s webhook/email limits)
- No "bring your own domain" (planned, per the original todo list)
- No abuse handling if a `forward_to` address gets un-verified in
  Cloudflare after aliases already point at it — forwards would start
  silently failing on Cloudflare's side
