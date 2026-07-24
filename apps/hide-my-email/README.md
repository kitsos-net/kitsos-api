# hide-my-email

`hme.api.kitsos.net` — manage random forwarding aliases like
`house.exclusive.15@hme.kitsos.net`. The actual mail relay runs via
Cloudflare Email Routing on the `hme.kitsos.net` **zone**, not
through the API route — see manual setup below.

## API (fetch handler)

Auth: `kitsos_...` API key with `hme:manage` scope (via `@kitsos/auth`).

- `GET /aliases` — list your own aliases
- `POST /aliases` `{forwardTo, label?}` → generates a random alias,
  returns `{id, email, forwardTo}`. `forwardTo` must be a
  `resource_grants` entry (`resourceType: "email_address"`, scope
  `hme:receive`) — same verify-first pattern as `mail`'s `from`
  address.
- `PATCH /aliases/:id` `{status?, label?, forwardTo?}` — disable/
  re-enable, rename, or change the forwarding target
- `DELETE /aliases/:id`

## Mail relay (email handler)

Incoming mail to `*@hme.kitsos.net` is handled by this Worker's
`email()` export, looked up by local part in `hme_aliases`, and
forwarded via `message.forward()`. Unknown or disabled aliases get a
proper SMTP reject (not a silent drop), so senders see a bounce
rather than mail vanishing.

**This part needs manual setup in the Cloudflare dashboard** — not
scriptable the same way as D1/KV/Workers:

1. **Email Routing → Enable** for the `hme.kitsos.net` zone
2. **Destination addresses** — every address you'll ever put in
   `forward_to` must be added and verified here first (Cloudflare
   sends a confirmation email). This is enforced by Cloudflare
   itself, independent of `@kitsos/auth`'s resource-grant check.
3. **Routing rules → Catch-all address → Send to a Worker** →
   `hide-my-email`

Until step 3 is done, `/aliases` will happily create aliases in D1,
but no actual mail will be relayed — the worker's `email()` handler
simply won't be invoked yet.

## Known gaps

- No per-user alias limit yet (unlike `mail`'s webhook/email limits)
- No "bring your own domain" (planned, per the original todo list)
- No abuse handling if a `forward_to` address gets un-verified in
  Cloudflare after aliases already point at it — forwards would start
  silently failing on Cloudflare's side
