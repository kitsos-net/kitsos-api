# Kitsos API limits

Limits have two separate purposes:

- **Hard abuse limits** protect Workers, D1, KV, template fetching, hashing,
  and upstream mail services. They are deliberately generous and cannot be
  increased per user.
- **Product limits** control Free Tier consumption. Users can request an
  increase; an admin-approved override is stored in `usage_limits`, but can
  never exceed the hard system maximum.

All daily windows use UTC days. A mail sent to multiple recipients consumes
one unit per recipient. Manual sends, stored-template sends, and public webhook
sends all consume the same `emails_per_day` counter. An attempted upstream send
consumes quota even when Brevo subsequently rejects it.

## Adjustable product limits

| Limit type | App | Default | Hard maximum |
| --- | --- | ---: | ---: |
| `emails_per_day` | `mail` | 20/day | 10,000/day |
| `mail_templates` | `mail` | 20 | 1,000 |
| `mail_webhooks` | `mail` | 10 | 1,000 |
| `hme_aliases` | `hide-my-email` | 100 | 10,000 |
| `verified_resources` | `verify` | 100 | 5,000 |
| `verification_attempts_per_day` | `verify` | 20/day | 500/day |
| `api_keys` | `keys-api` | 50 | 1,000 |

The effective values and current usage are available from
`GET https://keys.api.kitsos.net/v1/me/limits`. Only one pending increase
request per user and limit type, and at most five pending requests in total per
user, are permitted.

## Hard request and data limits

| Area | Hard limit |
| --- | ---: |
| Request URI | 8,192 characters |
| Keys, Verify, HME, and mail metadata request body | 64 KiB |
| Public mail webhook body | 256 KiB |
| Direct mail send body | 4 MiB |
| Email address | 320 characters |
| DNS resource / domain | 253 characters, valid hostname labels required |
| Template source URL | 2,048 characters, HTTPS only |
| Template source response | 3 MiB, 5-second timeout, no redirects |
| Direct HTML body | 3 MiB |
| Direct text body | 3 MiB |
| Complete outbound Brevo payload / rendered template | 4 MiB |
| Mail recipients | 50 per request |
| Mail subject | 998 characters |
| Inbound HME message | 10 MiB |
| Clerk bearer token | 8,192 characters |
| API key or webhook secret | 256 characters before hashing |
| API key name / description | 100 / 2,000 characters |
| API key scopes | 100 scopes, each at most 100 characters |
| Pagination | 500 rows/request, maximum offset 100,000 |
| Utility request URI | 8,192 characters |
| Utility hash input | 16,384 characters |
| Utility DNS upstream response | 64 KiB, 5-second timeout, 100 records per section |

Creation churn is additionally capped at 100 API keys, 100 templates,
100 webhooks, 500 HME aliases, and 10 limit-increase requests per user per UTC
day. HME forwarding is capped at 1,000 messages per alias and 5,000 messages
per user per UTC day. These limits are not overridable.

Expired API keys are removed before counting. Expired verification attempts
and unreferenced resources are cleaned up opportunistically, and revoked API
keys are deleted after their authentication cache entry is invalidated. D1
also enforces rolling per-user retention of 31 days for daily counters,
10,000 audit entries, 1,000 unreferenced verification-history rows, and 1,000
reviewed limit-increase requests. Pending requests and verification rows tied
to active grants are never removed by retention.

## Cloudflare edge limit

The zone currently uses Cloudflare Free. That plan supports one zone rate
limiting rule, counted by source IP, with a 10-second counting and mitigation
window. The recommended rule is:

- expression: API path starts with `/v1/`
- threshold: 30 requests per 10 seconds per source IP
- action: native Cloudflare `block`
- mitigation timeout: 10 seconds

This is an edge/DDoS budget guard, not a replacement for the application
rate limits or the atomic product counters. Before enabling it, inspect current
traffic and the existing `http_ratelimit` ruleset so legitimate webhook bursts
are not blocked. The API token needs `Zone WAF Read` and `Zone WAF Edit` for
the `kitsos.net` zone.
