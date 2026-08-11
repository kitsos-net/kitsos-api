# Kitsos API logging in Axiom EU

Every HTTP request, including unauthenticated, rejected, rate-limited and
not-found requests, produces one fully sampled OpenTelemetry server span in
Axiom EU through `https://eu-central-1.aws.edge.axiom.co/v1/traces`. Request
completion is represented by the root span; meaningful application and
decision events are added to its `events` array. The dataset is configured
through `AXIOM_DATASET` and should be `api-logs`. `AXIOM_TRACES_URL` is only
needed when the organization deliberately uses a different Axiom edge.

| Axiom field | Meaning |
| --- | --- |
| `service.name` | Kitsos API (`mail`, `verify`, `keys-api`, `utility`, …) |
| `attributes.url.path` | Sanitized path without query string, UUIDs or tokens |
| `attributes.custom["kitsos.telemetry.schema_version"]` | Telemetry contract version; currently `3` |
| `attributes.custom["kitsos.request.outcome"]` | Final HTTP outcome such as `success`, `rate_limited`, or `server_error` |
| `attributes.custom["kitsos.request.reason"]` | Stable final HTTP reason |
| `attributes.custom["kitsos.user.id"]` | Internal Clerk user ID |
| `attributes.custom["kitsos.auth.method"]` | `anonymous`, `bearer`, `api_key`, `session`, or `mcp` |
| `attributes.custom["kitsos.api_key.used"]` | Whether a Kitsos API key was presented |
| `attributes.custom["kitsos.api_key.id"]` | Internal key ID, if used |
| `attributes.custom["kitsos.request.scope"]` | Scope checked for the request |
| `attributes.custom["cloudflare.ray_id"]` | Cloudflare Ray ID for support correlation |
| `attributes.custom["cloudflare.colo"]` | Cloudflare data center |
| `attributes.custom["client.country"]` | Country code supplied by Cloudflare |
| `attributes.custom["client.asn"]` | ASN supplied by Cloudflare |
| `attributes.http.response.status_code` | Final HTTP response status |
| `attributes.http.request.method` | HTTP method |
| `duration` | End-to-end Worker duration |
| `attributes.faas.coldstart` | Whether Cloudflare started a fresh isolate |

Anonymous and session requests have `kitsos.api_key.used = false`. Presented
Kitsos keys have `kitsos.api_key.used = true`; valid keys additionally contain
`kitsos.api_key.id`. Invalid keys contain only a 16-character SHA-256
fingerprint in their `auth.decision` event so repeated attempts can be
correlated. No email address, raw API key, full API-key hash, authorization
header, confirmation token, webhook secret, request body, query string,
cookie, or full URL is added to telemetry.
Authenticated requests to the MCP endpoint use `service.name = "mcp"` and
carry the same user and authentication dimensions as the other API workers.

## Semantic events

Events are stored only in the span's `events` array so their data is not
duplicated on the root span. Current event names include:

- `auth.decision`, `resource.authorization`, `usage.decision`,
  `rate_limit.decision`
- `hme.alias.create`, `hme.alias.update`, `hme.alias.delete`
- `mail.message.send`, `mail.webhook.deliver`,
  and template/webhook create, update, and delete events
- `verify.resource.create`, `verify.resource.delete`,
  `verify.domain.check`, `verify.email.confirm`
- `keys.api_key.create`, `keys.api_key.revoke`,
  `keys.limit_request.create`, `keys.limit_request.approve`,
  `keys.limit_request.deny`
- `mcp.tool.call`, with the exact name in `kitsos.mcp.tool.name`, the upstream
  service and its HTTP status

Event fields use internal user, key, resource, and verification IDs. Failure
events have a stable `event.reason` and a sanitized `error.message` where
useful.

### Failures by event, user, and key

```apl
['YOUR_AXIOM_DATASET']
| where ['attributes.custom']['kitsos.telemetry.schema_version'] == 3
| mv-expand events
| extend
    event_name = tostring(events.name),
    outcome = tostring(events.attributes['event.outcome']),
    reason = tostring(events.attributes['event.reason']),
    user_id = tostring(events.attributes['kitsos.user.id']),
    api_key_id = tostring(events.attributes['kitsos.api_key.id'])
| where outcome in ("denied", "rate_limited", "error")
| summarize failures = count() by event_name, reason, user_id, api_key_id
| sort by failures desc
```

Replace `YOUR_AXIOM_DATASET` in the queries below with `api-logs`.

## Requests, successes, and errors per user and API

```apl
['YOUR_AXIOM_DATASET']
| where ['kind'] == "server"
| extend
    user_id = tostring(['attributes.custom']['kitsos.user.id']),
    api = tostring(['service.name']),
    status = toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize
    requests = count(),
    successful = countif(status < 400),
    errors = countif(status >= 400)
  by user_id, api
| extend success_rate = todouble(successful) / requests
| sort by requests desc
```

For a dashboard table, format `success_rate` as a percentage.

## Daily request trend

```apl
['YOUR_AXIOM_DATASET']
| where ['kind'] == "server"
| extend
    user_id = tostring(['attributes.custom']['kitsos.user.id']),
    api = tostring(['service.name']),
    status = toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize
    requests = count(),
    successful = countif(status < 400),
    errors = countif(status >= 400)
  by api, user_id, _time = bin(_time, 1d)
| sort by _time asc
```

## Endpoint and status breakdown

```apl
['YOUR_AXIOM_DATASET']
| where ['kind'] == "server"
| extend
    user_id = tostring(['attributes.custom']['kitsos.user.id']),
    api = tostring(['service.name']),
    method = tostring(['attributes.http.request.method']),
    path = tostring(['attributes.url.path']),
    status = toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize requests = count() by user_id, api, method, path, status
| sort by requests desc
```

## Errors only

```apl
['YOUR_AXIOM_DATASET']
| where ['kind'] == "server"
| extend
    user_id = tostring(['attributes.custom']['kitsos.user.id']),
    api = tostring(['service.name']),
    method = tostring(['attributes.http.request.method']),
    path = tostring(['attributes.url.path']),
    status = toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and status >= 400
| summarize errors = count() by user_id, api, method, path, status
| sort by errors desc
```

## Axiom dashboard

The shared Axiom dashboards are:

- **API Logs & Diagnostics**, stable UID `api-logs-diagnostics`, for request
  health, errors, latency, sources, structured events and privacy checks.
- **API Security & Limit Logs**, stable UID `api-security-limit-logs`, for
  authentication, authorization, user/key IDs, rate limits and usage limits.

Product and inventory statistics belong in Grafana.

The counts are not sampled: telemetry explicitly uses a `1.0` head-sampling
ratio. As with any external telemetry system, requests can only be counted
after Axiom successfully receives their spans.
