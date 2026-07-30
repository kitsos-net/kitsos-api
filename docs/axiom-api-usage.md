# API usage statistics in Axiom

Every authenticated HTTP request produces one fully sampled OpenTelemetry
server span in the dataset configured through `AXIOM_DATASET`. The span
contains:

| Axiom field | Meaning |
| --- | --- |
| `service.name` | Kitsos API (`mail`, `verify`, `keys-api`, `utility`, …) |
| `attributes.custom["kitsos.user.id"]` | Internal Clerk user ID |
| `attributes.custom["kitsos.auth.method"]` | `api_key`, `session`, or `mcp` |
| `attributes.custom["kitsos.api_key.id"]` | Internal key ID, if used |
| `attributes.custom["kitsos.request.scope"]` | Scope checked for the request |
| `attributes.custom["kitsos.event.name"]` | Last semantic event on the request |
| `attributes.custom["kitsos.event.outcome"]` | `success`, `allowed`, `denied`, `error`, or `noop` |
| `attributes.custom["error.code"]` | Stable machine-readable failure reason |
| `attributes.http.response.status_code` | Final HTTP response status |
| `attributes.http.request.method` | HTTP method |
| `attributes.url.path` | Request path |

Valid API-key requests contain `kitsos.api_key.id`. Invalid keys contain only
a 16-character SHA-256 fingerprint so repeated attempts can be correlated.
No email address, raw API key, full API-key hash, authorization header,
confirmation token, webhook secret, or request body is added to telemetry.
Authenticated requests to the MCP endpoint use `service.name = "mcp"` and
carry the same user and authentication dimensions as the other API workers.

## Semantic events

Events are stored both in the span's `events` array and, for simple filtering,
as the latest `kitsos.event.*` attributes. Current event names include:

- `auth.decision`, `resource.authorization`, `usage.decision`
- `hme.alias.create`, `hme.alias.update`, `hme.alias.delete`,
  `hme.email.forward`
- `mail.message.send`, `mail.verification.send`, `mail.webhook.deliver`,
  and template/webhook create, update, and delete events
- `verify.resource.create`, `verify.resource.delete`,
  `verify.domain.check`, `verify.domain.recheck`, `verify.email.confirm`
- `keys.api_key.create`, `keys.api_key.revoke`,
  `keys.limit_request.create`, `keys.limit_request.approve`,
  `keys.limit_request.deny`

Event fields use internal user, key, resource, and verification IDs. Failure
events have a stable `error.code` and a sanitized `error.message` where useful.

### Failures by event, user, and key

```apl
['YOUR_AXIOM_DATASET']
| where ['kind'] == "server"
| extend
    event_name = tostring(['attributes.custom']['kitsos.event.name']),
    outcome = tostring(['attributes.custom']['kitsos.event.outcome']),
    error_code = tostring(['attributes.custom']['error.code']),
    user_id = tostring(['attributes.custom']['kitsos.user.id']),
    api_key_id = tostring(['attributes.custom']['kitsos.api_key.id'])
| where outcome == "denied" or outcome == "error"
| summarize failures = count() by event_name, error_code, user_id, api_key_id
| sort by failures desc
```

Replace `YOUR_AXIOM_DATASET` in the queries below with the value of
`AXIOM_DATASET`.

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

The shared Axiom dashboard **API Usage by User** has the stable UID
`api-usage-by-user`. It contains headline request, success, error, and active
user statistics; API and outcome trends; and per-user/API and endpoint tables.
Axiom's existing OpenTelemetry Traces dashboard remains useful for opening the
underlying traces.

The counts are not sampled: telemetry explicitly uses a `1.0` head-sampling
ratio. As with any external telemetry system, requests can only be counted
after Axiom successfully receives their spans.
