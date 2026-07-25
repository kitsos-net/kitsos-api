# API usage statistics in Axiom

Every authenticated HTTP request produces one fully sampled OpenTelemetry
server span in the dataset configured through `AXIOM_DATASET`. The span
contains:

| Axiom field | Meaning |
| --- | --- |
| `service.name` | Kitsos API (`mail`, `verify`, `keys-api`, `utility`, …) |
| `attributes.custom["kitsos.user.id"]` | Internal Clerk user ID |
| `attributes.custom["kitsos.auth.method"]` | `api_key` or `session` |
| `attributes.custom["kitsos.api_key.id"]` | Internal key ID, if used |
| `attributes.custom["kitsos.request.scope"]` | Scope checked for the request |
| `attributes.http.response.status_code` | Final HTTP response status |
| `attributes.http.request.method` | HTTP method |
| `attributes.url.path` | Request path |

No email address, raw API key, authorization header, or request body is added
to telemetry.

Replace `YOUR_AXIOM_DATASET` in the queries below with the value of
`AXIOM_DATASET`.

## Requests, successes, and errors per user and API

```apl
['YOUR_AXIOM_DATASET']
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

In Axiom, run the first query and choose **More → Add to dashboard**. Add the
daily query as a stacked time-series chart and the endpoint query as a table.
Use dashboard filters for `user_id` and `api`. Axiom's existing OpenTelemetry
Traces dashboard remains useful for opening the underlying traces.

The counts are not sampled: telemetry explicitly uses a `1.0` head-sampling
ratio. As with any external telemetry system, requests can only be counted
after Axiom successfully receives their spans.
