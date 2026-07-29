# Kitsos Grafana dashboard

This directory contains a provisioned Grafana dashboard for product analytics
and API usage.

## Data ownership

- **Axiom (`api-logs`)** supplies time-scoped request counts, top APIs, top
  users, error trends, Brevo sends, and HME forwarding events.
- **Kitsos Analytics API** supplies durable D1-backed inventory and per-user
  ownership totals.
- Grafana does **not** connect directly to D1. This keeps database credentials
  and the database schema outside Grafana.

All usage panels exclude anonymous requests and health checks by requiring
`kitsos.user.id`. Inventory values are current state and therefore do not
change when the Grafana time range changes.

## Required plugins

- `axiomhq-axiom-datasource`
- `yesoreyeram-infinity-datasource`

Install the plugins using the deployment method supported by your Grafana
environment.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `KITSOS_ANALYTICS_API_KEY` | Admin-owned Kitsos key limited to app `analytics` and scope `analytics:read` |
| `AXIOM_GRAFANA_TOKEN` | Read-only Axiom token that can query `api-logs` |
| `AXIOM_ORG_ID` | Axiom organization ID |
| `AXIOM_EDGE_URL` | Axiom query edge URL, for example the organization region's HTTPS edge URL |

Do not commit any of these values. Grafana resolves them while provisioning
the data sources and stores secure values encrypted.

## Provision

1. Generate and validate the dashboard JSON:

   ```sh
   node ops/grafana/generate-dashboard.mjs
   node ops/grafana/validate-dashboard.mjs
   ```

2. Mount or copy:

   - `provisioning/datasources/kitsos.yaml` into Grafana's
     `provisioning/datasources` directory.
   - `provisioning/dashboards/kitsos.yaml` into Grafana's
     `provisioning/dashboards` directory.
   - `dashboards/kitsos-platform-overview.json` to
     `/var/lib/grafana/dashboards/kitsos/kitsos-platform-overview.json`.

3. Restart Grafana or wait for its provisioning poll.

The stable dashboard UID is `kitsos-platform-overview`. Grafana refreshes the
dashboard every five minutes and opens with a 30-day range.

## Security model

The Analytics API data source sends its key only from the Grafana server-side
proxy. The key must belong to an active member of the configured admin group;
the API rejects non-admin owners even when the key has the correct scope.
Datasource editing is disabled so dashboard viewers cannot change the target
host or reveal provisioned credentials.

Grafana permissions still need to restrict the `Kitsos` folder to the intended
admin team. API authorization is the final enforcement layer, not a substitute
for Grafana folder access control.
