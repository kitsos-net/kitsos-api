import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dashboardPath = join(here, "dashboards", "kitsos-platform-overview.json");

const axiomDatasource = { type: "axiomhq-axiom-datasource", uid: "kitsos-axiom" };
const analyticsDatasource = {
  type: "yesoreyeram-infinity-datasource",
  uid: "kitsos-analytics-api",
};

const axiomTarget = (refId, apl) => ({
  refId,
  datasource: axiomDatasource,
  apl,
  totals: false,
});

const analyticsTarget = (refId, path, rootSelector, columns) => ({
  refId,
  datasource: analyticsDatasource,
  type: "json",
  source: "url",
  format: "table",
  parser: "backend",
  url: `https://keys.api.kitsos.net${path}`,
  url_options: {
    method: "GET",
    data: "",
  },
  root_selector: rootSelector,
  columns,
  json_options: {
    columnar: false,
    root_is_not_array: rootSelector === "",
  },
});

const baseFieldConfig = {
  defaults: {
    color: { mode: "palette-classic" },
    custom: {},
    mappings: [],
    thresholds: {
      mode: "absolute",
      steps: [
        { color: "green", value: null },
        { color: "red", value: 80 },
      ],
    },
  },
  overrides: [],
};

const panel = (id, title, type, gridPos, targets, options = {}, fieldConfig = baseFieldConfig) => ({
  id,
  title,
  type,
  datasource: targets[0].datasource,
  gridPos,
  targets,
  options,
  fieldConfig,
});

const statOptions = {
  colorMode: "value",
  graphMode: "none",
  justifyMode: "auto",
  orientation: "horizontal",
  reduceOptions: {
    calcs: ["lastNotNull"],
    fields: "",
    values: false,
  },
  textMode: "auto",
  wideLayout: true,
};

const tableOptions = {
  cellHeight: "sm",
  footer: { countRows: false, fields: "", reducer: ["sum"], show: false },
  showHeader: true,
};

const inventoryColumns = [
  ["usersActive", "Active users"],
  ["usersTotal", "Users total"],
  ["appsTotal", "Apps"],
  ["hmeAliasesActive", "Active HME aliases"],
  ["hmeAliasesTotal", "HME aliases total"],
  ["hmeEmailsForwardedTotal", "HME forwarded total"],
  ["verifiedResourcesTotal", "Verified resources"],
  ["mailTemplatesTotal", "Mail templates"],
  ["mailWebhooksTotal", "Mail webhooks"],
].map(([selector, text]) => ({ selector, text, type: "number" }));

const summaryQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), status=toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize requests=count(), successful=countif(status < 400), errors=countif(status >= 400), active_users=dcount(user_id)
| extend success_rate=round(100.0 * todouble(successful) / requests, 2)`;

const eventQuery = (eventName, resultName) => `['api-logs']
| where ['kind'] == "server"
| extend event_name=tostring(['attributes.custom']['kitsos.event.name']), outcome=tostring(['attributes.custom']['kitsos.event.outcome'])
| where event_name == "${eventName}" and outcome == "success"
| summarize ${resultName}=count()`;

const requestTrendQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), api=tostring(['service.name']), status=toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize requests=count() by bin_auto(['_time']), api
| sort by ['_time'] asc`;

const errorTrendQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), api=tostring(['service.name']), status=toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and status >= 400
| summarize errors=count() by bin_auto(['_time']), api
| sort by ['_time'] asc`;

const topUsersQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), status=toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize requests=count(), errors=countif(status >= 400) by user_id
| extend error_rate=round(100.0 * todouble(errors) / requests, 2)
| top 10 by requests`;

const topAppsQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), api=tostring(['service.name']), status=toint(['attributes.http.response.status_code'])
| where isnotempty(user_id) and isnotnull(status)
| summarize requests=count(), errors=countif(status >= 400) by api
| extend error_rate=round(100.0 * todouble(errors) / requests, 2)
| top 10 by requests`;

const errorsQuery = `['api-logs']
| where ['kind'] == "server"
| extend user_id=tostring(['attributes.custom']['kitsos.user.id']), api=tostring(['service.name']), method=tostring(['attributes.http.request.method']), path=tostring(['attributes.url.path']), status=toint(['attributes.http.response.status_code']), error_code=tostring(['attributes.custom']['error.code'])
| where isnotempty(user_id) and status >= 400
| summarize errors=count() by api, method, path, status, error_code, user_id
| top 25 by errors`;

const topUserTarget = (refId, metric) =>
  analyticsTarget(refId, `/v1/analytics/top-users?metric=${metric}&limit=10`, "results", [
    { selector: "userName", text: "User", type: "string" },
    { selector: "value", text: "Value", type: "number" },
  ]);

const dashboard = {
  id: null,
  uid: "kitsos-platform-overview",
  title: "Kitsos Platform Analytics",
  description:
    "Admin dashboard: durable product inventory from the Kitsos Analytics API and time-scoped API usage from Axiom.",
  tags: ["kitsos", "analytics", "admin"],
  timezone: "browser",
  editable: true,
  graphTooltip: 1,
  fiscalYearStartMonth: 0,
  liveNow: false,
  links: [],
  panels: [
    panel(
      1,
      "Current product inventory",
      "stat",
      { h: 4, w: 24, x: 0, y: 0 },
      [analyticsTarget("A", "/v1/analytics/overview", "", inventoryColumns)],
      statOptions,
      {
        ...baseFieldConfig,
        defaults: {
          ...baseFieldConfig.defaults,
          unit: "short",
          min: 0,
        },
      },
    ),
    panel(
      2,
      "Authenticated API usage",
      "stat",
      { h: 4, w: 16, x: 0, y: 4 },
      [axiomTarget("A", summaryQuery)],
      statOptions,
      {
        ...baseFieldConfig,
        defaults: { ...baseFieldConfig.defaults, unit: "short", min: 0 },
        overrides: [
          {
            matcher: { id: "byName", options: "success_rate" },
            properties: [{ id: "unit", value: "percent" }],
          },
        ],
      },
    ),
    panel(
      3,
      "Product events in selected range",
      "stat",
      { h: 4, w: 8, x: 16, y: 4 },
      [
        axiomTarget("A", eventQuery("mail.message.send", "brevo_emails_sent")),
        axiomTarget("B", eventQuery("hme.email.forward", "hme_emails_forwarded")),
      ],
      statOptions,
      {
        ...baseFieldConfig,
        defaults: { ...baseFieldConfig.defaults, unit: "short", min: 0 },
        overrides: [
          {
            matcher: { id: "byName", options: "brevo_emails_sent" },
            properties: [{ id: "displayName", value: "Brevo emails sent" }],
          },
          {
            matcher: { id: "byName", options: "hme_emails_forwarded" },
            properties: [{ id: "displayName", value: "HME emails forwarded" }],
          },
        ],
      },
    ),
    panel(
      4,
      "Authenticated requests by API",
      "timeseries",
      { h: 8, w: 12, x: 0, y: 8 },
      [axiomTarget("A", requestTrendQuery)],
      {
        legend: { calcs: ["sum"], displayMode: "table", placement: "bottom", showLegend: true },
        tooltip: { mode: "multi", sort: "desc" },
      },
      {
        ...baseFieldConfig,
        defaults: {
          ...baseFieldConfig.defaults,
          unit: "short",
          min: 0,
          custom: {
            drawStyle: "line",
            fillOpacity: 18,
            lineInterpolation: "smooth",
            lineWidth: 2,
            pointSize: 4,
            showPoints: "never",
            spanNulls: false,
            stacking: { group: "A", mode: "none" },
          },
        },
      },
    ),
    panel(
      5,
      "Errors by API",
      "timeseries",
      { h: 8, w: 12, x: 12, y: 8 },
      [axiomTarget("A", errorTrendQuery)],
      {
        legend: { calcs: ["sum"], displayMode: "table", placement: "bottom", showLegend: true },
        tooltip: { mode: "multi", sort: "desc" },
      },
      {
        ...baseFieldConfig,
        defaults: {
          ...baseFieldConfig.defaults,
          color: { mode: "continuous-RdYlGr" },
          unit: "short",
          min: 0,
          custom: {
            drawStyle: "bars",
            fillOpacity: 35,
            lineInterpolation: "linear",
            lineWidth: 1,
            pointSize: 4,
            showPoints: "never",
            spanNulls: false,
            stacking: { group: "A", mode: "normal" },
          },
        },
      },
    ),
    panel(
      6,
      "Top users by requests",
      "table",
      { h: 8, w: 8, x: 0, y: 16 },
      [axiomTarget("A", topUsersQuery)],
      tableOptions,
      {
        ...baseFieldConfig,
        overrides: [
          {
            matcher: { id: "byName", options: "error_rate" },
            properties: [{ id: "unit", value: "percent" }],
          },
        ],
      },
    ),
    panel(
      7,
      "Top APIs by requests",
      "table",
      { h: 8, w: 8, x: 8, y: 16 },
      [axiomTarget("A", topAppsQuery)],
      tableOptions,
      {
        ...baseFieldConfig,
        overrides: [
          {
            matcher: { id: "byName", options: "error_rate" },
            properties: [{ id: "unit", value: "percent" }],
          },
        ],
      },
    ),
    panel(
      8,
      "Top users by HME forwarding",
      "table",
      { h: 8, w: 8, x: 16, y: 16 },
      [topUserTarget("A", "hme_emails_forwarded")],
      tableOptions,
      {
        ...baseFieldConfig,
        defaults: { ...baseFieldConfig.defaults, unit: "short", min: 0 },
      },
    ),
    panel(
      9,
      "HME aliases by user",
      "table",
      { h: 8, w: 8, x: 0, y: 24 },
      [topUserTarget("A", "hme_aliases")],
      tableOptions,
    ),
    panel(
      10,
      "Verified resources by user",
      "table",
      { h: 8, w: 8, x: 8, y: 24 },
      [topUserTarget("A", "verified_resources")],
      tableOptions,
    ),
    panel(
      11,
      "Mail templates by user",
      "table",
      { h: 8, w: 8, x: 16, y: 24 },
      [topUserTarget("A", "mail_templates")],
      tableOptions,
    ),
    panel(
      12,
      "Authenticated request errors",
      "table",
      { h: 8, w: 24, x: 0, y: 32 },
      [axiomTarget("A", errorsQuery)],
      tableOptions,
    ),
  ],
  refresh: "5m",
  schemaVersion: 41,
  style: "dark",
  templating: { list: [] },
  time: { from: "now-30d", to: "now" },
  timepicker: {
    refresh_intervals: ["1m", "5m", "15m", "30m", "1h"],
    time_options: ["6h", "24h", "7d", "30d", "90d", "1y"],
  },
  version: 1,
  weekStart: "monday",
};

const panelDescriptions = {
  1: "Current D1-backed state. These values are not affected by the dashboard time range.",
  2: "Authenticated server requests in the selected time range. Anonymous requests and health checks are excluded.",
  3: "Successful semantic product events captured in Axiom during the selected time range.",
  4: "Authenticated requests grouped by Kitsos Worker service and automatic time buckets.",
  5: "HTTP responses with status 400 or higher, grouped by Kitsos Worker service.",
  6: "Top authenticated users in the selected time range. User IDs are intentionally used instead of personal data.",
  7: "Top Kitsos Worker services by authenticated request count in the selected time range.",
  8: "Cumulative forwarded-email counters stored on HME aliases, grouped by owner.",
  9: "Current HME alias inventory grouped by owner.",
  10: "Currently valid verified resources grouped by owner.",
  11: "Current mail template inventory grouped by owner.",
  12: "Most frequent authenticated HTTP errors in the selected time range.",
};

for (const item of dashboard.panels) item.description = panelDescriptions[item.id];

mkdirSync(dirname(dashboardPath), { recursive: true });
writeFileSync(dashboardPath, `${JSON.stringify(dashboard, null, 2)}\n`);
console.log(dashboardPath);
