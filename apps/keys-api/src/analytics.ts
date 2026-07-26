import { Hono } from "hono";
import { authenticateApiKey } from "@kitsos/auth";
import type { Env } from "./env";

type Vars = { userId: string };
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 10;
const MAX_RANGE_SECONDS = 366 * 86400;

function limit(value: string | undefined): number {
  const parsed = Number(value ?? DEFAULT_LIMIT);
  if (!Number.isInteger(parsed) || parsed < 1) return DEFAULT_LIMIT;
  return Math.min(parsed, MAX_LIMIT);
}

function unixTime(value: string | undefined, fallback: number): number | null {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

const analytics = new Hono<{ Bindings: Env; Variables: Vars }>();

analytics.use("*", async (c, next) => {
  const auth = await authenticateApiKey(c.req.raw, c.env, "analytics:read", "analytics", {
    windowSeconds: 60,
    maxRequests: 120,
  });
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  c.set("userId", auth.context!.userId);
  await next();
});

/** Current entity counts. These are state metrics, not event counters. */
analytics.get("/overview", async (c) => {
  const results = await c.env.DB.batch([
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM users"),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM users WHERE status = 'active'"),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM apps WHERE id != 'analytics'"),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM hme_aliases"),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM hme_aliases WHERE status = 'active'"),
    c.env.DB.prepare("SELECT COALESCE(SUM(emails_forwarded), 0) AS value FROM hme_aliases"),
    c.env.DB.prepare(
      "SELECT COUNT(DISTINCT resource_id) AS value FROM resource_verifications WHERE verified_at IS NOT NULL AND (grace_expires_at IS NULL OR grace_expires_at >= unixepoch())"
    ),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM mail_templates"),
    c.env.DB.prepare("SELECT COUNT(*) AS value FROM mail_webhooks"),
  ]);
  const value = (index: number) => Number((results[index].results[0] as { value: number }).value);

  return c.json({
    usersTotal: value(0),
    usersActive: value(1),
    appsTotal: value(2),
    hmeAliasesTotal: value(3),
    hmeAliasesActive: value(4),
    hmeEmailsForwardedTotal: value(5),
    verifiedResourcesTotal: value(6),
    mailTemplatesTotal: value(7),
    mailWebhooksTotal: value(8),
  });
});

/** Rankings by durable product state or authenticated API calls. */
analytics.get("/top-users", async (c) => {
  const metric = c.req.query("metric") ?? "api_calls";
  const top = limit(c.req.query("limit"));
  const queries: Record<string, string> = {
    api_calls: `SELECT a.user_id AS userId, COALESCE(u.display_name, a.user_id) AS userName, COUNT(*) AS value
      FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
      WHERE a.result = 'allowed' AND a.action != 'analytics:read'
      GROUP BY a.user_id ORDER BY value DESC, userName ASC LIMIT ?`,
    hme_aliases: `SELECT h.user_id AS userId, COALESCE(u.display_name, h.user_id) AS userName, COUNT(*) AS value
      FROM hme_aliases h LEFT JOIN users u ON u.id = h.user_id
      GROUP BY h.user_id ORDER BY value DESC, userName ASC LIMIT ?`,
    hme_emails_forwarded: `SELECT h.user_id AS userId, COALESCE(u.display_name, h.user_id) AS userName, SUM(h.emails_forwarded) AS value
      FROM hme_aliases h LEFT JOIN users u ON u.id = h.user_id
      GROUP BY h.user_id ORDER BY value DESC, userName ASC LIMIT ?`,
    mail_templates: `SELECT m.user_id AS userId, COALESCE(u.display_name, m.user_id) AS userName, COUNT(*) AS value
      FROM mail_templates m LEFT JOIN users u ON u.id = m.user_id
      GROUP BY m.user_id ORDER BY value DESC, userName ASC LIMIT ?`,
    verified_resources: `SELECT rv.user_id AS userId, COALESCE(u.display_name, rv.user_id) AS userName, COUNT(DISTINCT rv.resource_id) AS value
      FROM resource_verifications rv LEFT JOIN users u ON u.id = rv.user_id
      WHERE rv.verified_at IS NOT NULL AND (rv.grace_expires_at IS NULL OR rv.grace_expires_at >= unixepoch())
      GROUP BY rv.user_id ORDER BY value DESC, userName ASC LIMIT ?`,
  };
  const query = queries[metric];
  if (!query) return c.json({ error: "invalid-metric", allowed: Object.keys(queries) }, 400);
  const rows = await c.env.DB.prepare(query).bind(top).all();
  return c.json({ metric, results: rows.results });
});

analytics.get("/top-apps", async (c) => {
  const top = limit(c.req.query("limit"));
  const rows = await c.env.DB.prepare(
    `SELECT a.app_id AS appId, COALESCE(p.name, a.app_id) AS appName, COUNT(*) AS value
     FROM audit_log a LEFT JOIN apps p ON p.id = a.app_id
     WHERE a.result = 'allowed' AND a.action != 'analytics:read'
     GROUP BY a.app_id ORDER BY value DESC, appName ASC LIMIT ?`
  ).bind(top).all();
  return c.json({ results: rows.results });
});

/** Daily authenticated request counts for Grafana time-series panels. */
analytics.get("/api-calls", async (c) => {
  const now = Math.floor(Date.now() / 1000);
  const from = unixTime(c.req.query("from"), now - 30 * 86400);
  const to = unixTime(c.req.query("to"), now);
  const groupBy = c.req.query("groupBy") ?? "app";
  if (from === null || to === null || from > to || to - from > MAX_RANGE_SECONDS) {
    return c.json({ error: "invalid-time-range" }, 400);
  }
  if (groupBy !== "app" && groupBy !== "user") return c.json({ error: "invalid-group-by", allowed: ["app", "user"] }, 400);

  const dimension = groupBy === "app" ? "a.app_id" : "a.user_id";
  const name = groupBy === "app" ? "COALESCE(p.name, a.app_id)" : "COALESCE(u.display_name, a.user_id)";
  const join = groupBy === "app" ? "LEFT JOIN apps p ON p.id = a.app_id" : "LEFT JOIN users u ON u.id = a.user_id";
  const rows = await c.env.DB.prepare(
    `SELECT datetime(a.created_at, 'unixepoch', 'start of day') AS time,
            ${dimension} AS dimension, ${name} AS name, COUNT(*) AS value
     FROM audit_log a ${join}
     WHERE a.result = 'allowed' AND a.action != 'analytics:read' AND a.created_at >= ? AND a.created_at <= ?
     GROUP BY time, dimension, name ORDER BY time ASC, value DESC`
  ).bind(from, to).all();
  return c.json({ from, to, groupBy, results: rows.results });
});

export default analytics;
