import { Hono } from "hono";
import { cors } from "hono/cors";
import { sha256Hex } from "@kitsos/auth";
import type { ApiKeyResourceGrant } from "@kitsos/auth";
import { recordEvent, withTelemetry } from "@kitsos/telemetry";
import { requireAdmin, requireUser } from "./middleware";
import analytics from "./analytics";
import type { Env } from "./env";

type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>();
const MAX_SELF_SERVICE_KEY_TTL_SECONDS = 300;
const PLATFORM_USAGE_DEFAULTS: Record<string, Array<[string, number]>> = {
  mail: [["emails_per_day", 20], ["webhooks", 10]],
  "hide-my-email": [["aliases", 25]],
  verify: [["verified_resources", 20]],
};

app.use("*", cors({
  origin: "*",
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

function id() {
  return crypto.randomUUID();
}

// ============================================================
// Admin routes — /admin/*
// ============================================================
const admin = new Hono<{ Bindings: Env; Variables: Vars }>();
admin.use("*", requireAdmin);

// --- Apps ---
admin.get("/apps", async (c) => {
  const r = await c.env.DB.prepare("SELECT * FROM apps ORDER BY name").all();
  return c.json(r.results);
});

admin.post("/apps", async (c) => {
  const body = await c.req.json<{ id: string; name: string; description?: string; environment?: string }>();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO apps (id, name, description, environment) VALUES (?, ?, ?, ?)"
    ).bind(body.id, body.name, body.description ?? null, body.environment ?? "production"),
    ...(PLATFORM_USAGE_DEFAULTS[body.id] ?? []).map(([limitType, limitValue]) => c.env.DB.prepare(
      "INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value) VALUES (?, ?, ?)"
    ).bind(body.id, limitType, limitValue)),
  ]);
  return c.json({ id: body.id }, 201);
});

admin.delete("/apps/:appId", async (c) => {
  await c.env.DB.prepare("DELETE FROM apps WHERE id = ?").bind(c.req.param("appId")).run();
  return c.body(null, 204);
});

admin.post("/apps/:appId/scopes", async (c) => {
  const appId = c.req.param("appId");
  const body = await c.req.json<{ scope: string; description?: string }>();
  await c.env.DB.prepare(
    "INSERT INTO app_scopes (app_id, scope, description) VALUES (?, ?, ?)"
  )
    .bind(appId, body.scope, body.description ?? null)
    .run();
  return c.json({ appId, scope: body.scope }, 201);
});

admin.delete("/apps/:appId/scopes/:scope", async (c) => {
  await c.env.DB.prepare("DELETE FROM app_scopes WHERE app_id = ? AND scope = ?")
    .bind(c.req.param("appId"), c.req.param("scope"))
    .run();
  return c.body(null, 204);
});

// --- Users ---
admin.get("/users", async (c) => {
  const r = await c.env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  return c.json(r.results);
});

admin.patch("/users/:userId", async (c) => {
  const body = await c.req.json<{ status: string }>();
  await c.env.DB.prepare("UPDATE users SET status = ? WHERE id = ?")
    .bind(body.status, c.req.param("userId"))
    .run();
  return c.body(null, 204);
});

// --- Groups ---
admin.get("/groups", async (c) => {
  const r = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all();
  return c.json(r.results);
});

admin.post("/groups", async (c) => {
  const body = await c.req.json<{ name: string; description?: string }>();
  const groupId = id();
  await c.env.DB.prepare("INSERT INTO groups (id, name, description) VALUES (?, ?, ?)")
    .bind(groupId, body.name, body.description ?? null)
    .run();
  return c.json({ id: groupId }, 201);
});

admin.delete("/groups/:groupId", async (c) => {
  await c.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(c.req.param("groupId")).run();
  return c.body(null, 204);
});

admin.post("/groups/:groupId/members", async (c) => {
  const body = await c.req.json<{ userId: string }>();
  await c.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)")
    .bind(c.req.param("groupId"), body.userId)
    .run();
  return c.body(null, 204);
});

admin.delete("/groups/:groupId/members/:userId", async (c) => {
  await c.env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
    .bind(c.req.param("groupId"), c.req.param("userId"))
    .run();
  return c.body(null, 204);
});

// --- Policies ---
admin.get("/policies", async (c) => {
  const appId = c.req.query("appId");
  const r = appId
    ? await c.env.DB.prepare("SELECT * FROM policies WHERE app_id = ?").bind(appId).all()
    : await c.env.DB.prepare("SELECT * FROM policies").all();
  return c.json(r.results);
});

admin.post("/policies", async (c) => {
  const body = await c.req.json<{
    appId: string;
    subjectType: "user" | "group";
    subjectId: string;
    scopes: string[];
  }>();
  const policyId = id();
  await c.env.DB.prepare(
    "INSERT INTO policies (id, app_id, subject_type, subject_id, scopes) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(policyId, body.appId, body.subjectType, body.subjectId, JSON.stringify(body.scopes))
    .run();
  return c.json({ id: policyId }, 201);
});

admin.delete("/policies/:policyId", async (c) => {
  await c.env.DB.prepare("DELETE FROM policies WHERE id = ?").bind(c.req.param("policyId")).run();
  return c.body(null, 204);
});

// --- API Keys (admin: manage any user's keys) ---
admin.get("/api-keys", async (c) => {
  const userId = c.req.query("userId");
  const r = userId
    ? await c.env.DB
        .prepare("SELECT id, user_id, app_id, name, status, scopes, expires_at, last_used_at, created_at, (SELECT json_group_array(app_id) FROM api_key_apps WHERE api_key_id = api_keys.id) AS app_ids FROM api_keys WHERE user_id = ?")
        .bind(userId)
        .all()
    : await c.env.DB
        .prepare("SELECT id, user_id, app_id, name, status, scopes, expires_at, last_used_at, created_at, (SELECT json_group_array(app_id) FROM api_key_apps WHERE api_key_id = api_keys.id) AS app_ids FROM api_keys")
        .all();
  return c.json(r.results); // never returns key_hash / raw key
});

admin.post("/api-keys", async (c) => {
  const body = await c.req.json<{
    userId: string;
    appId?: string; // legacy single-app input
    appIds?: string[];
    name?: string;
    scopes: string[];
    expiresAt?: number;
    resourceGrants?: ApiKeyResourceGrant[];
  }>();
  const appIds = [...new Set(body.appIds ?? (body.appId ? [body.appId] : []))];
  if (appIds.length === 0) return c.json({ error: "missing-app-ids" }, 400);

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const keyId = id();

  await c.env.DB.batch([
    c.env.DB.prepare(
    `INSERT INTO api_keys (id, key_hash, user_id, app_id, name, status, scopes, expires_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
  )
    .bind(keyId, keyHash, body.userId, appIds[0], body.name ?? null, JSON.stringify(body.scopes), body.expiresAt ?? null),
    ...appIds.map((appId) => c.env.DB.prepare(
      "INSERT INTO api_key_apps (api_key_id, app_id) VALUES (?, ?)"
    ).bind(keyId, appId)),
    ...(body.resourceGrants ?? []).map((grant) => c.env.DB.prepare(
      "INSERT INTO api_key_resource_grants (api_key_id, resource_type, resource_id, scopes) VALUES (?, ?, ?, ?)"
    ).bind(keyId, grant.resourceType, grant.resourceId, JSON.stringify(grant.scopes ?? []))),
  ]);

  recordEvent("keys.api_key.create", "success", {
    "kitsos.user.id": body.userId,
    "kitsos.api_key.id": keyId,
    "actor.user.id": c.get("userId"),
    "api_key.app_count": appIds.length,
    "api_key.scope_count": body.scopes.length,
  });
  // rawKey is only ever shown here — not recoverable afterwards
  return c.json({ id: keyId, key: rawKey, appIds, resourceGrants: body.resourceGrants ?? [] }, 201);
});

admin.delete("/api-keys/:keyId", async (c) => {
  const keyId = c.req.param("keyId");
  await c.env.DB.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ?")
    .bind(keyId)
    .run();
  recordEvent("keys.api_key.revoke", "success", {
    "kitsos.api_key.id": keyId,
    "actor.user.id": c.get("userId"),
  });
  return c.body(null, 204);
});

// --- Usage limits ---
admin.get("/usage-limits", async (c) => {
  const userId = c.req.query("userId");
  const r = userId
    ? await c.env.DB.prepare("SELECT * FROM usage_limits WHERE user_id = ?").bind(userId).all()
    : await c.env.DB.prepare("SELECT * FROM usage_limits").all();
  return c.json(r.results);
});

admin.post("/usage-limits", async (c) => {
  const body = await c.req.json<{
    userId: string;
    appId: string;
    limitType: string;
    limitValue: number;
    isOverride?: boolean;
  }>();
  const limitId = id();
  await c.env.DB.prepare(
    "INSERT INTO usage_limits (id, user_id, app_id, limit_type, limit_value, is_override) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(limitId, body.userId, body.appId, body.limitType, body.limitValue, body.isOverride ? 1 : 0)
    .run();
  return c.json({ id: limitId }, 201);
});

admin.get("/usage-limit-defaults", async (c) => {
  const r = await c.env.DB.prepare("SELECT * FROM usage_limit_defaults ORDER BY app_id, limit_type").all();
  return c.json(r.results);
});

admin.put("/usage-limit-defaults", async (c) => {
  const body = await c.req.json<{ appId: string; limitType: string; limitValue: number }>();
  if (!Number.isInteger(body.limitValue) || body.limitValue < 0) return c.json({ error: "invalid-limit-value" }, 400);
  await c.env.DB.prepare(
    `INSERT INTO usage_limit_defaults (app_id, limit_type, limit_value) VALUES (?, ?, ?)
     ON CONFLICT(app_id, limit_type) DO UPDATE SET limit_value = excluded.limit_value`
  ).bind(body.appId, body.limitType, body.limitValue).run();
  return c.body(null, 204);
});

// --- Limit increase requests (admin review) ---
admin.get("/limit-increase-requests", async (c) => {
  const status = c.req.query("status") ?? "pending";
  const r = await c.env.DB.prepare("SELECT * FROM limit_increase_requests WHERE status = ? ORDER BY created_at")
    .bind(status)
    .all();
  return c.json(r.results);
});

admin.post("/limit-increase-requests/:reqId/approve", async (c) => {
  const reqId = c.req.param("reqId");
  const adminId = c.get("userId");

  const req = await c.env.DB.prepare("SELECT * FROM limit_increase_requests WHERE id = ?")
    .bind(reqId)
    .first<{ user_id: string; app_id: string; limit_type: string; requested_value: number }>();
  if (!req) return c.json({ error: "not-found" }, 404);

  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE limit_increase_requests SET status = 'approved', reviewed_by = ?, reviewed_at = unixepoch() WHERE id = ?"
    ).bind(adminId, reqId),
    c.env.DB.prepare(
      "INSERT INTO usage_limits (id, user_id, app_id, limit_type, limit_value, is_override) VALUES (?, ?, ?, ?, ?, 1)"
    ).bind(id(), req.user_id, req.app_id, req.limit_type, req.requested_value),
  ]);

  recordEvent("keys.limit_request.approve", "success", {
    "actor.user.id": adminId,
    "kitsos.user.id": req.user_id,
    "kitsos.resource.id": reqId,
    "kitsos.app.id": req.app_id,
    "limit.type": req.limit_type,
    "limit.value": req.requested_value,
  });
  return c.body(null, 204);
});

admin.post("/limit-increase-requests/:reqId/deny", async (c) => {
  const adminId = c.get("userId");
  const reqId = c.req.param("reqId");
  await c.env.DB.prepare(
    "UPDATE limit_increase_requests SET status = 'denied', reviewed_by = ?, reviewed_at = unixepoch() WHERE id = ?"
  )
    .bind(adminId, reqId)
    .run();
  recordEvent("keys.limit_request.deny", "success", {
    "actor.user.id": adminId,
    "kitsos.resource.id": reqId,
  });
  return c.body(null, 204);
});

// --- Audit log ---
admin.get("/audit-log", async (c) => {
  const userId = c.req.query("userId");
  const limit = Math.min(Number(c.req.query("limit") ?? 100), 500);
  const r = userId
    ? await c.env.DB
        .prepare("SELECT * FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?")
        .bind(userId, limit)
        .all()
    : await c.env.DB.prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?").bind(limit).all();
  return c.json(r.results);
});

app.route("/admin", admin);

// ============================================================
// Self-service routes — /me/*
// ============================================================
const me = new Hono<{ Bindings: Env; Variables: Vars }>();
me.use("*", requireUser);

me.get("/", async (c) => {
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(c.get("userId")).first();
  return c.json(user);
});

me.get("/api-keys", async (c) => {
  const r = await c.env.DB
    .prepare("SELECT id, app_id, name, status, scopes, expires_at, last_used_at, created_at, (SELECT json_group_array(app_id) FROM api_key_apps WHERE api_key_id = api_keys.id) AS app_ids FROM api_keys WHERE user_id = ?")
    .bind(c.get("userId"))
    .all();
  return c.json(r.results);
});

// Users may only create keys with scopes their own policy already grants.
me.post("/api-keys", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{
    appId?: string; // legacy single-app input
    appIds?: string[];
    name?: string;
    scopes: string[];
    expiresAt?: number;
    resourceGrants?: ApiKeyResourceGrant[];
  }>();
  const appIds = [...new Set(body.appIds ?? (body.appId ? [body.appId] : []))];
  if (appIds.length === 0) return c.json({ error: "missing-app-ids" }, 400);

  const now = Math.floor(Date.now() / 1000);
  if (
    body.expiresAt !== undefined &&
    (!Number.isInteger(body.expiresAt) ||
      body.expiresAt <= now ||
      body.expiresAt > now + MAX_SELF_SERVICE_KEY_TTL_SECONDS)
  ) {
    return c.json({ error: "invalid-expires-at", maxTtlSeconds: MAX_SELF_SERVICE_KEY_TTL_SECONDS }, 400);
  }

  const groupRows = await c.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?")
    .bind(userId)
    .all<{ group_id: string }>();
  const groupIds = groupRows.results.map((g) => g.group_id);

  const policyRows = await c.env.DB
    .prepare(
      `SELECT scopes FROM policies WHERE app_id IN (${appIds.map(() => "?").join(",")}) AND (
         (subject_type = 'user' AND subject_id = ?) OR
         (subject_type = 'group' AND subject_id IN (${groupIds.map(() => "?").join(",") || "''"}))
       )`
    )
    .bind(...appIds, userId, ...groupIds)
    .all<{ scopes: string }>();

  const allowedScopes = new Set<string>(policyRows.results.flatMap((p) => JSON.parse(p.scopes) as string[]));
  const requestedScopes = body.scopes.filter((s) => allowedScopes.has(s));

  if (requestedScopes.length === 0) {
    return c.json({ error: "no-allowed-scopes" }, 403);
  }

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const keyId = id();

  await c.env.DB.batch([
    c.env.DB.prepare(
    "INSERT INTO api_keys (id, key_hash, user_id, app_id, name, status, scopes, expires_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)"
  )
    .bind(
      keyId,
      keyHash,
      userId,
      appIds[0],
      body.name ?? null,
      JSON.stringify(requestedScopes),
      body.expiresAt ?? null
    ),
    ...appIds.map((appId) => c.env.DB.prepare(
      "INSERT INTO api_key_apps (api_key_id, app_id) VALUES (?, ?)"
    ).bind(keyId, appId)),
    ...(body.resourceGrants ?? []).map((grant) => c.env.DB.prepare(
      "INSERT INTO api_key_resource_grants (api_key_id, resource_type, resource_id, scopes) VALUES (?, ?, ?, ?)"
    ).bind(keyId, grant.resourceType, grant.resourceId, JSON.stringify(grant.scopes ?? []))),
  ]);

  recordEvent("keys.api_key.create", "success", {
    "kitsos.user.id": userId,
    "kitsos.api_key.id": keyId,
    "api_key.app_count": appIds.length,
    "api_key.scope_count": requestedScopes.length,
  });
  return c.json({ id: keyId, key: rawKey, appIds, scopes: requestedScopes, resourceGrants: body.resourceGrants ?? [], expiresAt: body.expiresAt ?? null }, 201);
});

me.delete("/api-keys/:keyId", async (c) => {
  const keyId = c.req.param("keyId");
  await c.env.DB.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ? AND user_id = ?")
    .bind(keyId, c.get("userId"))
    .run();
  recordEvent("keys.api_key.revoke", "success", {
    "kitsos.user.id": c.get("userId"),
    "kitsos.api_key.id": keyId,
  });
  return c.body(null, 204);
});

me.get("/limit-increase-requests", async (c) => {
  const r = await c.env.DB
    .prepare("SELECT * FROM limit_increase_requests WHERE user_id = ? ORDER BY created_at DESC")
    .bind(c.get("userId"))
    .all();
  return c.json(r.results);
});

me.post("/limit-increase-requests", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{ appId: string; limitType: string; requestedValue: number; reason?: string }>();
  const reqId = id();
  await c.env.DB.prepare(
    "INSERT INTO limit_increase_requests (id, user_id, app_id, limit_type, requested_value, reason) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(reqId, userId, body.appId, body.limitType, body.requestedValue, body.reason ?? null)
    .run();
  recordEvent("keys.limit_request.create", "success", {
    "kitsos.user.id": userId,
    "kitsos.resource.id": reqId,
    "kitsos.app.id": body.appId,
    "limit.type": body.limitType,
    "limit.value": body.requestedValue,
  });
  return c.json({ id: reqId }, 201);
});

app.route("/me", me);
app.route("/analytics", analytics);

app.get("/health", (c) => c.json({ ok: true }));

export default withTelemetry(app, "keys-api");
