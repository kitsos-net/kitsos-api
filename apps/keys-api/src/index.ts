import { Hono } from "hono";
import { WorkerEntrypoint } from "cloudflare:workers";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import {
  consumeHardDailyLimit,
  getEffectiveLimit,
  getPolicyScopes,
  invalidateApiKeyCache,
  invalidateAppApiKeyCaches,
  invalidateGroupApiKeyCaches,
  invalidateUserApiKeyCaches,
  LIMIT_DEFINITIONS,
  isValidLimitConfiguration,
  sha256Hex,
  acceptPrivateMcpDelegation,
  ensureUserRow,
  verifyClerkSession,
  writeAuditLog,
} from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import { requireAdmin, requireUser } from "./middleware";
import analytics from "./analytics";
import { boundedLimit, boundedOffset, isNonEmptyString, isStringArray } from "./validation";
import type { Env } from "./env";

type Vars = { userId: string };
type KeyPermission = { appId: string; scopes: string[] };
const CONSOLE_SESSION_APPS = new Set(["mail", "hide-my-email", "verify", "utility"]);
const CONSOLE_SESSION_KEY_NAME = "API Console session";
const CONSOLE_SESSION_KEY_DESCRIPTION = "Five-minute key issued by apidev.kitsos.net";
const CONSOLE_SESSION_KEY_TTL_SECONDS = 5 * 60;
const app = new Hono<{ Bindings: Env; Variables: Vars }>().basePath("/v1");

app.use("*", async (c, next) => {
  if (c.req.url.length > 8192) return c.json({ error: "uri-too-long" }, 414);
  await next();
});
app.use("*", bodyLimit({
  maxSize: 64 * 1024,
  onError: (c) => c.json({ error: "request-body-too-large" }, 413),
}));
app.use("*", cors({
  origin: (origin, c) => {
    const configured = (c.env as Env).CORS_ORIGINS
      ?? "https://apidev.kitsos.net,https://myaccount.kitsos.net";
    const allowedOrigins = configured.split(",").map((item) => item.trim());
    allowedOrigins.push("https://docs.api.kitsos.net");
    return allowedOrigins.includes(origin) ? origin : null;
  },
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

function id() {
  return crypto.randomUUID();
}

function pagination(c: { req: { query(name: string): string | undefined } }) {
  const limit = boundedLimit(c.req.query("limit"));
  const offset = boundedOffset(c.req.query("offset"));
  return limit === null || offset === null ? null : { limit, offset };
}

function decodeJsonFields(
  rows: Record<string, unknown>[],
  fields: string[]
): Record<string, unknown>[] {
  return rows.map((row) => {
    const decoded = { ...row };
    for (const field of fields) {
      if (typeof decoded[field] === "string") {
        try {
          decoded[field] = JSON.parse(decoded[field] as string);
        } catch {
          decoded[field] = [];
        }
      }
    }
    return decoded;
  });
}

async function prepareApiKeyCreation(env: Env, userId: string): Promise<number | null> {
  await env.DB.prepare(
    "DELETE FROM api_keys WHERE user_id = ? AND expires_at IS NOT NULL AND expires_at <= unixepoch()"
  )
    .bind(userId)
    .run();
  const withinHardCreationLimit = await consumeHardDailyLimit(
    env,
    userId,
    "keys-api",
    "api_key_creations_per_day",
    100
  );
  if (!withinHardCreationLimit) return null;
  return getEffectiveLimit(env, userId, "api_keys");
}

function normalizeKeyPermissions(body: {
  appId?: unknown;
  scopes?: unknown;
  permissions?: unknown;
}): KeyPermission[] | null {
  const hasLegacy = body.appId !== undefined || body.scopes !== undefined;
  const hasCanonical = body.permissions !== undefined;
  if (hasLegacy === hasCanonical) return null;
  const raw = hasCanonical
    ? body.permissions
    : [{ appId: body.appId, scopes: body.scopes }];
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > 20) return null;
  const seenApps = new Set<string>();
  const permissions: KeyPermission[] = [];
  for (const item of raw) {
    if (
      !item
      || typeof item !== "object"
      || !isNonEmptyString((item as { appId?: unknown }).appId, 63)
      || !isStringArray((item as { scopes?: unknown }).scopes)
    ) {
      return null;
    }
    const appId = (item as { appId: string }).appId;
    if (seenApps.has(appId)) return null;
    seenApps.add(appId);
    permissions.push({
      appId,
      scopes: [...new Set((item as { scopes: string[] }).scopes)],
    });
  }
  return permissions;
}

async function validateCatalogPermissions(
  env: Env,
  permissions: KeyPermission[],
): Promise<boolean> {
  for (const permission of permissions) {
    const placeholders = permission.scopes.map(() => "?").join(",");
    const result = await env.DB.prepare(
      `SELECT COUNT(*) AS count FROM app_scopes
       WHERE app_id = ? AND scope IN (${placeholders})`
    )
      .bind(permission.appId, ...permission.scopes)
      .first<{ count: number }>();
    if (result?.count !== permission.scopes.length) return false;
  }
  return true;
}

async function insertKeyPermissions(
  env: Env,
  keyId: string,
  permissions: KeyPermission[],
): Promise<void> {
  await env.DB.batch(permissions.map((permission) =>
    env.DB.prepare(
      "INSERT INTO api_key_apps (api_key_id, app_id, scopes) VALUES (?, ?, ?)"
    ).bind(keyId, permission.appId, JSON.stringify(permission.scopes))
  ));
}

async function rotateApiKey(
  env: Env,
  keyId: string,
  ownerId?: string,
): Promise<
  | { ok: true; id: string; key: string; permissions: KeyPermission[]; expiresAt?: number }
  | { ok: false; reason: "not-found" | "creation-limit" | "conflict" }
> {
  const ownerClause = ownerId ? "AND k.user_id = ?" : "";
  const oldKey = await env.DB.prepare(
    `SELECT k.user_id, k.expires_at
     FROM api_keys k
     WHERE k.id = ? ${ownerClause}
       AND k.status = 'active'
       AND (k.expires_at IS NULL OR k.expires_at > unixepoch())`
  )
    .bind(keyId, ...(ownerId ? [ownerId] : []))
    .first<{ user_id: string; expires_at: number | null }>();
  if (!oldKey) return { ok: false, reason: "not-found" };

  const permissionRows = await env.DB.prepare(
    `SELECT app_id, scopes
     FROM api_key_apps
     WHERE api_key_id = ?
     ORDER BY app_id`
  )
    .bind(keyId)
    .all<{ app_id: string; scopes: string }>();
  if (permissionRows.results.length === 0) {
    return { ok: false, reason: "conflict" };
  }
  const permissions = permissionRows.results.map((row) => ({
    appId: row.app_id,
    scopes: JSON.parse(row.scopes) as string[],
  }));

  // Rotation creates new secret material, so it shares the non-overridable
  // daily churn budget with normal key creation. It is a one-for-one
  // replacement and therefore cannot bypass the stored-key product limit.
  const withinHardCreationLimit = await consumeHardDailyLimit(
    env,
    oldKey.user_id,
    "keys-api",
    "api_key_creations_per_day",
    100
  );
  if (!withinHardCreationLimit) return { ok: false, reason: "creation-limit" };

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const replacementId = id();
  const statements = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO api_keys
         (id, key_hash, user_id, app_id, name, description, status, scopes,
          expires_at, auto_roll_at)
       SELECT ?, ?, user_id, app_id, name, description, 'active', scopes,
              expires_at, auto_roll_at
       FROM api_keys
       WHERE id = ? ${ownerId ? "AND user_id = ?" : ""}
         AND status = 'active'
         AND (expires_at IS NULL OR expires_at > unixepoch())`
    ).bind(replacementId, keyHash, keyId, ...(ownerId ? [ownerId] : [])),
    env.DB.prepare(
      `INSERT INTO api_key_apps (api_key_id, app_id, scopes)
       SELECT ?, a.app_id, a.scopes
       FROM api_key_apps a
       JOIN api_keys old_key ON old_key.id = a.api_key_id
       JOIN api_keys replacement ON replacement.id = ?
       WHERE a.api_key_id = ? AND old_key.status = 'active'`
    ).bind(replacementId, replacementId, keyId),
    env.DB.prepare(
      `UPDATE api_keys
       SET status = 'revoked'
       WHERE id = ? ${ownerId ? "AND user_id = ?" : ""}
         AND status = 'active'
         AND EXISTS (SELECT 1 FROM api_keys WHERE id = ?)`
    ).bind(keyId, ...(ownerId ? [ownerId] : []), replacementId),
  ]);
  if (statements[0].meta.changes !== 1 || statements[2].meta.changes !== 1) {
    return { ok: false, reason: "conflict" };
  }

  // Cached requests independently re-check D1 status, so failures in the
  // optional KV cleanup cannot make the revoked credential usable or prevent
  // the one-time raw replacement key from being returned.
  await invalidateApiKeyCache(env, keyId).catch(() => {});
  await env.DB.prepare("DELETE FROM api_keys WHERE id = ? AND status = 'revoked'")
    .bind(keyId)
    .run()
    .catch(() => {});
  return {
    ok: true,
    id: replacementId,
    key: rawKey,
    permissions,
    ...(oldKey.expires_at ? { expiresAt: oldKey.expires_at } : {}),
  };
}

async function getConsoleSessionPermissions(
  env: Env,
  userId: string,
  appIds: string[],
): Promise<KeyPermission[] | null> {
  const permissions: KeyPermission[] = [];
  for (const appId of appIds) {
    const policy = await getPolicyScopes(env, userId, appId);
    if (!policy) return null;
    const catalog = await env.DB.prepare(
      "SELECT scope FROM app_scopes WHERE app_id = ? ORDER BY scope"
    )
      .bind(appId)
      .all<{ scope: string }>();
    const allowedScopes = new Set(policy.scopes);
    const scopes = catalog.results
      .map((row) => row.scope)
      .filter((scope) => allowedScopes.has(scope));
    if (scopes.length === 0) return null;
    permissions.push({ appId, scopes });
  }
  return permissions;
}

async function serializeApiKeys(
  env: Env,
  rows: Record<string, unknown>[],
): Promise<Record<string, unknown>[]> {
  if (rows.length === 0) return [];
  const ids = rows.map((row) => String(row.id));
  const grants = await env.DB.prepare(
    `SELECT api_key_id, app_id, scopes FROM api_key_apps
     WHERE api_key_id IN (${ids.map(() => "?").join(",")})
     ORDER BY app_id`
  )
    .bind(...ids)
    .all<{ api_key_id: string; app_id: string; scopes: string }>();
  const byKey = new Map<string, KeyPermission[]>();
  for (const grant of grants.results) {
    const permissions = byKey.get(grant.api_key_id) ?? [];
    permissions.push({
      appId: grant.app_id,
      scopes: JSON.parse(grant.scopes) as string[],
    });
    byKey.set(grant.api_key_id, permissions);
  }
  return rows.map((row) => {
    const permissions = byKey.get(String(row.id)) ?? [];
    const { app_id: _appId, scopes: _scopes, ...rest } = row;
    return {
      ...rest,
      permissions,
      ...(permissions.length === 1 ? {
        appId: permissions[0].appId,
        scopes: permissions[0].scopes,
      } : {}),
    };
  });
}

// ============================================================
// Admin routes — /admin/*
// ============================================================
const admin = new Hono<{ Bindings: Env; Variables: Vars }>();
admin.use("*", requireAdmin);

// --- Apps ---
admin.get("/apps", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare("SELECT * FROM apps ORDER BY name, id LIMIT ? OFFSET ?")
    .bind(page.limit, page.offset)
    .all();
  return c.json(r.results);
});

admin.post("/apps", async (c) => {
  const body = await c.req.json<{ id: string; name: string; description?: string; environment?: string }>().catch(() => null);
  if (
    !body
    || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(body.id)
    || !isNonEmptyString(body.name, 100)
    || (body.description !== undefined && (
      typeof body.description !== "string" || body.description.length > 2_000
    ))
    || (body.environment !== undefined && !["production", "staging", "dev"].includes(body.environment))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  await c.env.DB.prepare(
    "INSERT INTO apps (id, name, description, environment) VALUES (?, ?, ?, ?)"
  )
    .bind(body.id, body.name, body.description ?? null, body.environment ?? "production")
    .run();
  return c.json({ id: body.id }, 201);
});

admin.delete("/apps/:appId", async (c) => {
  const appId = c.req.param("appId");
  const dependencies = await c.env.DB.batch([
    c.env.DB.prepare("SELECT 1 FROM app_scopes WHERE app_id = ? LIMIT 1").bind(appId),
    c.env.DB.prepare("SELECT 1 FROM policies WHERE app_id = ? LIMIT 1").bind(appId),
    c.env.DB.prepare("SELECT 1 FROM api_key_apps WHERE app_id = ? LIMIT 1").bind(appId),
    c.env.DB.prepare("SELECT 1 FROM resources WHERE app_id = ? LIMIT 1").bind(appId),
  ]);
  if (dependencies.some((result) => result.results.length > 0)) {
    return c.json({ error: "app-has-dependencies" }, 409);
  }
  await c.env.DB.prepare("DELETE FROM apps WHERE id = ?").bind(appId).run();
  return c.body(null, 204);
});

admin.post("/apps/:appId/scopes", async (c) => {
  const appId = c.req.param("appId");
  const body = await c.req.json<{ scope: string; description?: string }>().catch(() => null);
  if (
    !body
    || typeof body.scope !== "string"
    || body.scope.length > 100
    || !/^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/.test(body.scope)
    || (body.description !== undefined && (
      typeof body.description !== "string" || body.description.length > 2_000
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  await c.env.DB.prepare(
    "INSERT INTO app_scopes (app_id, scope, description) VALUES (?, ?, ?)"
  )
    .bind(appId, body.scope, body.description ?? null)
    .run();
  return c.json({ appId, scope: body.scope }, 201);
});

admin.delete("/apps/:appId/scopes/:scope", async (c) => {
  const appId = c.req.param("appId");
  await c.env.DB.prepare("DELETE FROM app_scopes WHERE app_id = ? AND scope = ?")
    .bind(appId, c.req.param("scope"))
    .run();
  await invalidateAppApiKeyCaches(c.env, appId);
  return c.body(null, 204);
});

// --- Users ---
admin.get("/users", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
    .bind(page.limit, page.offset)
    .all();
  return c.json(r.results);
});

admin.patch("/users/:userId", async (c) => {
  const body = await c.req.json<{ status: string }>().catch(() => null);
  if (!body || !["active", "deactivated", "pending_deletion", "deleted"].includes(body.status)) {
    return c.json({ error: "invalid-status" }, 400);
  }
  await c.env.DB.prepare("UPDATE users SET status = ? WHERE id = ?")
    .bind(body.status, c.req.param("userId"))
    .run();
  await invalidateUserApiKeyCaches(c.env, c.req.param("userId"));
  return c.body(null, 204);
});

// --- Groups ---
admin.get("/groups", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name, id LIMIT ? OFFSET ?")
    .bind(page.limit, page.offset)
    .all();
  return c.json(r.results);
});

admin.post("/groups", async (c) => {
  const body = await c.req.json<{ name: string; description?: string }>().catch(() => null);
  if (
    !body
    || !isNonEmptyString(body.name, 100)
    || (body.description !== undefined && (
      typeof body.description !== "string" || body.description.length > 2_000
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const groupId = id();
  await c.env.DB.prepare("INSERT INTO groups (id, name, description) VALUES (?, ?, ?)")
    .bind(groupId, body.name, body.description ?? null)
    .run();
  return c.json({ id: groupId }, 201);
});

admin.delete("/groups/:groupId", async (c) => {
  const groupId = c.req.param("groupId");
  const dependencies = await c.env.DB.batch([
    c.env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? LIMIT 1").bind(groupId),
    c.env.DB.prepare(
      "SELECT 1 FROM policies WHERE subject_type = 'group' AND subject_id = ? LIMIT 1"
    ).bind(groupId),
  ]);
  if (dependencies.some((result) => result.results.length > 0)) {
    return c.json({ error: "group-has-dependencies" }, 409);
  }
  await c.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(groupId).run();
  return c.body(null, 204);
});

admin.post("/groups/:groupId/members", async (c) => {
  const body = await c.req.json<{ userId: string }>().catch(() => null);
  if (!body || !isNonEmptyString(body.userId, 100)) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  await c.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)")
    .bind(c.req.param("groupId"), body.userId)
    .run();
  await invalidateUserApiKeyCaches(c.env, body.userId);
  return c.body(null, 204);
});

admin.delete("/groups/:groupId/members/:userId", async (c) => {
  await c.env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
    .bind(c.req.param("groupId"), c.req.param("userId"))
    .run();
  await invalidateUserApiKeyCaches(c.env, c.req.param("userId"));
  return c.body(null, 204);
});

// --- Policies ---
admin.get("/policies", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const appId = c.req.query("appId");
  const r = appId
    ? await c.env.DB.prepare(
        "SELECT * FROM policies WHERE app_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
      ).bind(appId, page.limit, page.offset).all()
    : await c.env.DB.prepare(
        "SELECT * FROM policies ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
      ).bind(page.limit, page.offset).all();
  return c.json(decodeJsonFields(r.results, ["scopes"]));
});

admin.post("/policies", async (c) => {
  const body = await c.req.json<{
    appId: string;
    subjectType: "user" | "group";
    subjectId: string;
    scopes: string[];
  }>().catch(() => null);
  if (
    !body
    || !isNonEmptyString(body.appId, 63)
    || !["user", "group"].includes(body.subjectType)
    || !isNonEmptyString(body.subjectId, 100)
    || !isStringArray(body.scopes)
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const uniqueScopes = [...new Set(body.scopes)];
  const subjectTable = body.subjectType === "user" ? "users" : "groups";
  const subject = await c.env.DB.prepare(`SELECT 1 FROM ${subjectTable} WHERE id = ?`)
    .bind(body.subjectId)
    .first();
  if (!subject) return c.json({ error: "subject-not-found" }, 404);
  const validScopes = await c.env.DB.prepare(
    `SELECT COUNT(*) AS count FROM app_scopes
     WHERE app_id = ? AND scope IN (${uniqueScopes.map(() => "?").join(",")})`
  )
    .bind(body.appId, ...uniqueScopes)
    .first<{ count: number }>();
  if (validScopes?.count !== uniqueScopes.length) return c.json({ error: "invalid-scopes" }, 400);
  const policyId = id();
  await c.env.DB.prepare(
    "INSERT INTO policies (id, app_id, subject_type, subject_id, scopes) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(policyId, body.appId, body.subjectType, body.subjectId, JSON.stringify(uniqueScopes))
    .run();
  if (body.subjectType === "user") {
    await invalidateUserApiKeyCaches(c.env, body.subjectId, body.appId);
  } else {
    await invalidateGroupApiKeyCaches(c.env, body.subjectId, body.appId);
  }
  return c.json({ id: policyId }, 201);
});

admin.delete("/policies/:policyId", async (c) => {
  const policy = await c.env.DB.prepare(
    "SELECT app_id, subject_type, subject_id FROM policies WHERE id = ?"
  )
    .bind(c.req.param("policyId"))
    .first<{ app_id: string; subject_type: string; subject_id: string }>();
  if (!policy) return c.json({ error: "not-found" }, 404);
  await c.env.DB.prepare("DELETE FROM policies WHERE id = ?").bind(c.req.param("policyId")).run();
  if (policy.subject_type === "user") {
    await invalidateUserApiKeyCaches(c.env, policy.subject_id, policy.app_id);
  } else {
    await invalidateGroupApiKeyCaches(c.env, policy.subject_id, policy.app_id);
  }
  return c.body(null, 204);
});

// --- API Keys (admin: manage any user's keys) ---
admin.get("/api-keys", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const userId = c.req.query("userId");
  const r = userId
    ? await c.env.DB
        .prepare("SELECT id, user_id, app_id, name, description, status, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(userId, page.limit, page.offset)
        .all()
    : await c.env.DB
        .prepare("SELECT id, user_id, app_id, name, description, status, scopes, expires_at, last_used_at, created_at FROM api_keys ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(page.limit, page.offset)
        .all();
  return c.json(await serializeApiKeys(c.env, r.results)); // never returns key_hash / raw key
});

admin.post("/api-keys", async (c) => {
  const body = await c.req.json<{
    userId: string;
    appId?: string;
    name?: string;
    description?: string;
    scopes?: string[];
    permissions?: KeyPermission[];
    expiresAt?: number;
  }>().catch(() => null);
  const permissions = body ? normalizeKeyPermissions(body) : null;
  if (
    !body
    || !isNonEmptyString(body.userId, 100)
    || !permissions
    || (body.name !== undefined && !isNonEmptyString(body.name, 100))
    || (body.description !== undefined && (
      typeof body.description !== "string" || body.description.length > 2_000
    ))
    || (body.expiresAt !== undefined && (
      !Number.isSafeInteger(body.expiresAt)
      || body.expiresAt <= Date.now() / 1000
      || body.expiresAt > Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 60 * 60
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const user = await c.env.DB.prepare("SELECT 1 FROM users WHERE id = ?")
    .bind(body.userId)
    .first();
  if (!user) return c.json({ error: "user-not-found" }, 404);
  if (!(await validateCatalogPermissions(c.env, permissions))) {
    return c.json({ error: "invalid-scopes" }, 400);
  }

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const keyId = id();
  const apiKeyLimit = await prepareApiKeyCreation(c.env, body.userId);
  if (apiKeyLimit === null) {
    return c.json({ error: "api-key-creation-abuse-limit-exceeded" }, 429);
  }

  const created = await c.env.DB.prepare(
    `INSERT INTO api_keys
       (id, key_hash, user_id, app_id, name, description, status, scopes, expires_at)
     SELECT ?, ?, ?, ?, ?, ?, 'active', ?, ?
     WHERE (
       SELECT COUNT(*) FROM api_keys WHERE user_id = ?
     ) < ?`
  )
    .bind(
      keyId,
      keyHash,
      body.userId,
      permissions[0].appId,
      body.name ?? null,
      body.description ?? null,
      JSON.stringify(permissions.flatMap((permission) => permission.scopes)),
      body.expiresAt ?? null,
      body.userId,
      apiKeyLimit
    )
    .run();
  if (created.meta.changes !== 1) {
    return c.json({ error: "api-key-limit-exceeded", limit: apiKeyLimit }, 429);
  }
  try {
    await insertKeyPermissions(c.env, keyId, permissions);
  } catch (error) {
    await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ?").bind(keyId).run();
    throw error;
  }

  // rawKey is only ever shown here — not recoverable afterwards
  return c.json({ id: keyId, key: rawKey, permissions }, 201);
});

admin.delete("/api-keys/:keyId", async (c) => {
  await invalidateApiKeyCache(c.env, c.req.param("keyId"));
  await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ?")
    .bind(c.req.param("keyId"))
    .run();
  return c.body(null, 204);
});

admin.post("/api-keys/:keyId/rotate", async (c) => {
  const keyId = c.req.param("keyId");
  const result = await rotateApiKey(c.env, keyId);
  if (!result.ok) {
    if (result.reason === "not-found") return c.json({ error: "not-found" }, 404);
    if (result.reason === "creation-limit") {
      return c.json({ error: "api-key-creation-abuse-limit-exceeded" }, 429);
    }
    return c.json({ error: "api-key-rotation-conflict" }, 409);
  }
  await writeAuditLog(c.env, {
    userId: c.get("userId"),
    appId: "keys-api",
    apiKeyId: result.id,
    action: "api_key.rotate.admin",
    result: "allowed",
    reason: `replaced:${keyId}`,
  });
  return c.json(result, 201);
});

// --- Usage limits ---
admin.get("/usage-limits", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const userId = c.req.query("userId");
  const r = userId
    ? await c.env.DB.prepare("SELECT * FROM usage_limits WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(userId, page.limit, page.offset).all()
    : await c.env.DB.prepare("SELECT * FROM usage_limits ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(page.limit, page.offset).all();
  return c.json(r.results.map((row) => ({
    ...row,
    is_override: Boolean((row as { is_override: number }).is_override),
  })));
});

admin.post("/usage-limits", async (c) => {
  const body = await c.req.json<{
    userId: string;
    appId: string;
    limitType: string;
    limitValue: number;
    isOverride?: boolean;
  }>().catch(() => null);
  if (
    !body
    || !isNonEmptyString(body.userId, 100)
    || !isNonEmptyString(body.appId, 63)
    || !isNonEmptyString(body.limitType, 100)
    || !isValidLimitConfiguration(body.appId, body.limitType, body.limitValue)
    || (body.isOverride !== undefined && typeof body.isOverride !== "boolean")
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const ownerAndApp = await c.env.DB.batch([
    c.env.DB.prepare("SELECT 1 FROM users WHERE id = ?").bind(body.userId),
    c.env.DB.prepare("SELECT 1 FROM apps WHERE id = ?").bind(body.appId),
  ]);
  if (ownerAndApp.some((result) => result.results.length === 0)) {
    return c.json({ error: "user-or-app-not-found" }, 404);
  }
  const limitId = id();
  await c.env.DB.prepare(
    `INSERT INTO usage_limits (id, user_id, app_id, limit_type, limit_value, is_override)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, app_id, limit_type, is_override) DO UPDATE SET
       limit_value = excluded.limit_value,
       created_at = unixepoch()`
  )
    .bind(limitId, body.userId, body.appId, body.limitType, body.limitValue, body.isOverride ? 1 : 0)
    .run();
  return c.json({ id: limitId }, 201);
});

// --- Limit increase requests (admin review) ---
admin.get("/limit-increase-requests", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const status = c.req.query("status") ?? "pending";
  if (!["pending", "approved", "denied"].includes(status)) {
    return c.json({ error: "invalid-status" }, 400);
  }
  const r = await c.env.DB.prepare(
    "SELECT * FROM limit_increase_requests WHERE status = ? ORDER BY created_at, id LIMIT ? OFFSET ?"
  )
    .bind(status, page.limit, page.offset)
    .all();
  return c.json(r.results);
});

admin.post("/limit-increase-requests/:reqId/approve", async (c) => {
  const reqId = c.req.param("reqId");
  const adminId = c.get("userId");

  const req = await c.env.DB.prepare("SELECT * FROM limit_increase_requests WHERE id = ?")
    .bind(reqId)
    .first<{ user_id: string; app_id: string; limit_type: string; requested_value: number; status: string }>();
  if (!req) return c.json({ error: "not-found" }, 404);
  if (req.status !== "pending") return c.json({ error: "request-already-reviewed" }, 409);
  if (!isValidLimitConfiguration(req.app_id, req.limit_type, req.requested_value)) {
    return c.json({ error: "invalid-limit-request" }, 400);
  }

  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO usage_limits (id, user_id, app_id, limit_type, limit_value, is_override)
       SELECT ?, user_id, app_id, limit_type, requested_value, 1
       FROM limit_increase_requests WHERE id = ? AND status = 'pending'
       ON CONFLICT(user_id, app_id, limit_type, is_override) DO UPDATE SET
         limit_value = excluded.limit_value,
         created_at = unixepoch()`
    ).bind(id(), reqId),
    c.env.DB.prepare(
      `UPDATE limit_increase_requests
       SET status = 'approved', reviewed_by = ?, reviewed_at = unixepoch()
       WHERE id = ? AND status = 'pending'`
    ).bind(adminId, reqId),
  ]);

  return c.body(null, 204);
});

admin.post("/limit-increase-requests/:reqId/deny", async (c) => {
  const adminId = c.get("userId");
  const result = await c.env.DB.prepare(
    `UPDATE limit_increase_requests
     SET status = 'denied', reviewed_by = ?, reviewed_at = unixepoch()
     WHERE id = ? AND status = 'pending'`
  )
    .bind(adminId, c.req.param("reqId"))
    .run();
  if (result.meta.changes !== 1) return c.json({ error: "not-found-or-already-reviewed" }, 409);
  return c.body(null, 204);
});

// --- Audit log ---
admin.get("/audit-log", async (c) => {
  const userId = c.req.query("userId");
  const limit = boundedLimit(c.req.query("limit"));
  const offset = boundedOffset(c.req.query("offset"));
  if (limit === null || offset === null) return c.json({ error: "invalid-pagination" }, 400);
  const r = userId
    ? await c.env.DB
        .prepare("SELECT * FROM audit_log WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(userId, limit, offset)
        .all()
    : await c.env.DB.prepare("SELECT * FROM audit_log ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        .bind(limit, offset).all();
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

me.get("/limits", async (c) => {
  const userId = c.get("userId");
  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const counts = await c.env.DB.batch([
    c.env.DB.prepare(
      `SELECT count FROM daily_usage_counters
       WHERE user_id = ? AND app_id = 'mail'
         AND limit_type = 'emails_per_day' AND day_bucket = ?`
    ).bind(userId, dayBucket),
    c.env.DB.prepare("SELECT COUNT(*) AS count FROM mail_templates WHERE user_id = ?").bind(userId),
    c.env.DB.prepare("SELECT COUNT(*) AS count FROM mail_webhooks WHERE user_id = ?").bind(userId),
    c.env.DB.prepare("SELECT COUNT(*) AS count FROM hme_aliases WHERE user_id = ?").bind(userId),
    c.env.DB.prepare("SELECT COUNT(*) AS count FROM resource_grants WHERE user_id = ?").bind(userId),
    c.env.DB.prepare(
      `SELECT count FROM daily_usage_counters
       WHERE user_id = ? AND app_id = 'verify'
         AND limit_type = 'verification_attempts_per_day' AND day_bucket = ?`
    ).bind(userId, dayBucket),
    c.env.DB.prepare(
      `SELECT COUNT(*) AS count FROM api_keys
       WHERE user_id = ? AND status = 'active'
         AND (expires_at IS NULL OR expires_at > unixepoch())`
    ).bind(userId),
    c.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM mcp_connections WHERE user_id = ?"
    ).bind(userId),
  ]);
  const limitTypes = Object.keys(LIMIT_DEFINITIONS) as Array<keyof typeof LIMIT_DEFINITIONS>;
  const effectiveLimits = await Promise.all(
    limitTypes.map((limitType) => getEffectiveLimit(c.env, userId, limitType))
  );
  return c.json(limitTypes.map((limitType, index) => {
    const definition = LIMIT_DEFINITIONS[limitType];
    const current = Number(
      (counts[index].results[0] as { count?: number } | undefined)?.count ?? 0
    );
    return {
      appId: definition.appId,
      limitType,
      limitValue: effectiveLimits[index],
      currentValue: current,
      remaining: Math.max(0, effectiveLimits[index] - current),
      maximumValue: definition.maximumValue,
      daily: definition.daily,
    };
  }));
});

me.post("/session-api-key", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{ appIds?: unknown }>().catch(() => null);
  if (
    !body
    || !Array.isArray(body.appIds)
    || body.appIds.length < 1
    || body.appIds.length > CONSOLE_SESSION_APPS.size
    || !body.appIds.every((appId) =>
      isNonEmptyString(appId, 63) && CONSOLE_SESSION_APPS.has(appId)
    )
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const appIds = [...new Set(body.appIds as string[])];
  if (appIds.length !== body.appIds.length) {
    return c.json({ error: "duplicate-app-id" }, 400);
  }

  const permissions = await getConsoleSessionPermissions(c.env, userId, appIds);
  if (!permissions) {
    return c.json({
      error: "scope-not-allowed",
      message: "At least one selected app has no scopes granted by your policy.",
    }, 403);
  }

  const apiKeyLimit = await prepareApiKeyCreation(c.env, userId);
  if (apiKeyLimit === null) {
    return c.json({ error: "api-key-creation-abuse-limit-exceeded" }, 429);
  }

  const previousKeys = await c.env.DB.prepare(
    `SELECT id FROM api_keys
     WHERE user_id = ? AND name = ? AND description = ?
       AND expires_at IS NOT NULL`
  )
    .bind(userId, CONSOLE_SESSION_KEY_NAME, CONSOLE_SESSION_KEY_DESCRIPTION)
    .all<{ id: string }>();
  await Promise.all(previousKeys.results.map((key) =>
    invalidateApiKeyCache(c.env, key.id)
  ));
  await c.env.DB.prepare(
    `DELETE FROM api_keys
     WHERE user_id = ? AND name = ? AND description = ?
       AND expires_at IS NOT NULL`
  )
    .bind(userId, CONSOLE_SESSION_KEY_NAME, CONSOLE_SESSION_KEY_DESCRIPTION)
    .run();

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const keyId = id();
  const expiresAt = Math.floor(Date.now() / 1000) + CONSOLE_SESSION_KEY_TTL_SECONDS;
  const created = await c.env.DB.prepare(
    `INSERT INTO api_keys
       (id, key_hash, user_id, app_id, name, description, status, scopes, expires_at)
     SELECT ?, ?, ?, ?, ?, ?, 'active', ?, ?
     WHERE (
       SELECT COUNT(*) FROM api_keys WHERE user_id = ?
     ) < ?`
  )
    .bind(
      keyId,
      keyHash,
      userId,
      permissions[0].appId,
      CONSOLE_SESSION_KEY_NAME,
      CONSOLE_SESSION_KEY_DESCRIPTION,
      JSON.stringify(permissions.flatMap((permission) => permission.scopes)),
      expiresAt,
      userId,
      apiKeyLimit,
    )
    .run();
  if (created.meta.changes !== 1) {
    return c.json({ error: "api-key-limit-exceeded", limit: apiKeyLimit }, 429);
  }
  try {
    await insertKeyPermissions(c.env, keyId, permissions);
  } catch (error) {
    await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ?").bind(keyId).run();
    throw error;
  }
  await writeAuditLog(c.env, {
    userId,
    appId: "keys-api",
    apiKeyId: keyId,
    action: "session_api_key.create",
    result: "allowed",
  });
  return c.json({ id: keyId, key: rawKey, permissions, expiresAt }, 201);
});

me.get("/api-keys", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB
    .prepare("SELECT id, app_id, name, description, status, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
    .bind(c.get("userId"), page.limit, page.offset)
    .all();
  return c.json(await serializeApiKeys(c.env, r.results));
});

// Users may only create keys with scopes their own policy already grants.
me.post("/api-keys", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{
    appId?: string;
    name?: string;
    description?: string;
    scopes?: string[];
    permissions?: KeyPermission[];
  }>().catch(() => null);
  const permissions = body ? normalizeKeyPermissions(body) : null;
  if (
    !body
    || !permissions
    || (body.name !== undefined && !isNonEmptyString(body.name, 100))
    || (body.description !== undefined && (
      typeof body.description !== "string" || body.description.length > 2_000
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }

  if (!(await validateCatalogPermissions(c.env, permissions))) {
    return c.json({ error: "invalid-scopes" }, 400);
  }
  for (const permission of permissions) {
    const policy = await getPolicyScopes(c.env, userId, permission.appId);
    const allowedScopes = new Set(policy?.scopes ?? []);
    if (permission.scopes.some((scope) => !allowedScopes.has(scope))) {
      return c.json({ error: "scope-not-allowed", appId: permission.appId }, 403);
    }
  }

  const rawKey = `kitsos_${crypto.randomUUID().replace(/-/g, "")}`;
  const keyHash = await sha256Hex(rawKey);
  const keyId = id();
  const apiKeyLimit = await prepareApiKeyCreation(c.env, userId);
  if (apiKeyLimit === null) {
    return c.json({ error: "api-key-creation-abuse-limit-exceeded" }, 429);
  }

  const created = await c.env.DB.prepare(
    `INSERT INTO api_keys
       (id, key_hash, user_id, app_id, name, description, status, scopes)
     SELECT ?, ?, ?, ?, ?, ?, 'active', ?
     WHERE (
       SELECT COUNT(*) FROM api_keys WHERE user_id = ?
     ) < ?`
  )
    .bind(
      keyId,
      keyHash,
      userId,
      permissions[0].appId,
      body.name ?? null,
      body.description ?? null,
      JSON.stringify(permissions.flatMap((permission) => permission.scopes)),
      userId,
      apiKeyLimit
    )
    .run();
  if (created.meta.changes !== 1) {
    return c.json({ error: "api-key-limit-exceeded", limit: apiKeyLimit }, 429);
  }
  try {
    await insertKeyPermissions(c.env, keyId, permissions);
  } catch (error) {
    await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ?").bind(keyId).run();
    throw error;
  }

  return c.json({ id: keyId, key: rawKey, permissions }, 201);
});

me.delete("/api-keys/:keyId", async (c) => {
  await invalidateApiKeyCache(c.env, c.req.param("keyId"));
  await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ? AND user_id = ?")
    .bind(c.req.param("keyId"), c.get("userId"))
    .run();
  return c.body(null, 204);
});

me.post("/api-keys/:keyId/rotate", async (c) => {
  const keyId = c.req.param("keyId");
  const userId = c.get("userId");
  const result = await rotateApiKey(c.env, keyId, userId);
  if (!result.ok) {
    if (result.reason === "not-found") return c.json({ error: "not-found" }, 404);
    if (result.reason === "creation-limit") {
      return c.json({ error: "api-key-creation-abuse-limit-exceeded" }, 429);
    }
    return c.json({ error: "api-key-rotation-conflict" }, 409);
  }
  await writeAuditLog(c.env, {
    userId,
    appId: "keys-api",
    apiKeyId: result.id,
    action: "api_key.rotate",
    result: "allowed",
    reason: `replaced:${keyId}`,
  });
  return c.json(result, 201);
});

me.get("/limit-increase-requests", async (c) => {
  const page = pagination(c);
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB
    .prepare("SELECT * FROM limit_increase_requests WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
    .bind(c.get("userId"), page.limit, page.offset)
    .all();
  return c.json(r.results);
});

me.post("/limit-increase-requests", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{ appId: string; limitType: string; requestedValue: number; reason?: string }>().catch(() => null);
  if (
    !body
    || !isNonEmptyString(body.appId, 63)
    || !isNonEmptyString(body.limitType, 100)
    || !isValidLimitConfiguration(body.appId, body.limitType, body.requestedValue)
    || (body.reason !== undefined && !isNonEmptyString(body.reason, 2000))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const currentLimit = await getEffectiveLimit(c.env, userId, body.limitType);
  if (body.requestedValue <= currentLimit) {
    return c.json({ error: "requested-limit-must-be-higher", currentLimit }, 400);
  }
  const existing = await c.env.DB.prepare(
    `SELECT 1 FROM limit_increase_requests
     WHERE user_id = ? AND app_id = ? AND limit_type = ? AND status = 'pending'`
  )
    .bind(userId, body.appId, body.limitType)
    .first();
  if (existing) return c.json({ error: "limit-request-already-pending" }, 409);
  const withinHardRequestLimit = await consumeHardDailyLimit(
    c.env,
    userId,
    "keys-api",
    "limit_increase_requests_per_day",
    10
  );
  if (!withinHardRequestLimit) {
    return c.json({ error: "limit-request-abuse-limit-exceeded" }, 429);
  }
  const reqId = id();
  try {
    const created = await c.env.DB.prepare(
      `INSERT INTO limit_increase_requests
         (id, user_id, app_id, limit_type, requested_value, reason)
       SELECT ?, ?, ?, ?, ?, ?
       WHERE (
         SELECT COUNT(*) FROM limit_increase_requests
         WHERE user_id = ? AND status = 'pending'
       ) < 5`
    )
      .bind(
        reqId,
        userId,
        body.appId,
        body.limitType,
        body.requestedValue,
        body.reason ?? null,
        userId
      )
      .run();
    if (created.meta.changes !== 1) {
      return c.json({ error: "pending-limit-request-limit-exceeded", limit: 5 }, 429);
    }
  } catch (error) {
    if (String(error).toLowerCase().includes("unique")) {
      return c.json({ error: "limit-request-already-pending" }, 409);
    }
    throw error;
  }
  return c.json({ id: reqId }, 201);
});

app.route("/me", me);
app.route("/analytics", analytics);

app.get("/health", (c) => c.json({ ok: true }));
app.notFound((c) => c.json({ error: "not-found" }, 404));
app.onError((_error, c) => c.json({ error: "internal-error" }, 500));

const instrumented = withTelemetry(app, "keys-api");

async function cleanupExpiredData(env: Env): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM api_keys
       WHERE status = 'revoked'
          OR (expires_at IS NOT NULL AND expires_at <= unixepoch())`
    ),
    env.DB.prepare(
      `DELETE FROM resource_verifications
       WHERE verified_at IS NULL
         AND token_expires_at IS NOT NULL
         AND token_expires_at <= unixepoch()`
    ),
    env.DB.prepare(
      `DELETE FROM resources
       WHERE NOT EXISTS (
         SELECT 1 FROM resource_verifications WHERE resource_id = resources.id
       )
         AND NOT EXISTS (
           SELECT 1 FROM resource_grants WHERE resource_id = resources.id
         )
         AND NOT EXISTS (
           SELECT 1 FROM api_key_resource_grants WHERE resource_id = resources.id
         )`
    ),
    env.DB.prepare(
      `DELETE FROM daily_usage_counters
       WHERE day_bucket <= CAST(unixepoch() / 86400 AS INTEGER) - 31`
    ),
    env.DB.prepare(
      "DELETE FROM request_rate_counters WHERE expires_at <= unixepoch()"
    ),
  ]);
}

export default {
  fetch: instrumented.fetch,
  scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): void {
    ctx.waitUntil(cleanupExpiredData(env));
  },
};

export class McpEntrypoint extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    const delegated = acceptPrivateMcpDelegation(this.env, request);
    if (!delegated) return Response.json({ error: "invalid-mcp-delegation" }, { status: 401 });
    return instrumented.fetch!(
      delegated.request as Request<unknown, IncomingRequestCfProperties>,
      delegated.env,
      this.ctx,
    );
  }
}

/**
 * Private Clerk identity verifier for the MCP consent UI. Keeping this on the
 * keys worker means the public MCP worker never needs its own Clerk secret.
 * Named entrypoints are only reachable through an explicit service binding.
 */
export class McpIdentityEntrypoint extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/verify") {
      return Response.json({ error: "not-found" }, { status: 404 });
    }
    const token = (request.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
    if (!token || token.length > 8192) {
      return Response.json({ error: "not-authenticated" }, { status: 401 });
    }
    const session = await verifyClerkSession(token, this.env);
    if (!session) {
      return Response.json({ error: "not-authenticated" }, { status: 401 });
    }
    await ensureUserRow(session.userId, this.env);
    const user = await this.env.DB.prepare("SELECT status FROM users WHERE id = ?")
      .bind(session.userId)
      .first<{ status: string }>();
    if (user?.status !== "active") {
      return Response.json({ error: "user-inactive" }, { status: 403 });
    }
    return Response.json({ userId: session.userId });
  }
}
