import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { consumeDailyLimit, getEffectiveLimit, sha256Hex } from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import { requireUser, requireAdmin } from "./middleware";
import { lookupTxtRecords, verificationRecordName, generateVerificationToken } from "./dns";
import { sendMagicLinkEmail } from "./mail";
import type { Env } from "./env";

type Vars = { userId: string };
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
    return configured.split(",").map((item) => item.trim()).includes(origin) ? origin : null;
  },
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

const DNS_REVERIFY_DAYS = 30;
const DNS_GRACE_DAYS = 7;
const MAGIC_LINK_REVERIFY_DAYS = 90;
const MAGIC_LINK_GRACE_DAYS = 14;
const DNS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const MAGIC_LINK_TOKEN_TTL_SECONDS = 30 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function id() {
  return crypto.randomUUID();
}
function daysFromNow(days: number): number {
  return Math.floor(Date.now() / 1000) + days * 86400;
}

function pagination(limitValue?: string, offsetValue?: string) {
  const limit = Number(limitValue ?? 100);
  const offset = Number(offsetValue ?? 0);
  return Number.isInteger(limit) && limit >= 1 && limit <= 500
    && Number.isInteger(offset) && offset >= 0 && offset <= 100_000
    ? { limit, offset }
    : null;
}

function normalizeResourceValue(resourceType: string, method: string, value: string): string | null {
  const normalized = value.trim().toLowerCase();
  if (method === "magic_link") {
    return resourceType === "email_address"
      && normalized.length <= 320
      && EMAIL_PATTERN.test(normalized)
      ? normalized
      : null;
  }
  return HOSTNAME_PATTERN.test(normalized.replace(/\.$/, ""))
    ? normalized.replace(/\.$/, "")
    : null;
}

async function findOrCreateResource(env: Env, appId: string, resourceType: string, value: string) {
  const existing = await env.DB.prepare(
    "SELECT id FROM resources WHERE app_id = ? AND resource_type = ? AND value = ?"
  )
    .bind(appId, resourceType, value)
    .first<{ id: string }>();
  if (existing) return existing.id;

  const resourceId = id();
  await env.DB.prepare(
    "INSERT OR IGNORE INTO resources (id, app_id, resource_type, value) VALUES (?, ?, ?, ?)"
  )
    .bind(resourceId, appId, resourceType, value)
    .run();
  const resource = await env.DB.prepare(
    "SELECT id FROM resources WHERE app_id = ? AND resource_type = ? AND value = ?"
  )
    .bind(appId, resourceType, value)
    .first<{ id: string }>();
  if (!resource) throw new Error("resource creation failed");
  return resource.id;
}

async function grantAccess(
  env: Env,
  resourceId: string,
  userId: string,
  verificationId: string,
  scopes: string[]
): Promise<boolean> {
  const resourceLimit = await getEffectiveLimit(env, userId, "verified_resources");
  const result = await env.DB.prepare(
    `INSERT INTO resource_grants (id, resource_id, user_id, scopes, verification_id)
     SELECT ?, ?, ?, ?, ?
     WHERE EXISTS (
       SELECT 1 FROM resource_grants WHERE resource_id = ? AND user_id = ?
     ) OR (
       SELECT COUNT(*) FROM resource_grants WHERE user_id = ?
     ) < ?
     ON CONFLICT(resource_id, user_id) DO UPDATE SET
       scopes = excluded.scopes,
       verification_id = excluded.verification_id,
       created_at = unixepoch()`
  )
    .bind(
      id(),
      resourceId,
      userId,
      JSON.stringify(scopes),
      verificationId,
      resourceId,
      userId,
      userId,
      resourceLimit
    )
    .run();
  return result.meta.changes === 1;
}

// ============================================================
// Self-service — /resources
// ============================================================
const resources = new Hono<{ Bindings: Env; Variables: Vars }>();
resources.use("*", async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (c.req.method === "GET" && /^\/v1\/resources\/[^/]+\/confirm$/.test(path)) {
    await next();
    return;
  }
  return requireUser(c, next);
});

resources.get("/", async (c) => {
  const userId = c.get("userId");
  const page = pagination(c.req.query("limit"), c.req.query("offset"));
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare(
    `SELECT r.id, r.app_id, r.resource_type, r.value,
            rv.method, rv.verified_at, rv.reverify_due_at, rv.grace_expires_at
     FROM resources r
     JOIN resource_verifications rv ON rv.id = (
       SELECT latest.id
       FROM resource_verifications latest
       WHERE latest.resource_id = r.id AND latest.user_id = ?
       ORDER BY latest.created_at DESC
       LIMIT 1
     )
     WHERE rv.user_id = ?
     ORDER BY rv.created_at DESC, r.id
     LIMIT ? OFFSET ?`
  )
    .bind(userId, userId, page.limit, page.offset)
    .all();
  return c.json(r.results);
});

// Register a resource + start a verification attempt
const VALID_METHODS = ["dns_txt", "magic_link"];

resources.post("/", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{
    appId?: string;
    resourceType?: string;
    value?: string;
    method?: string;
    scopes?: string[];
  }>().catch(() => null);

  if (!body) return c.json({ error: "invalid-json-body" }, 400);
  if (
    typeof body.appId !== "string"
    || body.appId.length > 63
    || typeof body.resourceType !== "string"
    || body.resourceType.length > 64
    || typeof body.value !== "string"
    || typeof body.method !== "string"
    || body.method.length > 32
  ) {
    return c.json({ error: "invalid-field-types" }, 400);
  }

  const missing = ["appId", "resourceType", "value", "method"].filter(
    (k) => !body[k as keyof typeof body]
  );
  if (missing.length > 0) {
    return c.json({ error: "missing-fields", fields: missing }, 400);
  }
  if (!VALID_METHODS.includes(body.method!)) {
    return c.json({ error: "invalid-method", allowed: VALID_METHODS }, 400);
  }
  if (!Array.isArray(body.scopes) || body.scopes.length === 0 || body.scopes.length > 100) {
    return c.json({ error: "missing-scopes" }, 400);
  }
  if (!body.scopes.every((scope) =>
    typeof scope === "string" && scope.length > 0 && scope.length <= 100
  )) {
    return c.json({ error: "invalid-scopes" }, 400);
  }

  const normalizedValue = normalizeResourceValue(body.resourceType!, body.method!, body.value!);
  if (!normalizedValue) {
    return c.json({
      error: body.method === "magic_link"
        ? "magic-link-requires-valid-email-address"
        : "invalid-dns-resource-value",
    }, 400);
  }

  const appExists = await c.env.DB.prepare("SELECT 1 FROM apps WHERE id = ?")
    .bind(body.appId)
    .first();
  if (!appExists) {
    return c.json({ error: "app-not-found", appId: body.appId, hint: "Create the app first via keys-api /admin/apps" }, 404);
  }
  const scopeRows = await c.env.DB.prepare("SELECT scope FROM app_scopes WHERE app_id = ?")
    .bind(body.appId)
    .all<{ scope: string }>();
  const allowedScopes = new Set(scopeRows.results.map((row) => row.scope));
  const unknownScopes = body.scopes.filter((scope) => !allowedScopes.has(scope));
  if (unknownScopes.length > 0) {
    return c.json({ error: "invalid-scopes", scopes: unknownScopes }, 400);
  }

  const existingGrant = await c.env.DB.prepare(
    `SELECT 1
     FROM resources r
     JOIN resource_grants rg ON rg.resource_id = r.id
     WHERE r.app_id = ? AND r.resource_type = ? AND r.value = ?
       AND rg.user_id = ?
     LIMIT 1`
  )
    .bind(body.appId, body.resourceType, normalizedValue, userId)
    .first();
  if (!existingGrant) {
    const resourceLimit = await getEffectiveLimit(c.env, userId, "verified_resources");
    const resourceCount = await c.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM resource_grants WHERE user_id = ?"
    )
      .bind(userId)
      .first<{ count: number }>();
    if ((resourceCount?.count ?? 0) >= resourceLimit) {
      return c.json({ error: "verified-resource-limit-exceeded", limit: resourceLimit }, 429);
    }
  }

  const attemptLimit = await consumeDailyLimit(
    c.env,
    userId,
    "verification_attempts_per_day"
  );
  if (!attemptLimit.allowed) {
    return c.json({ error: "verification-attempt-limit-exceeded" }, 429);
  }
  await c.env.DB.batch([
    c.env.DB.prepare(
      `DELETE FROM resource_verifications
       WHERE user_id = ? AND verified_at IS NULL
         AND token_expires_at IS NOT NULL AND token_expires_at <= unixepoch()`
    ).bind(userId),
    c.env.DB.prepare(
      `DELETE FROM resources
       WHERE id IN (
         SELECT r.id FROM resources r
         WHERE NOT EXISTS (
           SELECT 1 FROM resource_verifications rv WHERE rv.resource_id = r.id
         )
           AND NOT EXISTS (
             SELECT 1 FROM resource_grants rg WHERE rg.resource_id = r.id
           )
         LIMIT 100
       )`
    ),
  ]);

  const method = body.method as "dns_txt" | "magic_link";

  let resourceId: string;
  let verificationId: string;
  const token = generateVerificationToken();
  const tokenHash = await sha256Hex(token);
  const tokenExpiresAt = Math.floor(Date.now() / 1000) + (
    method === "magic_link" ? MAGIC_LINK_TOKEN_TTL_SECONDS : DNS_TOKEN_TTL_SECONDS
  );
  verificationId = id();

  try {
    resourceId = await findOrCreateResource(c.env, body.appId!, body.resourceType!, normalizedValue);
    await c.env.DB.prepare(
      `INSERT INTO resource_verifications
         (id, resource_id, user_id, method, token_hash, token_expires_at, pending_scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        verificationId,
        resourceId,
        userId,
        method,
        tokenHash,
        tokenExpiresAt,
        JSON.stringify([...new Set(body.scopes)])
      )
      .run();
  } catch {
    return c.json({ error: "database-error" }, 500);
  }

  if (method === "dns_txt") {
    return c.json({
      resourceId,
      verificationId,
      instructions: {
        record: verificationRecordName(normalizedValue),
        type: "TXT",
        value: token,
      },
    }, 201);
  }

  const confirmUrl = `https://verify.api.kitsos.net/v1/resources/${resourceId}/confirm?token=${token}`;
  const result = await sendMagicLinkEmail(c.env, normalizedValue, confirmUrl, normalizedValue);

  if (!result.ok) {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "DELETE FROM resource_verifications WHERE id = ? AND verified_at IS NULL"
      ).bind(verificationId),
      c.env.DB.prepare(
        `DELETE FROM resources
         WHERE id = ?
           AND NOT EXISTS (
             SELECT 1 FROM resource_verifications WHERE resource_id = ?
           )
           AND NOT EXISTS (
             SELECT 1 FROM resource_grants WHERE resource_id = ?
           )`
      ).bind(resourceId, resourceId, resourceId),
    ]);
    return c.json({ error: "verification-email-failed" }, 502);
  }
  return c.json({ resourceId, verificationId, emailSent: true }, 201);
});

// Check a pending DNS-TXT verification
resources.post("/:resourceId/check-dns", async (c) => {
  const userId = c.get("userId");
  const resourceId = c.req.param("resourceId");

  const verification = await c.env.DB.prepare(
    `SELECT rv.id, rv.token_hash, rv.pending_scopes, r.value
     FROM resource_verifications rv
     JOIN resources r ON r.id = rv.resource_id
     WHERE rv.resource_id = ? AND rv.user_id = ? AND rv.method = 'dns_txt' AND rv.verified_at IS NULL
       AND rv.token_expires_at >= unixepoch()
     ORDER BY rv.created_at DESC LIMIT 1`
  )
    .bind(resourceId, userId)
    .first<{ id: string; token_hash: string; pending_scopes: string; value: string }>();

  if (!verification) return c.json({ error: "no-pending-verification" }, 404);

  const records = await lookupTxtRecords(verificationRecordName(verification.value));
  const recordHashes = await Promise.all(records.map(sha256Hex));
  if (!recordHashes.includes(verification.token_hash)) {
    return c.json({ verified: false }, 200);
  }

  const update = await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = ?
     WHERE id = ? AND verified_at IS NULL AND token_expires_at >= unixepoch()`
  )
    .bind(daysFromNow(DNS_REVERIFY_DAYS), daysFromNow(DNS_REVERIFY_DAYS + DNS_GRACE_DAYS), verification.id)
    .run();
  if (update.meta.changes !== 1) return c.json({ error: "verification-expired" }, 410);

  const granted = await grantAccess(
    c.env,
    resourceId,
    userId,
    verification.id,
    JSON.parse(verification.pending_scopes)
  );
  if (!granted) {
    await c.env.DB.prepare(
      `UPDATE resource_verifications
       SET verified_at = NULL, reverify_due_at = NULL, grace_expires_at = NULL
       WHERE id = ?`
    ).bind(verification.id).run();
    return c.json({ error: "verified-resource-limit-exceeded" }, 429);
  }

  return c.json({ verified: true });
});

// Public confirm endpoint for magic-link — no auth, gated by the token itself
resources.get("/:resourceId/confirm", async (c) => {
  c.header("Cache-Control", "no-store");
  c.header("Referrer-Policy", "no-referrer");
  const resourceId = c.req.param("resourceId");
  const token = c.req.query("token");
  if (!token) return c.json({ error: "missing-token" }, 400);
  if (token.length > 128) return c.json({ error: "invalid-token" }, 400);
  const tokenHash = await sha256Hex(token);

  const verification = await c.env.DB.prepare(
    `SELECT id, user_id, pending_scopes FROM resource_verifications
     WHERE resource_id = ? AND token_hash = ? AND method = 'magic_link'
       AND verified_at IS NULL AND token_expires_at >= unixepoch()`
  )
    .bind(resourceId, tokenHash)
    .first<{ id: string; user_id: string; pending_scopes: string }>();

  if (!verification) return c.json({ error: "invalid-or-expired-token" }, 404);

  const update = await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = ?
     WHERE id = ? AND verified_at IS NULL AND token_expires_at >= unixepoch()`
  )
    .bind(
      daysFromNow(MAGIC_LINK_REVERIFY_DAYS),
      daysFromNow(MAGIC_LINK_REVERIFY_DAYS + MAGIC_LINK_GRACE_DAYS),
      verification.id
    )
    .run();
  if (update.meta.changes !== 1) return c.json({ error: "invalid-or-expired-token" }, 404);

  const granted = await grantAccess(
    c.env,
    resourceId,
    verification.user_id,
    verification.id,
    JSON.parse(verification.pending_scopes)
  );
  if (!granted) {
    await c.env.DB.prepare(
      `UPDATE resource_verifications
       SET verified_at = NULL, reverify_due_at = NULL, grace_expires_at = NULL
       WHERE id = ?`
    ).bind(verification.id).run();
    return c.json({ error: "verified-resource-limit-exceeded" }, 429);
  }

  return c.json({ verified: true });
});

app.route("/resources", resources);

// ============================================================
// Admin — /admin/resources
// ============================================================
const admin = new Hono<{ Bindings: Env; Variables: Vars }>();
admin.use("*", requireAdmin);

admin.get("/resources", async (c) => {
  const page = pagination(c.req.query("limit"), c.req.query("offset"));
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare(
    `SELECT r.id, r.app_id, r.resource_type, r.value,
            rv.user_id, rv.method, rv.verified_at, rv.reverify_due_at, rv.grace_expires_at
     FROM resources r
     LEFT JOIN resource_verifications rv ON rv.resource_id = r.id
     ORDER BY r.created_at DESC, r.id
     LIMIT ? OFFSET ?`
  ).bind(page.limit, page.offset).all();
  return c.json(r.results);
});

admin.delete("/resources/:resourceId", async (c) => {
  const resourceId = c.req.param("resourceId");
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM resource_grants WHERE resource_id = ?").bind(resourceId),
    c.env.DB.prepare("DELETE FROM resource_verifications WHERE resource_id = ?").bind(resourceId),
    c.env.DB.prepare("DELETE FROM resources WHERE id = ?").bind(resourceId),
  ]);
  return c.body(null, 204);
});

app.route("/admin", admin);

app.get("/health", (c) => c.json({ ok: true }));
app.notFound((c) => c.json({ error: "not-found" }, 404));
app.onError((_error, c) => c.json({ error: "internal-error" }, 500));

export default withTelemetry(app, "verify");
