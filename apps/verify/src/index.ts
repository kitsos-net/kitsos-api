import { Hono } from "hono";
import { cors } from "hono/cors";
import { withTelemetry } from "@kitsos/telemetry";
import { requireUser, requireAdmin } from "./middleware";
import { lookupTxtRecords, verificationRecordName, generateVerificationToken } from "./dns";
import { sendMagicLinkEmail } from "./mail";
import type { Env } from "./env";

type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>();

app.use("*", cors({
  origin: "*",
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

const DNS_REVERIFY_DAYS = 30;
const DNS_GRACE_DAYS = 7;
const MAGIC_LINK_REVERIFY_DAYS = 90;
const MAGIC_LINK_GRACE_DAYS = 14;

function id() {
  return crypto.randomUUID();
}
function daysFromNow(days: number): number {
  return Math.floor(Date.now() / 1000) + days * 86400;
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
    "INSERT INTO resources (id, app_id, resource_type, value) VALUES (?, ?, ?, ?)"
  )
    .bind(resourceId, appId, resourceType, value)
    .run();
  return resourceId;
}

async function grantAccess(
  env: Env,
  resourceId: string,
  userId: string,
  verificationId: string,
  scopes: string[]
) {
  await env.DB.prepare(
    "INSERT INTO resource_grants (id, resource_id, user_id, scopes) VALUES (?, ?, ?, ?)"
  )
    .bind(id(), resourceId, userId, JSON.stringify(scopes))
    .run();
}

// ============================================================
// Self-service — /resources
// ============================================================
const resources = new Hono<{ Bindings: Env; Variables: Vars }>();
resources.use("*", requireUser);

resources.get("/", async (c) => {
  const userId = c.get("userId");
  const r = await c.env.DB.prepare(
    `SELECT r.id, r.app_id, r.resource_type, r.value,
            rv.method, rv.verified_at, rv.reverify_due_at, rv.grace_expires_at
     FROM resources r
     JOIN resource_verifications rv ON rv.resource_id = r.id
     WHERE rv.user_id = ?
     ORDER BY rv.created_at DESC`
  )
    .bind(userId)
    .all();
  return c.json(r.results);
});

// Register a resource + start a verification attempt
resources.post("/", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{
    appId: string;
    resourceType: string;
    value: string;
    method: "dns_txt" | "magic_link";
    scopes: string[];
  }>();

  const resourceId = await findOrCreateResource(c.env, body.appId, body.resourceType, body.value);
  const token = generateVerificationToken();
  const verificationId = id();

  await c.env.DB.prepare(
    `INSERT INTO resource_verifications (id, resource_id, user_id, method, token, pending_scopes)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(verificationId, resourceId, userId, body.method, token, JSON.stringify(body.scopes))
    .run();

  if (body.method === "dns_txt") {
    return c.json({
      resourceId,
      verificationId,
      instructions: {
        record: verificationRecordName(body.value),
        type: "TXT",
        value: token,
      },
    }, 201);
  }

  // magic_link — user's email comes from their `users` row
  const user = await c.env.DB.prepare("SELECT email FROM users WHERE id = ?")
    .bind(userId)
    .first<{ email: string }>();
  const confirmUrl = `https://verify.api.kitsos.net/resources/${resourceId}/confirm?token=${token}`;
  const sent = user ? await sendMagicLinkEmail(c.env, user.email, confirmUrl, body.value) : false;

  return c.json({ resourceId, verificationId, emailSent: sent }, 201);
});

// Check a pending DNS-TXT verification
resources.post("/:resourceId/check-dns", async (c) => {
  const userId = c.get("userId");
  const resourceId = c.req.param("resourceId");

  const verification = await c.env.DB.prepare(
    `SELECT rv.id, rv.token, rv.pending_scopes, r.value
     FROM resource_verifications rv
     JOIN resources r ON r.id = rv.resource_id
     WHERE rv.resource_id = ? AND rv.user_id = ? AND rv.method = 'dns_txt' AND rv.verified_at IS NULL
     ORDER BY rv.created_at DESC LIMIT 1`
  )
    .bind(resourceId, userId)
    .first<{ id: string; token: string; pending_scopes: string; value: string }>();

  if (!verification) return c.json({ error: "no-pending-verification" }, 404);

  const records = await lookupTxtRecords(verificationRecordName(verification.value));
  if (!records.includes(verification.token)) {
    return c.json({ verified: false, expected: verification.token, found: records }, 200);
  }

  await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = ?
     WHERE id = ?`
  )
    .bind(daysFromNow(DNS_REVERIFY_DAYS), daysFromNow(DNS_REVERIFY_DAYS + DNS_GRACE_DAYS), verification.id)
    .run();

  await grantAccess(c.env, resourceId, userId, verification.id, JSON.parse(verification.pending_scopes));

  return c.json({ verified: true });
});

// Public confirm endpoint for magic-link — no auth, gated by the token itself
resources.get("/:resourceId/confirm", async (c) => {
  const resourceId = c.req.param("resourceId");
  const token = c.req.query("token");
  if (!token) return c.json({ error: "missing-token" }, 400);

  const verification = await c.env.DB.prepare(
    `SELECT id, user_id, pending_scopes FROM resource_verifications
     WHERE resource_id = ? AND token = ? AND method = 'magic_link' AND verified_at IS NULL`
  )
    .bind(resourceId, token)
    .first<{ id: string; user_id: string; pending_scopes: string }>();

  if (!verification) return c.json({ error: "invalid-or-expired-token" }, 404);

  await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = ?
     WHERE id = ?`
  )
    .bind(
      daysFromNow(MAGIC_LINK_REVERIFY_DAYS),
      daysFromNow(MAGIC_LINK_REVERIFY_DAYS + MAGIC_LINK_GRACE_DAYS),
      verification.id
    )
    .run();

  await grantAccess(c.env, resourceId, verification.user_id, verification.id, JSON.parse(verification.pending_scopes));

  return c.json({ verified: true });
});

app.route("/resources", resources);

// ============================================================
// Admin — /admin/resources
// ============================================================
const admin = new Hono<{ Bindings: Env; Variables: Vars }>();
admin.use("*", requireAdmin);

admin.get("/resources", async (c) => {
  const r = await c.env.DB.prepare(
    `SELECT r.id, r.app_id, r.resource_type, r.value,
            rv.user_id, rv.method, rv.verified_at, rv.reverify_due_at, rv.grace_expires_at
     FROM resources r
     LEFT JOIN resource_verifications rv ON rv.resource_id = r.id
     ORDER BY r.created_at DESC`
  ).all();
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

export default withTelemetry(app, "verify");
