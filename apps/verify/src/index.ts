import { Hono } from "hono";
import { cors } from "hono/cors";
import { withTelemetry } from "@kitsos/telemetry";
import { requireUser, requireAdmin } from "./middleware";
import { lookupTxtRecords, verificationRecordName, generateVerificationToken } from "./dns";
import { sendMagicLinkEmail } from "./mail";
import { getUsageLimit } from "@kitsos/auth";
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
const MAX_VERIFY_EMAILS_PER_DAY = 15;

function id() {
  return crypto.randomUUID();
}
function daysFromNow(days: number): number {
  return Math.floor(Date.now() / 1000) + days * 86400;
}

async function findOrCreateResource(env: Env, userId: string, appId: string, resourceType: string, value: string) {
  const findExisting = () => env.DB.prepare(
    `SELECT r.id FROM resources r
     LEFT JOIN resource_verifications rv ON rv.resource_id = r.id AND rv.user_id = ?
     WHERE r.resource_type = ? AND r.value = ?
     ORDER BY CASE WHEN rv.verified_at IS NOT NULL THEN 0 ELSE 1 END, r.created_at ASC
     LIMIT 1`
  )
    .bind(userId, resourceType, value)
    .first<{ id: string }>();
  const existing = await findExisting();
  if (existing) return existing.id;

  // The global resource_type/value unique index makes concurrent creates safe.
  await env.DB.prepare(
    "INSERT OR IGNORE INTO resources (id, app_id, resource_type, value) VALUES (?, ?, ?, ?)"
  )
    .bind(id(), appId, resourceType, value)
    .run();

  const resource = await findExisting();
  if (!resource) throw new Error("resource-create-failed");
  return resource.id;
}

async function grantAccess(
  env: Env,
  resourceId: string,
  userId: string,
  scopes: string[]
) {
  const existing = await env.DB.prepare(
    "SELECT id, scopes FROM resource_grants WHERE resource_id = ? AND user_id = ? ORDER BY created_at ASC"
  ).bind(resourceId, userId).all<{ id: string; scopes: string }>();
  const mergedScopes = [...new Set([...existing.results.flatMap((grant) => JSON.parse(grant.scopes) as string[]), ...scopes])];
  if (existing.results.length > 0) {
    await env.DB.prepare("UPDATE resource_grants SET scopes = ? WHERE id = ?")
      .bind(JSON.stringify(mergedScopes), existing.results[0].id).run();
    return mergedScopes;
  }
  await env.DB.prepare(
    "INSERT OR IGNORE INTO resource_grants (id, resource_id, user_id, scopes) VALUES (?, ?, ?, ?)"
  )
    .bind(id(), resourceId, userId, JSON.stringify(mergedScopes))
    .run();
  return mergedScopes;
}

async function hasActiveVerification(env: Env, resourceId: string, userId: string) {
  const verification = await env.DB.prepare(
    `SELECT grace_expires_at FROM resource_verifications
     WHERE resource_id = ? AND user_id = ? AND verified_at IS NOT NULL
     ORDER BY verified_at DESC LIMIT 1`
  ).bind(resourceId, userId).first<{ grace_expires_at: number | null }>();
  return Boolean(verification && (!verification.grace_expires_at || verification.grace_expires_at >= Math.floor(Date.now() / 1000)));
}

/** Fixed UTC-day budget for verification email delivery. A per-user
 * usage_limits row can raise this default after an approved request. */
async function checkAndIncrementVerifyEmailLimit(env: Env, userId: string): Promise<{ allowed: boolean; maxPerDay: number }> {
  const configured = await getUsageLimit(env, userId, "verify", "verification_emails_per_day");
  const maxPerDay = configured ?? MAX_VERIFY_EMAILS_PER_DAY;
  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const key = `verify:email:${userId}:${dayBucket}`;
  const current = await env.USAGE_COUNTERS.get(key);
  const count = current ? Number.parseInt(current, 10) : 0;
  if (count >= maxPerDay) return { allowed: false, maxPerDay };
  await env.USAGE_COUNTERS.put(key, String(count + 1), { expirationTtl: 172800 });
  return { allowed: true, maxPerDay };
}

async function canVerifyResource(env: Env, userId: string, resourceId: string): Promise<boolean> {
  // Reverification does not consume another slot; only distinct verified
  // resources count towards the account-wide quota.
  const existing = await env.DB.prepare(
    "SELECT 1 FROM resource_verifications WHERE user_id = ? AND resource_id = ? AND verified_at IS NOT NULL"
  ).bind(userId, resourceId).first();
  if (existing) return true;
  const max = await getUsageLimit(env, userId, "verify", "verified_resources");
  if (max === null) return true;
  const count = await env.DB.prepare(
    "SELECT COUNT(DISTINCT resource_id) AS n FROM resource_verifications WHERE user_id = ? AND verified_at IS NOT NULL"
  ).bind(userId).first<{ n: number }>();
  return (count?.n ?? 0) < max;
}

// ============================================================
// Self-service — /resources
// ============================================================
const resources = new Hono<{ Bindings: Env; Variables: Vars }>();
resources.use("*", async (c, next) => {
  // Magic-link confirmations are authenticated by their one-time token.
  if (c.req.method === "GET" && new URL(c.req.url).pathname.endsWith("/confirm")) {
    return next();
  }
  const path = new URL(c.req.url).pathname;
  const scope = c.req.method === "GET" ? "verify:resource:read"
    : c.req.method === "POST" && path.endsWith("/check-dns") ? "verify:resource:verify"
    : c.req.method === "DELETE" ? "verify:resource:delete"
    : "verify:resource:create";
  return requireUser(scope)(c, next);
});

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

  const missing = ["appId", "resourceType", "value", "method"].filter(
    (k) => !body[k as keyof typeof body]
  );
  if (missing.length > 0) {
    return c.json({ error: "missing-fields", fields: missing }, 400);
  }
  if (!VALID_METHODS.includes(body.method!)) {
    return c.json({ error: "invalid-method", allowed: VALID_METHODS }, 400);
  }
  if (!Array.isArray(body.scopes) || body.scopes.length === 0) {
    return c.json({ error: "missing-scopes" }, 400);
  }

  const appExists = await c.env.DB.prepare("SELECT 1 FROM apps WHERE id = ?")
    .bind(body.appId)
    .first();
  if (!appExists) {
    return c.json({ error: "app-not-found", appId: body.appId, hint: "Create the app first via keys-api /admin/apps" }, 404);
  }

  const method = body.method as "dns_txt" | "magic_link";

  let resourceId: string;
  let verificationId: string;
  const token = generateVerificationToken();

  try {
    resourceId = await findOrCreateResource(c.env, userId, body.appId!, body.resourceType!, body.value!);
    if (await hasActiveVerification(c.env, resourceId, userId)) {
      const scopes = await grantAccess(c.env, resourceId, userId, body.scopes);
      return c.json({ resourceId, alreadyVerified: true, scopes }, 200);
    }

    const verification = await c.env.DB.prepare(
      `SELECT id, verified_at FROM resource_verifications
       WHERE resource_id = ? AND user_id = ?`
    )
      .bind(resourceId, userId)
      .first<{ id: string; verified_at: number | null }>();

    verificationId = verification?.id ?? id();

    // Only count an email that can actually be sent. DNS-TXT checks do not
    // consume this budget, and a missing profile email does not either.
    if (method === "magic_link") {
      const user = await c.env.DB.prepare("SELECT email FROM users WHERE id = ?")
        .bind(userId)
        .first<{ email: string }>();
      if (!user?.email) {
        return c.json({ resourceId, verificationId, emailSent: false, emailError: "no-user-email-on-file" }, 201);
      }
      const limit = await checkAndIncrementVerifyEmailLimit(c.env, userId);
      if (!limit.allowed) {
        return c.json({ error: "verify-email-daily-limit-exceeded", maxPerDay: limit.maxPerDay }, 429);
      }
    }

    // Re-sending or switching methods replaces the one pending attempt. It
    // cannot create another resource/grant row for the same user and value.
    await c.env.DB.prepare(
      `INSERT INTO resource_verifications (id, resource_id, user_id, method, token, pending_scopes)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(resource_id, user_id) DO UPDATE SET
         method = excluded.method,
         token = excluded.token,
         pending_scopes = excluded.pending_scopes,
         verified_at = NULL,
         reverify_due_at = NULL,
         grace_expires_at = NULL,
         created_at = unixepoch()`
    )
      .bind(verificationId, resourceId, userId, method, token, JSON.stringify(body.scopes))
      .run();
  } catch (e) {
    return c.json({ error: "database-error", detail: String(e) }, 500);
  }

  if (method === "dns_txt") {
    return c.json({
      resourceId,
      verificationId,
      instructions: {
        record: verificationRecordName(body.value!),
        type: "TXT",
        value: token,
      },
    }, 201);
  }

  // magic_link — the user was checked before the pending attempt was saved.
  const user = await c.env.DB.prepare("SELECT email FROM users WHERE id = ?")
    .bind(userId)
    .first<{ email: string }>();

  if (!user?.email) {
    return c.json({
      resourceId, verificationId,
      emailSent: false, emailError: "no-user-email-on-file",
    }, 201);
  }

  const confirmUrl = `https://verify.api.kitsos.net/resources/${resourceId}/confirm?token=${token}`;
  const result = await sendMagicLinkEmail(c.env, user.email, confirmUrl, body.value!);

  return c.json({
    resourceId, verificationId,
    emailSent: result.ok,
    emailError: result.ok ? undefined : result.error,
  }, 201);
});

// A user removes only their own verified ownership claim. If no other user
// has a verification for the shared resource, remove the resource itself too.
resources.delete("/:resourceId", async (c) => {
  const userId = c.get("userId");
  const resourceId = c.req.param("resourceId");
  const verification = await c.env.DB.prepare(
    `SELECT id FROM resource_verifications
     WHERE resource_id = ? AND user_id = ? AND verified_at IS NOT NULL`
  )
    .bind(resourceId, userId)
    .first();
  if (!verification) return c.json({ error: "verified-resource-not-found" }, 404);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM resource_grants WHERE resource_id = ? AND user_id = ?").bind(resourceId, userId),
    c.env.DB.prepare("DELETE FROM resource_verifications WHERE resource_id = ? AND user_id = ?").bind(resourceId, userId),
  ]);

  const remaining = await c.env.DB.prepare(
    "SELECT 1 FROM resource_verifications WHERE resource_id = ? LIMIT 1"
  )
    .bind(resourceId)
    .first();
  if (!remaining) {
    await c.env.DB.prepare("DELETE FROM resources WHERE id = ?").bind(resourceId).run();
  }
  return c.body(null, 204);
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

  if (!await canVerifyResource(c.env, userId, resourceId)) {
    return c.json({ error: "usage-limit-exceeded" }, 429);
  }

  await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = ?
     WHERE id = ?`
  )
    .bind(daysFromNow(DNS_REVERIFY_DAYS), daysFromNow(DNS_REVERIFY_DAYS + DNS_GRACE_DAYS), verification.id)
    .run();

  await grantAccess(c.env, resourceId, userId, JSON.parse(verification.pending_scopes));

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

  if (!await canVerifyResource(c.env, verification.user_id, resourceId)) {
    return c.json({ error: "usage-limit-exceeded" }, 429);
  }

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

  await grantAccess(c.env, resourceId, verification.user_id, JSON.parse(verification.pending_scopes));

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
