import { Hono } from "hono";
import { cors } from "hono/cors";
import { recordError, recordEvent, withTelemetry } from "@kitsos/telemetry";
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

const MAX_VERIFY_EMAILS_PER_DAY = 15;
const CANONICAL_RESOURCE_APP_ID = "verify";
const RESOURCE_METHODS = { zone: "dns_txt", email_address: "magic_link" } as const;
type ResourceType = keyof typeof RESOURCE_METHODS;

function id() {
  return crypto.randomUUID();
}
function tomorrow(): number {
  return Math.floor(Date.now() / 1000) + 86400;
}

function normalizeResource(resourceType: ResourceType, rawValue: string) {
  const value = rawValue.trim().toLowerCase();
  if (resourceType === "email_address") {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? value : null;
  }
  const zone = value.replace(/\.$/, "");
  return zone.length <= 253 && zone.includes(".") && zone.split(".").every((label) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label)) ? zone : null;
}

async function findOrCreateResource(env: Env, userId: string, resourceType: string, value: string) {
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
    .bind(id(), CANONICAL_RESOURCE_APP_ID, resourceType, value)
    .run();

  const resource = await findExisting();
  if (!resource) throw new Error("resource-create-failed");
  return resource.id;
}

async function grantAccess(
  env: Env,
  resourceId: string,
  userId: string
) {
  const existing = await env.DB.prepare(
    "SELECT id FROM resource_grants WHERE resource_id = ? AND user_id = ? LIMIT 1"
  ).bind(resourceId, userId).first();
  if (existing) return;
  await env.DB.prepare(
    "INSERT OR IGNORE INTO resource_grants (id, resource_id, user_id, scopes) VALUES (?, ?, ?, ?)"
  )
    .bind(id(), resourceId, userId, "[]")
    .run();
}

async function hasActiveVerification(env: Env, resourceId: string, userId: string) {
  const verification = await env.DB.prepare(
    `SELECT 1 FROM resource_verifications
     WHERE resource_id = ? AND user_id = ? AND verified_at IS NOT NULL
     ORDER BY verified_at DESC LIMIT 1`
  ).bind(resourceId, userId).first();
  return Boolean(verification);
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
    `WITH ranked AS (
       SELECT r.id, r.resource_type, r.value, rv.method, rv.verified_at,
              rv.reverify_due_at, rv.grace_expires_at, rv.created_at,
              ROW_NUMBER() OVER (
                PARTITION BY r.resource_type, r.value
                ORDER BY (rv.verified_at IS NOT NULL) DESC, rv.created_at DESC
              ) AS position
       FROM resources r
       JOIN resource_verifications rv ON rv.resource_id = r.id
       WHERE rv.user_id = ?
     )
     SELECT id, resource_type, value, method, verified_at, reverify_due_at, grace_expires_at
     FROM ranked WHERE position = 1 ORDER BY created_at DESC`
  )
    .bind(userId)
    .all();
  return c.json(r.results);
});

// Register a resource + start the method dictated by its resource type.

resources.post("/", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{
    resourceType?: string;
    value?: string;
  }>().catch(() => null);

  if (!body) {
    recordEvent("verify.resource.create", "denied", {
      "kitsos.user.id": userId,
      "error.code": "invalid-json-body",
    });
    return c.json({ error: "invalid-json-body" }, 400);
  }

  const missing = ["resourceType", "value"].filter(
    (k) => !body[k as keyof typeof body]
  );
  if (missing.length > 0) {
    return c.json({ error: "missing-fields", fields: missing }, 400);
  }
  if (!(body.resourceType! in RESOURCE_METHODS)) {
    return c.json({ error: "invalid-resource-type", allowed: Object.keys(RESOURCE_METHODS) }, 400);
  }
  const resourceType = body.resourceType as ResourceType;
  const value = normalizeResource(resourceType, body.value!);
  if (!value) return c.json({ error: resourceType === "email_address" ? "invalid-email-address" : "invalid-zone" }, 400);
  const method = RESOURCE_METHODS[resourceType];

  let resourceId: string;
  let verificationId: string;
  const token = generateVerificationToken();

  try {
    resourceId = await findOrCreateResource(c.env, userId, resourceType, value);
    if (await hasActiveVerification(c.env, resourceId, userId)) {
      await grantAccess(c.env, resourceId, userId);
      recordEvent("verify.resource.create", "noop", {
        "kitsos.user.id": userId,
        "kitsos.resource.id": resourceId,
        "kitsos.resource.type": resourceType,
        "verify.reason": "already-verified",
      });
      return c.json({ resourceId, alreadyVerified: true }, 200);
    }

    const verification = await c.env.DB.prepare(
      `SELECT id, verified_at FROM resource_verifications
       WHERE resource_id = ? AND user_id = ?`
    )
      .bind(resourceId, userId)
      .first<{ id: string; verified_at: number | null }>();

    verificationId = verification?.id ?? id();

    // Only magic-link delivery consumes this budget. DNS-TXT checks do not.
    if (method === "magic_link") {
      const limit = await checkAndIncrementVerifyEmailLimit(c.env, userId);
      if (!limit.allowed) {
        recordEvent("verify.resource.create", "denied", {
          "kitsos.user.id": userId,
          "kitsos.resource.id": resourceId,
          "kitsos.resource.type": resourceType,
          "limit.type": "verification_emails_per_day",
          "limit.value": limit.maxPerDay,
          "error.code": "verify-email-daily-limit-exceeded",
        });
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
      .bind(verificationId, resourceId, userId, method, token, "[]")
      .run();
  } catch (e) {
    recordError("verify.resource.create", "database-error", "Could not create verification record", {
      "kitsos.user.id": userId,
      "kitsos.resource.type": resourceType,
    });
    return c.json({ error: "database-error", detail: String(e) }, 500);
  }

  if (method === "dns_txt") {
    recordEvent("verify.resource.create", "success", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "kitsos.verification.id": verificationId,
      "kitsos.resource.type": resourceType,
      "verify.method": method,
    });
    return c.json({
      resourceId,
      verificationId,
      instructions: {
        record: verificationRecordName(value),
        type: "TXT",
        value: token,
      },
    }, 201);
  }

  const confirmUrl = `https://verify.api.kitsos.net/resources/${resourceId}/confirm?token=${token}`;
  const result = await sendMagicLinkEmail(c.env, value, confirmUrl, value);
  if (result.ok) {
    recordEvent("verify.resource.create", "success", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "kitsos.verification.id": verificationId,
      "kitsos.resource.type": resourceType,
      "verify.method": method,
    });
  } else {
    recordError("verify.resource.create", "verification-email-send-failed", "Could not send verification email", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "kitsos.verification.id": verificationId,
      "kitsos.resource.type": resourceType,
      "verify.method": method,
    });
  }

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
  recordEvent("verify.resource.delete", "success", {
    "kitsos.user.id": userId,
    "kitsos.resource.id": resourceId,
  });
  return c.body(null, 204);
});

// Check a pending DNS-TXT verification
resources.post("/:resourceId/check-dns", async (c) => {
  const userId = c.get("userId");
  const resourceId = c.req.param("resourceId");

  const verification = await c.env.DB.prepare(
    `SELECT rv.id, rv.token, r.value
     FROM resource_verifications rv
     JOIN resources r ON r.id = rv.resource_id
     WHERE rv.resource_id = ? AND rv.user_id = ? AND rv.method = 'dns_txt' AND rv.verified_at IS NULL
     ORDER BY rv.created_at DESC LIMIT 1`
  )
    .bind(resourceId, userId)
    .first<{ id: string; token: string; value: string }>();

  if (!verification) {
    recordEvent("verify.domain.check", "denied", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "error.code": "no-pending-verification",
    });
    return c.json({ error: "no-pending-verification" }, 404);
  }

  const records = await lookupTxtRecords(verificationRecordName(verification.value));
  if (!records.includes(verification.token)) {
    recordEvent("verify.domain.check", "denied", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "kitsos.verification.id": verification.id,
      "error.code": "verification-token-not-found",
      "dns.txt_record_count": records.length,
    });
    return c.json({ verified: false, expected: verification.token, found: records }, 200);
  }

  if (!await canVerifyResource(c.env, userId, resourceId)) {
    recordEvent("verify.domain.check", "denied", {
      "kitsos.user.id": userId,
      "kitsos.resource.id": resourceId,
      "error.code": "usage-limit-exceeded",
    });
    return c.json({ error: "usage-limit-exceeded" }, 429);
  }

  await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = ?, grace_expires_at = NULL
     WHERE id = ?`
  )
    .bind(tomorrow(), verification.id)
    .run();

  await grantAccess(c.env, resourceId, userId);

  recordEvent("verify.domain.check", "success", {
    "kitsos.user.id": userId,
    "kitsos.resource.id": resourceId,
    "kitsos.verification.id": verification.id,
  });
  return c.json({ verified: true });
});

// Public confirm endpoint for magic-link — no auth, gated by the token itself
resources.get("/:resourceId/confirm", async (c) => {
  const resourceId = c.req.param("resourceId");
  const token = c.req.query("token");
  if (!token) return c.json({ error: "missing-token" }, 400);

  const verification = await c.env.DB.prepare(
    `SELECT id, user_id FROM resource_verifications
     WHERE resource_id = ? AND token = ? AND method = 'magic_link' AND verified_at IS NULL`
  )
    .bind(resourceId, token)
    .first<{ id: string; user_id: string }>();

  if (!verification) {
    recordEvent("verify.email.confirm", "denied", {
      "kitsos.resource.id": resourceId,
      "error.code": "invalid-or-expired-token",
    });
    return c.json({ error: "invalid-or-expired-token" }, 404);
  }

  if (!await canVerifyResource(c.env, verification.user_id, resourceId)) {
    recordEvent("verify.email.confirm", "denied", {
      "kitsos.user.id": verification.user_id,
      "kitsos.resource.id": resourceId,
      "kitsos.verification.id": verification.id,
      "error.code": "usage-limit-exceeded",
    });
    return c.json({ error: "usage-limit-exceeded" }, 429);
  }

  await c.env.DB.prepare(
    `UPDATE resource_verifications
     SET verified_at = unixepoch(), reverify_due_at = NULL, grace_expires_at = NULL
     WHERE id = ?`
  )
    .bind(verification.id)
    .run();

  await grantAccess(c.env, resourceId, verification.user_id);

  recordEvent("verify.email.confirm", "success", {
    "kitsos.user.id": verification.user_id,
    "kitsos.resource.id": resourceId,
    "kitsos.verification.id": verification.id,
  });
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

type VerifiedZone = {
  id: string;
  resource_id: string;
  user_id: string;
  token: string;
  value: string;
};

async function recheckVerifiedZones(env: Env) {
  let afterId = "";
  for (;;) {
    const page = await env.DB.prepare(
      `SELECT rv.id, rv.resource_id, rv.user_id, rv.token, r.value
       FROM resource_verifications rv
       JOIN resources r ON r.id = rv.resource_id
       WHERE r.resource_type = 'zone'
         AND rv.method = 'dns_txt'
         AND rv.verified_at IS NOT NULL
         AND rv.id > ?
       ORDER BY rv.id
       LIMIT 100`
    ).bind(afterId).all<VerifiedZone>();

    if (page.results.length === 0) break;

    for (let offset = 0; offset < page.results.length; offset += 10) {
      await Promise.all(page.results.slice(offset, offset + 10).map(async (verification) => {
        try {
          const records = await lookupTxtRecords(verificationRecordName(verification.value));
          if (records.includes(verification.token)) {
            await env.DB.prepare(
              "UPDATE resource_verifications SET reverify_due_at = ? WHERE id = ?"
            ).bind(tomorrow(), verification.id).run();
            recordEvent("verify.domain.recheck", "success", {
              "kitsos.user.id": verification.user_id,
              "kitsos.resource.id": verification.resource_id,
              "kitsos.verification.id": verification.id,
            });
          } else {
            await env.DB.prepare(
              `UPDATE resource_verifications
               SET verified_at = NULL, reverify_due_at = NULL, grace_expires_at = NULL
               WHERE id = ?`
            ).bind(verification.id).run();
            recordEvent("verify.domain.recheck", "denied", {
              "kitsos.user.id": verification.user_id,
              "kitsos.resource.id": verification.resource_id,
              "kitsos.verification.id": verification.id,
              "error.code": "verification-token-not-found",
              "dns.txt_record_count": records.length,
            });
          }
        } catch {
          // A resolver/network failure is not proof that ownership was lost.
          // Leave the last verified state intact and try again on the next run.
          recordError("verify.domain.recheck", "dns-query-failed", "DNS ownership recheck could not query the resolver", {
            "kitsos.user.id": verification.user_id,
            "kitsos.resource.id": verification.resource_id,
            "kitsos.verification.id": verification.id,
          });
        }
      }));
    }

    afterId = page.results[page.results.length - 1].id;
    if (page.results.length < 100) break;
  }
}

export default withTelemetry({
  fetch: app.fetch,
  scheduled(_event, env, ctx) {
    ctx.waitUntil(recheckVerifiedZones(env));
  },
} satisfies ExportedHandler<Env>, "verify");
