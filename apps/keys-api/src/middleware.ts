import type { Context, Next } from "hono";
import {
  authenticate,
  annotateAuthenticatedRequest,
  checkRateLimit,
  recordAuthDecision,
  recordRateLimitDecision,
  verifyClerkSession,
  ensureUserRow,
} from "@kitsos/auth";
import type { AuthContext } from "@kitsos/auth";
import type { Env } from "./env";

type ContextEnv = { Bindings: Env; Variables: { userId: string } };

function sessionContext(userId: string): AuthContext {
  return {
    method: "session",
    userId,
    appId: "keys-api",
    scopes: [],
    groupIds: [],
  };
}

/**
 * Gates a route to Clerk-authenticated users who are members of the
 * admin group (env.ADMIN_GROUP_ID). Sets c.set("userId", ...) for
 * downstream handlers on success.
 */
export async function requireAdmin(c: Context<ContextEnv>, next: Next) {
  const requiredScope = "account:admin";
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "missing-credentials" });
    return c.json({ error: "missing-credentials" }, 401);
  }
  if (token.length > 8192) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  const session = await verifyClerkSession(token, c.env);
  if (!session) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  await ensureUserRow(session.userId, c.env);
  const context = sessionContext(session.userId);
  annotateAuthenticatedRequest(context, "keys-api", requiredScope);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "user-inactive", context });
    return c.json({ error: "user-inactive" }, 403);
  }
  const rateBucket = `session:${session.userId}`;
  const rateLimit = await checkRateLimit(c.env, `session:${session.userId}`, {
    windowSeconds: 60,
    maxRequests: 120,
  });
  recordRateLimitDecision("keys-api", rateBucket, rateLimit.allowed ? "allowed" : "rate_limited", rateLimit.retryAfterSeconds, rateLimit.reason);
  if (!rateLimit.allowed) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: rateLimit.reason, context });
    return c.json({ error: rateLimit.reason }, 429);
  }

  const membership = await c.env.DB.prepare(
    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?"
  )
    .bind(c.env.ADMIN_GROUP_ID, session.userId)
    .first();

  if (!membership) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "not-admin", context });
    return c.json({ error: "not-admin" }, 403);
  }

  recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "allowed", context });
  c.set("userId", session.userId);
  await next();
}

/** Only requires a valid Clerk session — for self-service routes. */
export async function requireUser(c: Context<ContextEnv>, next: Next) {
  if (c.env.MCP_DELEGATION) {
    const path = new URL(c.req.url).pathname;
    if (path.includes("/api-keys") || path.endsWith("/session-api-key")) {
      return c.json({ error: "mcp-api-key-management-disabled" }, 403);
    }
    const requiredScope =
      c.req.method === "POST" && path.endsWith("/limit-increase-requests")
        ? "account:limits:request"
        : "account:read";
    const auth = await authenticate(c.req.raw, c.env, requiredScope, "keys-api");
    if (!auth.allowed || !auth.context) {
      return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
    }
    c.set("userId", auth.context.userId);
    await next();
    return;
  }
  const requiredScope = "account:self";
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "missing-credentials" });
    return c.json({ error: "missing-credentials" }, 401);
  }
  if (token.length > 8192) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  const session = await verifyClerkSession(token, c.env);
  if (!session) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  await ensureUserRow(session.userId, c.env);
  const context = sessionContext(session.userId);
  annotateAuthenticatedRequest(context, "keys-api", requiredScope);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: "user-inactive", context });
    return c.json({ error: "user-inactive" }, 403);
  }
  const rateBucket = `session:${session.userId}`;
  const rateLimit = await checkRateLimit(c.env, rateBucket, {
    windowSeconds: 60,
    maxRequests: 120,
  });
  recordRateLimitDecision("keys-api", rateBucket, rateLimit.allowed ? "allowed" : "rate_limited", rateLimit.retryAfterSeconds, rateLimit.reason);
  if (!rateLimit.allowed) {
    recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "denied", reason: rateLimit.reason, context });
    return c.json({ error: rateLimit.reason }, 429);
  }
  recordAuthDecision({ appId: "keys-api", requiredScope, outcome: "allowed", context });
  c.set("userId", session.userId);
  await next();
}
