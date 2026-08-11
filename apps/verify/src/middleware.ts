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
    appId: "verify",
    scopes: [],
    groupIds: [],
  };
}

export async function requireUser(c: Context<ContextEnv>, next: Next) {
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (c.env.MCP_DELEGATION || token.startsWith("kitsos_")) {
    const requiredScope = c.req.method === "GET" ? "verify:read" : "verify:manage";
    const auth = await authenticate(c.req.raw, c.env, requiredScope, "verify");
    if (!auth.allowed || !auth.context) {
      return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
    }
    c.set("userId", auth.context.userId);
    await next();
    return;
  }
  const requiredScope = "verify:session";
  if (!token) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "missing-credentials" });
    return c.json({ error: "missing-credentials" }, 401);
  }
  if (token.length > 8192) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  const session = await verifyClerkSession(token, c.env);
  if (!session) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  await ensureUserRow(session.userId, c.env);
  const context = sessionContext(session.userId);
  annotateAuthenticatedRequest(context, "verify", requiredScope);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "user-inactive", context });
    return c.json({ error: "user-inactive" }, 403);
  }
  const rateBucket = `session:${session.userId}`;
  const rateLimit = await checkRateLimit(c.env, rateBucket, {
    windowSeconds: 60,
    maxRequests: 60,
  });
  recordRateLimitDecision("verify", rateBucket, rateLimit.allowed ? "allowed" : "rate_limited", rateLimit.retryAfterSeconds, rateLimit.reason);
  if (!rateLimit.allowed) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: rateLimit.reason, context });
    return c.json({ error: rateLimit.reason }, 429);
  }
  recordAuthDecision({ appId: "verify", requiredScope, outcome: "allowed", context });
  c.set("userId", session.userId);
  await next();
}

export async function requireAdmin(c: Context<ContextEnv>, next: Next) {
  const requiredScope = "verify:admin";
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "missing-credentials" });
    return c.json({ error: "missing-credentials" }, 401);
  }
  if (token.length > 8192) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  const session = await verifyClerkSession(token, c.env);
  if (!session) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return c.json({ error: "invalid-credentials" }, 401);
  }

  await ensureUserRow(session.userId, c.env);
  const context = sessionContext(session.userId);
  annotateAuthenticatedRequest(context, "verify", requiredScope);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "user-inactive", context });
    return c.json({ error: "user-inactive" }, 403);
  }
  const rateBucket = `session:${session.userId}`;
  const rateLimit = await checkRateLimit(c.env, rateBucket, {
    windowSeconds: 60,
    maxRequests: 60,
  });
  recordRateLimitDecision("verify", rateBucket, rateLimit.allowed ? "allowed" : "rate_limited", rateLimit.retryAfterSeconds, rateLimit.reason);
  if (!rateLimit.allowed) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: rateLimit.reason, context });
    return c.json({ error: rateLimit.reason }, 429);
  }

  const membership = await c.env.DB.prepare(
    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?"
  )
    .bind(c.env.ADMIN_GROUP_ID, session.userId)
    .first();

  if (!membership) {
    recordAuthDecision({ appId: "verify", requiredScope, outcome: "denied", reason: "not-admin", context });
    return c.json({ error: "not-admin" }, 403);
  }

  recordAuthDecision({ appId: "verify", requiredScope, outcome: "allowed", context });
  c.set("userId", session.userId);
  await next();
}
