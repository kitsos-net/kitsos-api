import type { Context, Next } from "hono";
import {
  authenticate,
  checkRateLimit,
  verifyClerkSession,
  ensureUserRow,
} from "@kitsos/auth";
import type { Env } from "./env";

type ContextEnv = { Bindings: Env; Variables: { userId: string } };

/**
 * Gates a route to Clerk-authenticated users who are members of the
 * admin group (env.ADMIN_GROUP_ID). Sets c.set("userId", ...) for
 * downstream handlers on success.
 */
export async function requireAdmin(c: Context<ContextEnv>, next: Next) {
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return c.json({ error: "missing-credentials" }, 401);
  if (token.length > 8192) return c.json({ error: "invalid-credentials" }, 401);

  const session = await verifyClerkSession(token, c.env);
  if (!session) return c.json({ error: "invalid-credentials" }, 401);

  await ensureUserRow(session.userId, c.env);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") return c.json({ error: "user-inactive" }, 403);
  const rateLimit = await checkRateLimit(c.env, `session:${session.userId}`, {
    windowSeconds: 60,
    maxRequests: 120,
  });
  if (!rateLimit.allowed) return c.json({ error: rateLimit.reason }, 429);

  const membership = await c.env.DB.prepare(
    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?"
  )
    .bind(c.env.ADMIN_GROUP_ID, session.userId)
    .first();

  if (!membership) return c.json({ error: "not-admin" }, 403);

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
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return c.json({ error: "missing-credentials" }, 401);
  if (token.length > 8192) return c.json({ error: "invalid-credentials" }, 401);

  const session = await verifyClerkSession(token, c.env);
  if (!session) return c.json({ error: "invalid-credentials" }, 401);

  await ensureUserRow(session.userId, c.env);
  const user = await c.env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(session.userId)
    .first<{ status: string }>();
  if (user?.status !== "active") return c.json({ error: "user-inactive" }, 403);
  const rateLimit = await checkRateLimit(c.env, `session:${session.userId}`, {
    windowSeconds: 60,
    maxRequests: 120,
  });
  if (!rateLimit.allowed) return c.json({ error: rateLimit.reason }, 429);
  c.set("userId", session.userId);
  await next();
}
