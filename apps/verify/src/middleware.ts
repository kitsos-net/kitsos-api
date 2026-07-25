import type { Context, Next } from "hono";
import { authenticateApiKey, verifyClerkSession, ensureUserRow } from "@kitsos/auth";
import type { Env } from "./env";

export const VERIFY_MANAGE_SCOPE = "verify:manage";
type VerifyContext = Context<{ Bindings: Env; Variables: { userId: string } }>;

/**
 * Authorizes self-service verification routes with a scoped Kitsos API key.
 * Administrative routes intentionally remain Clerk-session-only below.
 */
export async function requireUser(c: VerifyContext, next: Next) {
  const auth = await authenticateApiKey(c.req.raw, c.env, VERIFY_MANAGE_SCOPE, "verify");
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);

  c.set("userId", auth.context!.userId);
  await next();
}

export async function requireAdmin(c: VerifyContext, next: Next) {
  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return c.json({ error: "missing-credentials" }, 401);

  const session = await verifyClerkSession(token, c.env);
  if (!session) return c.json({ error: "invalid-credentials" }, 401);

  await ensureUserRow(session.userId, c.env);

  const membership = await c.env.DB.prepare(
    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?"
  )
    .bind(c.env.ADMIN_GROUP_ID, session.userId)
    .first();

  if (!membership) return c.json({ error: "not-admin" }, 403);

  c.set("userId", session.userId);
  await next();
}
