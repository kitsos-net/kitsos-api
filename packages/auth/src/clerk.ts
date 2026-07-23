import { createClerkClient, verifyToken } from "@clerk/backend";
import type { Env } from "./types";

/**
 * Verifies a Clerk session JWT (from Authorization: Bearer <token> or
 * the __session cookie, forwarded by the frontend) and returns the
 * Clerk user ID (`sub`). Used for browser-authenticated requests
 * (Admin UI, myaccount, etc.) as opposed to API-key auth.
 */
export async function verifyClerkSession(
  token: string,
  env: Env
): Promise<{ userId: string } | null> {
  try {
    const payload = await verifyToken(token, {
      secretKey: env.CLERK_SECRET_KEY,
    });
    if (!payload?.sub) return null;
    return { userId: payload.sub };
  } catch {
    return null;
  }
}

/**
 * Lazily-constructed Clerk client, for cases where we need more than
 * token verification (e.g. fetching user email/display name to sync
 * into the `users` table on first sight).
 */
export function getClerkClient(env: Env) {
  return createClerkClient({
    secretKey: env.CLERK_SECRET_KEY,
    publishableKey: env.CLERK_PUBLISHABLE_KEY,
  });
}

/**
 * Ensures a `users` row exists for a given Clerk user ID, creating it
 * from Clerk profile data on first sight. Cheap D1 read on the common
 * path (row already exists).
 */
export async function ensureUserRow(userId: string, env: Env): Promise<void> {
  const existing = await env.DB.prepare("SELECT id FROM users WHERE id = ?")
    .bind(userId)
    .first();
  if (existing) return;

  const clerk = getClerkClient(env);
  const user = await clerk.users.getUser(userId);
  const email = user.emailAddresses[0]?.emailAddress ?? "";
  const displayName = [user.firstName, user.lastName].filter(Boolean).join(" ");

  await env.DB.prepare(
    "INSERT INTO users (id, email, display_name, status) VALUES (?, ?, ?, 'active')"
  )
    .bind(userId, email, displayName)
    .run();
}
