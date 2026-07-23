import type {
  Env,
  AuthContext,
  CheckResult,
  RateLimitOptions,
  UsageLimitOptions,
} from "./types";

const AUTH_CACHE_TTL_SECONDS = 60;

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Validates an API key against D1, with a 60s KV cache to stay well
 * under the Workers Free Tier D1 read budget. Returns null if the key
 * is invalid, revoked, or expired.
 */
export async function validateApiKey(
  rawKey: string,
  appId: string,
  env: Env
): Promise<AuthContext | null> {
  const keyHash = await sha256Hex(rawKey);
  const cacheKey = `auth:${keyHash}`;

  const cached = await env.AUTH_CACHE.get(cacheKey, "json");
  if (cached) return cached as AuthContext;

  const row = await env.DB.prepare(
    `SELECT id, user_id, app_id, status, scopes, expires_at
     FROM api_keys WHERE key_hash = ? AND app_id = ?`
  )
    .bind(keyHash, appId)
    .first<{
      id: string;
      user_id: string;
      app_id: string;
      status: string;
      scopes: string;
      expires_at: number | null;
    }>();

  if (!row) return null;
  if (row.status !== "active") return null;
  if (row.expires_at && row.expires_at < Date.now() / 1000) return null;

  const groupRows = await env.DB.prepare(
    "SELECT group_id FROM group_members WHERE user_id = ?"
  )
    .bind(row.user_id)
    .all<{ group_id: string }>();
  const groupIds = groupRows.results.map((g) => g.group_id);

  // Effective scopes = intersection of key scopes and policy scopes
  // (user or any of their groups) for this app. Key can only narrow,
  // never widen, what the policy allows.
  const policyRows = await env.DB.prepare(
    `SELECT scopes FROM policies
     WHERE app_id = ? AND (
       (subject_type = 'user' AND subject_id = ?) OR
       (subject_type = 'group' AND subject_id IN (${groupIds.map(() => "?").join(",") || "''"}))
     )`
  )
    .bind(appId, row.user_id, ...groupIds)
    .all<{ scopes: string }>();

  const policyScopes = new Set<string>(
    policyRows.results.flatMap((p) => JSON.parse(p.scopes) as string[])
  );
  const keyScopes: string[] = JSON.parse(row.scopes);
  const effectiveScopes = keyScopes.filter((s) => policyScopes.has(s));

  const context: AuthContext = {
    method: "api_key",
    userId: row.user_id,
    appId: row.app_id,
    apiKeyId: row.id,
    scopes: effectiveScopes,
    groupIds,
  };

  await env.AUTH_CACHE.put(cacheKey, JSON.stringify(context), {
    expirationTtl: AUTH_CACHE_TTL_SECONDS,
  });

  // Fire-and-forget last_used_at update — not awaited to keep hot path fast
  env.DB.prepare("UPDATE api_keys SET last_used_at = unixepoch() WHERE id = ?")
    .bind(row.id)
    .run()
    .catch(() => {});

  return context;
}

export function checkScope(context: AuthContext, requiredScope: string): CheckResult {
  if (context.scopes.includes(requiredScope)) {
    return { allowed: true, status: 200 };
  }
  return { allowed: false, status: 403, reason: "scope-missing" };
}

/**
 * Checks whether the authenticated user has a grant on the given
 * resource with the required scope, and that the underlying
 * verification hasn't expired past its grace period.
 */
export async function checkResourceGrant(
  env: Env,
  context: AuthContext,
  resourceType: string,
  value: string,
  scope: string
): Promise<CheckResult> {
  const resource = await env.DB.prepare(
    `SELECT id FROM resources WHERE app_id = ? AND resource_type = ? AND value = ?`
  )
    .bind(context.appId, resourceType, value)
    .first<{ id: string }>();

  if (!resource) return { allowed: false, status: 403, reason: "resource-not-found" };

  const grant = await env.DB.prepare(
    `SELECT rg.scopes, rv.grace_expires_at
     FROM resource_grants rg
     JOIN resource_verifications rv ON rv.resource_id = rg.resource_id AND rv.user_id = rg.user_id
     WHERE rg.resource_id = ? AND rg.user_id = ?
     ORDER BY rv.verified_at DESC LIMIT 1`
  )
    .bind(resource.id, context.userId)
    .first<{ scopes: string; grace_expires_at: number | null }>();

  if (!grant) return { allowed: false, status: 403, reason: "resource-not-granted" };

  const now = Date.now() / 1000;
  if (grant.grace_expires_at && grant.grace_expires_at < now) {
    return { allowed: false, status: 403, reason: "resource-verification-expired" };
  }

  const scopes: string[] = JSON.parse(grant.scopes);
  if (!scopes.includes(scope)) {
    return { allowed: false, status: 403, reason: "resource-scope-missing" };
  }

  return { allowed: true, status: 200 };
}

/**
 * Fixed-window rate limiter backed by KV. Not perfectly precise at
 * window boundaries, but cheap — one KV read + occasional write per
 * request, well within Free Tier budget for a handful of concurrent
 * keys. Swap for a Durable Object if precision becomes necessary.
 */
export async function checkRateLimit(
  env: Env,
  bucketKey: string,
  options: RateLimitOptions
): Promise<CheckResult> {
  const windowStart = Math.floor(Date.now() / 1000 / options.windowSeconds);
  const kvKey = `rl:${bucketKey}:${windowStart}`;

  const current = await env.USAGE_COUNTERS.get(kvKey);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= options.maxRequests) {
    return { allowed: false, status: 429, reason: "rate-limit-exceeded" };
  }

  await env.USAGE_COUNTERS.put(kvKey, String(count + 1), {
    expirationTtl: options.windowSeconds + 5,
  });

  return { allowed: true, status: 200 };
}

/**
 * Daily (or other window) usage limit against a configured budget in
 * `usage_limits`, with counters in KV (48h TTL, matches original
 * design) rather than D1 to avoid write-quota pressure.
 */
export async function checkUsageLimit(
  env: Env,
  context: AuthContext,
  options: UsageLimitOptions
): Promise<CheckResult> {
  const limitRow = await env.DB.prepare(
    `SELECT limit_value FROM usage_limits
     WHERE user_id = ? AND app_id = ? AND limit_type = ?
     ORDER BY is_override DESC LIMIT 1`
  )
    .bind(context.userId, context.appId, options.limitType)
    .first<{ limit_value: number }>();

  if (!limitRow) {
    // No configured limit = no enforcement for this limit_type
    return { allowed: true, status: 200 };
  }

  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const kvKey = `usage:${context.userId}:${context.appId}:${options.limitType}:${dayBucket}`;
  const current = await env.USAGE_COUNTERS.get(kvKey);
  const count = current ? parseInt(current, 10) : 0;
  const cost = options.cost ?? 1;

  if (count + cost > limitRow.limit_value) {
    return { allowed: false, status: 429, reason: "usage-limit-exceeded" };
  }

  await env.USAGE_COUNTERS.put(kvKey, String(count + cost), {
    expirationTtl: 172800, // 48h
  });

  return { allowed: true, status: 200 };
}

export async function writeAuditLog(
  env: Env,
  entry: {
    userId?: string;
    appId?: string;
    apiKeyId?: string;
    action: string;
    resourceId?: string;
    result: "allowed" | "denied";
    reason?: string;
  }
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO audit_log (id, user_id, app_id, api_key_id, action, resource_id, result, reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      crypto.randomUUID(),
      entry.userId ?? null,
      entry.appId ?? null,
      entry.apiKeyId ?? null,
      entry.action,
      entry.resourceId ?? null,
      entry.result,
      entry.reason ?? null
    )
    .run()
    .catch(() => {}); // audit logging must never break the request
}
