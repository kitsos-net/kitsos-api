import type {
  Env,
  AuthContext,
  CheckResult,
  RateLimitOptions,
  UsageLimitOptions,
} from "./types";

const AUTH_CACHE_TTL_SECONDS = 60;

export async function sha256Hex(input: string): Promise<string> {
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
  // The same key can be valid for several apps, so the effective policy
  // intersection is app-specific and must not share a cache entry.
  const cacheKey = `auth:${keyHash}:${appId}`;

  const cached = await env.AUTH_CACHE.get(cacheKey, "json");
  if (cached) return cached as AuthContext;

  const row = await env.DB.prepare(
    `SELECT k.id, k.user_id, k.app_id, k.status, k.scopes, k.expires_at
     FROM api_keys k
     WHERE k.key_hash = ?
       AND EXISTS (SELECT 1 FROM api_key_apps ka WHERE ka.api_key_id = k.id AND ka.app_id = ?)`
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
    // A multi-app key retains its original app_id for backwards-compatible
    // storage, but authorization and resource grants must use the API that
    // is currently being accessed.
    appId,
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
  const namespace = requiredScope.split(":", 1)[0];
  // Keep existing broad keys working while new keys can use narrowly scoped
  // permissions. This is deliberately one-way: a granular scope never
  // implies another granular scope.
  if (context.scopes.includes(requiredScope) || context.scopes.includes(`${namespace}:manage`)) {
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
  _scope: string
): Promise<CheckResult> {
  const normalizedValue = resourceType === "zone"
    ? value.trim().toLowerCase().replace(/\.$/, "")
    : value.trim().toLowerCase();
  // API-key scopes decide which operation is allowed. Resource verification
  // only proves ownership and is therefore valid platform-wide.
  const verification = await env.DB.prepare(
    `SELECT 1
     FROM resources r
     JOIN resource_verifications rv ON rv.resource_id = r.id AND rv.user_id = ?
     WHERE r.resource_type = ? AND r.value = ?
       AND rv.verified_at IS NOT NULL`
  )
    .bind(context.userId, resourceType, normalizedValue)
    .first();

  if (!verification) return { allowed: false, status: 403, reason: "resource-not-verified" };

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
    const now = Math.floor(Date.now() / 1000);
    return {
      allowed: false,
      status: 429,
      reason: "rate-limit-exceeded",
      retryAfterSeconds: Math.max(1, options.windowSeconds - (now % options.windowSeconds)),
    };
  }

  await env.USAGE_COUNTERS.put(kvKey, String(count + 1), {
    expirationTtl: options.windowSeconds + 5,
  });

  return { allowed: true, status: 200 };
}

/** Returns the most specific configured rate limit, or the safe default. */
export async function resolveRateLimit(
  env: Env,
  appId: string,
  scope: string,
  fallback: RateLimitOptions
): Promise<RateLimitOptions> {
  const row = await env.DB.prepare(
    `SELECT window_seconds, max_requests FROM rate_limit_rules
     WHERE app_id = ? AND (scope = ? OR scope IS NULL)
     ORDER BY CASE WHEN scope = ? THEN 0 ELSE 1 END LIMIT 1`
  ).bind(appId, scope, scope).first<{ window_seconds: number; max_requests: number }>();
  return row
    ? { windowSeconds: row.window_seconds, maxRequests: row.max_requests }
    : fallback;
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
  return checkUsageLimitForUser(env, context.userId, context.appId, options);
}

export async function getUsageLimit(
  env: Env,
  userId: string,
  appId: string,
  limitType: string
): Promise<number | null> {
  const limitRow = await env.DB.prepare(
    `SELECT limit_value FROM usage_limits
     WHERE user_id = ? AND app_id = ? AND limit_type = ?
     ORDER BY is_override DESC LIMIT 1`
  )
    .bind(userId, appId, limitType)
    .first<{ limit_value: number }>();

  if (limitRow) return limitRow.limit_value;
  const defaultRow = await env.DB.prepare(
    "SELECT limit_value FROM usage_limit_defaults WHERE app_id = ? AND limit_type = ?"
  ).bind(appId, limitType).first<{ limit_value: number }>();
  return defaultRow?.limit_value ?? null;
}

export async function checkUsageLimitForUser(
  env: Env,
  userId: string,
  appId: string,
  options: UsageLimitOptions
): Promise<CheckResult> {
  const limitValue = await getUsageLimit(env, userId, appId, options.limitType);

  if (limitValue === null) {
    // No configured limit = no enforcement for this limit_type
    return { allowed: true, status: 200 };
  }

  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const kvKey = `usage:${userId}:${appId}:${options.limitType}:${dayBucket}`;
  const current = await env.USAGE_COUNTERS.get(kvKey);
  const count = current ? parseInt(current, 10) : 0;
  const cost = options.cost ?? 1;

  if (count + cost > limitValue) {
    const now = Math.floor(Date.now() / 1000);
    return {
      allowed: false,
      status: 429,
      reason: "usage-limit-exceeded",
      retryAfterSeconds: Math.max(1, 86400 - (now % 86400)),
    };
  }

  await env.USAGE_COUNTERS.put(kvKey, String(count + cost), {
    expirationTtl: 172800, // 48h
  });

  return { allowed: true, status: 200 };
}

/** Enforces optional per-key resource allow-lists. Session auth is unrestricted. */
export async function checkKeyResourceAccess(
  env: Env,
  context: AuthContext,
  resourceType: string,
  resourceId: string,
  scope: string
): Promise<CheckResult> {
  if (!context.apiKeyId) return { allowed: true, status: 200 };
  const rules = await env.DB.prepare(
    "SELECT resource_id, scopes FROM api_key_resource_grants WHERE api_key_id = ? AND resource_type = ?"
  ).bind(context.apiKeyId, resourceType).all<{ resource_id: string; scopes: string }>();
  if (rules.results.length === 0) return { allowed: true, status: 200 };
  const grant = rules.results.find((rule) => rule.resource_id === resourceId);
  if (!grant) return { allowed: false, status: 403, reason: "key-resource-not-granted" };
  const scopes: string[] = JSON.parse(grant.scopes);
  return scopes.length === 0 || scopes.includes(scope)
    ? { allowed: true, status: 200 }
    : { allowed: false, status: 403, reason: "key-resource-scope-missing" };
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
