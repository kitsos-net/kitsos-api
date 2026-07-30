import type {
  Env,
  AuthContext,
  CheckResult,
  RateLimitOptions,
  UsageLimitOptions,
} from "./types";

const AUTH_CACHE_TTL_SECONDS = 60;

const IMPLIED_SCOPES: Record<string, string[]> = {
  "mail:manage": ["mail:read"],
  "hme:manage": ["hme:read"],
  "verify:manage": ["verify:read"],
};

export function expandScopes(scopes: string[]): string[] {
  const expanded = new Set(scopes);
  for (const scope of scopes) {
    for (const implied of IMPLIED_SCOPES[scope] ?? []) expanded.add(implied);
  }
  return [...expanded];
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  if (data.byteLength > 16 * 1024) {
    throw new Error("hash input too large");
  }
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index++) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

async function invalidateHashes(env: Env, hashes: string[]): Promise<void> {
  await Promise.all(hashes.map((hash) => env.AUTH_CACHE.delete(`auth:${hash}`)));
}

export async function invalidateApiKeyCache(env: Env, keyId: string): Promise<void> {
  const row = await env.DB.prepare("SELECT key_hash FROM api_keys WHERE id = ?")
    .bind(keyId)
    .first<{ key_hash: string }>();
  if (!row) return;
  const apps = await env.DB.prepare("SELECT app_id FROM api_key_apps WHERE api_key_id = ?")
    .bind(keyId)
    .all<{ app_id: string }>();
  await Promise.all([
    env.AUTH_CACHE.delete(`auth:${row.key_hash}`),
    ...apps.results.map((app) => env.AUTH_CACHE.delete(`auth:${row.key_hash}:${app.app_id}`)),
  ]);
}

export async function invalidateUserApiKeyCaches(
  env: Env,
  userId: string,
  appId?: string
): Promise<void> {
  const rows = await env.DB.prepare("SELECT key_hash FROM api_keys WHERE user_id = ?")
    .bind(userId)
    .all<{ key_hash: string }>();
  const hashes = rows.results.map((row) => row.key_hash);
  const apps = await env.DB.prepare(
    `SELECT DISTINCT k.key_hash, a.app_id
     FROM api_keys k
     JOIN api_key_apps a ON a.api_key_id = k.id
     WHERE k.user_id = ? ${appId ? "AND a.app_id = ?" : ""}`
  )
    .bind(userId, ...(appId ? [appId] : []))
    .all<{ key_hash: string; app_id: string }>();
  await Promise.all([
    invalidateHashes(env, hashes),
    ...apps.results.map((row) => env.AUTH_CACHE.delete(`auth:${row.key_hash}:${row.app_id}`)),
  ]);
}

export async function invalidateGroupApiKeyCaches(
  env: Env,
  groupId: string,
  appId?: string
): Promise<void> {
  const rows = await env.DB.prepare(
    `SELECT DISTINCT k.key_hash, a.app_id
     FROM api_keys k
     JOIN group_members gm ON gm.user_id = k.user_id
     JOIN api_key_apps a ON a.api_key_id = k.id
     WHERE gm.group_id = ? ${appId ? "AND a.app_id = ?" : ""}`
  )
    .bind(groupId, ...(appId ? [appId] : []))
    .all<{ key_hash: string; app_id: string }>();
  await Promise.all(rows.results.flatMap((row) => [
    env.AUTH_CACHE.delete(`auth:${row.key_hash}`),
    env.AUTH_CACHE.delete(`auth:${row.key_hash}:${row.app_id}`),
  ]));
}

export async function invalidateAppApiKeyCaches(env: Env, appId: string): Promise<void> {
  const rows = await env.DB.prepare(
    `SELECT k.key_hash
     FROM api_keys k
     JOIN api_key_apps a ON a.api_key_id = k.id
     WHERE a.app_id = ?`
  )
    .bind(appId)
    .all<{ key_hash: string }>();
  await Promise.all(rows.results.flatMap((row) => [
    env.AUTH_CACHE.delete(`auth:${row.key_hash}:${appId}`),
    env.AUTH_CACHE.delete(`auth:${row.key_hash}`),
  ]));
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
  if (rawKey.length > 256 || appId.length > 63) return null;
  const keyHash = await sha256Hex(rawKey);
  const cacheKey = `auth:${keyHash}:${appId}`;

  const cached = await env.AUTH_CACHE.get<
    AuthContext & { credentialExpiresAt?: number | null }
  >(cacheKey, "json").catch(() => null);
  if (cached) {
    if (
      cached.credentialExpiresAt
      && cached.credentialExpiresAt <= Math.floor(Date.now() / 1000)
    ) {
      await env.AUTH_CACHE.delete(cacheKey);
      if (cached.apiKeyId) {
        await env.DB.prepare("DELETE FROM api_keys WHERE id = ? AND expires_at <= unixepoch()")
          .bind(cached.apiKeyId)
          .run();
      }
      return null;
    }
    const { credentialExpiresAt: _expiresAt, ...context } = cached;
    return context;
  }

  const row = await env.DB.prepare(
    `SELECT k.id, k.user_id, a.app_id, k.status, a.scopes, k.expires_at
     FROM api_keys k
     JOIN api_key_apps a ON a.api_key_id = k.id
     JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ? AND a.app_id = ? AND u.status = 'active'`
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
  if (row.expires_at && row.expires_at <= Date.now() / 1000) {
    await env.DB.prepare("DELETE FROM api_keys WHERE id = ?")
      .bind(row.id)
      .run();
    return null;
  }

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

  const policyScopes = new Set<string>(expandScopes(
    policyRows.results.flatMap((p) => JSON.parse(p.scopes) as string[])
  ));
  const keyScopes: string[] = JSON.parse(row.scopes);
  const effectiveScopes = expandScopes(keyScopes.filter((s) => policyScopes.has(s)));

  const context: AuthContext = {
    method: "api_key",
    userId: row.user_id,
    appId: row.app_id,
    apiKeyId: row.id,
    scopes: effectiveScopes,
    groupIds,
  };

  // Authentication must remain available when the optional KV cache reaches
  // its daily write allowance. D1 is the source of truth; a failed cache write
  // only makes this path less efficient and must not reject a valid key.
  await env.AUTH_CACHE.put(cacheKey, JSON.stringify({
    ...context,
    credentialExpiresAt: row.expires_at,
  }), {
    expirationTtl: AUTH_CACHE_TTL_SECONDS,
  }).catch(() => {});

  // Fire-and-forget last_used_at update — not awaited to keep hot path fast
  env.DB.prepare("UPDATE api_keys SET last_used_at = unixepoch() WHERE id = ?")
    .bind(row.id)
    .run()
    .catch(() => {});

  return context;
}

export async function getPolicyScopes(
  env: Pick<Env, "DB">,
  userId: string,
  appId: string
): Promise<{ scopes: string[]; groupIds: string[] } | null> {
  const user = await env.DB.prepare("SELECT status FROM users WHERE id = ?")
    .bind(userId)
    .first<{ status: string }>();
  if (!user || user.status !== "active") return null;

  const groupRows = await env.DB.prepare(
    "SELECT group_id FROM group_members WHERE user_id = ?"
  )
    .bind(userId)
    .all<{ group_id: string }>();
  const groupIds = groupRows.results.map((g) => g.group_id);
  const placeholders = groupIds.map(() => "?").join(",") || "''";
  const policies = await env.DB.prepare(
    `SELECT scopes FROM policies
     WHERE app_id = ? AND (
       (subject_type = 'user' AND subject_id = ?) OR
       (subject_type = 'group' AND subject_id IN (${placeholders}))
     )`
  )
    .bind(appId, userId, ...groupIds)
    .all<{ scopes: string }>();

  const scopes = expandScopes(policies.results.flatMap(
    (policy) => JSON.parse(policy.scopes) as string[]
  ));
  return { scopes, groupIds };
}

/**
 * MCP consent scopes normally follow the same D1 policies as API keys.
 * Account self-service is the deliberate exception: every active Clerk user
 * can already use these routes without a policy, so MCP may narrow that
 * existing right through explicit consent but must not require an unrelated
 * admin-created policy first.
 */
export async function getMcpPolicyScopes(
  env: Pick<Env, "DB">,
  userId: string,
  appId: string,
): Promise<{ scopes: string[]; groupIds: string[] } | null> {
  const policy = await getPolicyScopes(env, userId, appId);
  if (!policy) return null;
  if (appId !== "keys-api") return policy;
  return {
    ...policy,
    scopes: expandScopes([
      ...policy.scopes,
      "account:read",
      "account:limits:request",
    ]),
  };
}

export function checkScope(context: AuthContext, requiredScope: string): CheckResult {
  if (expandScopes(context.scopes).includes(requiredScope)) {
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
     JOIN resource_verifications rv ON rv.id = rg.verification_id
     WHERE rg.resource_id = ? AND rg.user_id = ?
       AND rv.resource_id = rg.resource_id
       AND rv.user_id = rg.user_id
       AND rv.verified_at IS NOT NULL
     LIMIT 1`
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
 * Atomic fixed-window rate limiter backed by D1. KV is intentionally not used
 * here: its free-tier write allowance is far below the platform's request
 * allowance, so a KV write per request can make every protected route fail.
 */
export async function checkRateLimit(
  env: Pick<Env, "DB">,
  bucketKey: string,
  options: RateLimitOptions
): Promise<CheckResult> {
  if (
    bucketKey.length < 1
    || bucketKey.length > 512
    || !Number.isInteger(options.windowSeconds)
    || options.windowSeconds < 1
    || options.windowSeconds > 86_400
    || !Number.isInteger(options.maxRequests)
    || options.maxRequests < 1
    || options.maxRequests > 1_000_000
  ) {
    return { allowed: false, status: 429, reason: "invalid-rate-limit-configuration" };
  }

  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / options.windowSeconds) * options.windowSeconds;
  const consumed = await env.DB.prepare(
    `INSERT INTO request_rate_counters
       (bucket_key, window_start, expires_at, count)
     VALUES (?, ?, ?, 1)
     ON CONFLICT(bucket_key, window_start)
     DO UPDATE SET count = count + 1
       WHERE count < ?
     RETURNING count`
  )
    .bind(
      bucketKey,
      windowStart,
      windowStart + options.windowSeconds,
      options.maxRequests
    )
    .first<{ count: number }>();

  if (!consumed) {
    return {
      allowed: false,
      status: 429,
      reason: "rate-limit-exceeded",
      retryAfterSeconds: Math.max(1, windowStart + options.windowSeconds - now),
    };
  }

  return { allowed: true, status: 200 };
}

/**
 * Daily usage limit against a configured budget in `usage_limits`.
 * The D1 upsert is atomic, unlike a read-then-write KV counter, so
 * concurrent requests cannot overshoot the configured budget.
 */
export async function checkUsageLimit(
  env: Env,
  context: AuthContext,
  options: UsageLimitOptions
): Promise<CheckResult> {
  const limitRow = await env.DB.prepare(
    `SELECT limit_value FROM usage_limits
     WHERE user_id = ? AND app_id = ? AND limit_type = ?
     ORDER BY is_override DESC, created_at DESC LIMIT 1`
  )
    .bind(context.userId, context.appId, options.limitType)
    .first<{ limit_value: number }>();

  if (!limitRow) {
    // No configured limit = no enforcement for this limit_type
    return { allowed: true, status: 200 };
  }

  const cost = options.cost ?? 1;
  if (
    !Number.isInteger(cost)
    || cost < 1
    || !/^[a-z][a-z0-9_]{0,63}$/.test(options.limitType)
  ) {
    return { allowed: false, status: 429, reason: "invalid-usage-limit-cost" };
  }
  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const consumed = await env.DB.prepare(
    `INSERT INTO daily_usage_counters
       (user_id, app_id, limit_type, day_bucket, count)
     SELECT ?, ?, ?, ?, ?
     WHERE ? <= ?
     ON CONFLICT(user_id, app_id, limit_type, day_bucket)
     DO UPDATE SET count = count + excluded.count
       WHERE count + excluded.count <= ?
     RETURNING count`
  )
    .bind(
      context.userId,
      context.appId,
      options.limitType,
      dayBucket,
      cost,
      cost,
      limitRow.limit_value,
      limitRow.limit_value
    )
    .first();
  return consumed
    ? { allowed: true, status: 200 }
    : { allowed: false, status: 429, reason: "usage-limit-exceeded" };
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
    context?: AuthContext;
  }
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO audit_log
       (id, user_id, app_id, api_key_id, action, resource_id, result, reason,
        auth_method, credential_id, client_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      crypto.randomUUID(),
      entry.userId ?? null,
      entry.appId ?? null,
      entry.apiKeyId ?? null,
      entry.action,
      entry.resourceId ?? null,
      entry.result,
      entry.reason ?? null,
      entry.context?.method ?? (entry.apiKeyId ? "api_key" : null),
      entry.context?.credentialId ?? entry.apiKeyId ?? null,
      entry.context?.clientId ?? null,
    )
    .run()
    .catch(() => {}); // audit logging must never break the request
}
