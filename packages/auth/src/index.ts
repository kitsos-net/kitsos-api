import type { Env, AuthContext, CheckResult, RateLimitOptions } from "./types";
import { verifyClerkSession, ensureUserRow } from "./clerk";
import {
  annotateAuthenticatedRequest,
  recordAuthDecision,
  recordRateLimitDecision,
} from "./telemetry";
import {
  validateApiKey,
  checkScope,
  checkResourceGrant,
  checkRateLimit,
  resolveRateLimit,
  checkUsageLimit,
  checkUsageLimitForUser,
  getUsageLimit,
  checkKeyResourceAccess,
  writeAuditLog,
  sha256Hex,
} from "./checks";

export * from "./types";
export {
  verifyClerkSession,
  ensureUserRow,
  validateApiKey,
  checkScope,
  checkResourceGrant,
  checkRateLimit,
  resolveRateLimit,
  checkUsageLimit,
  checkUsageLimitForUser,
  getUsageLimit,
  checkKeyResourceAccess,
  writeAuditLog,
  sha256Hex,
  recordRateLimitDecision,
};

/** Applies RFC 9110's Retry-After header for exhausted or unavailable limiters. */
export function withRetryAfter(response: Response, check: CheckResult): Response {
  if ((check.status === 429 || check.status === 503) && check.retryAfterSeconds) {
    response.headers.set("Retry-After", String(check.retryAfterSeconds));
  }
  return response;
}

const DEFAULT_RATE_LIMIT: RateLimitOptions = { windowSeconds: 60, maxRequests: 60 };

/**
 * API-key-only variant for machine-facing endpoints. Unlike authenticate(),
 * this never falls back to a Clerk session token.
 */
export async function authenticateApiKey(
  request: Request,
  env: Env,
  requiredScope: string,
  appId: string,
  rateLimit: RateLimitOptions = DEFAULT_RATE_LIMIT
): Promise<CheckResult & { context?: AuthContext }> {
  const authHeader = request.headers.get("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");

  if (!token) {
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: "missing-credentials" });
    return { allowed: false, status: 401, reason: "missing-credentials" };
  }
  if (!token.startsWith("kitsos_")) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "api-key-required",
      keyFingerprint: (await sha256Hex(token)).slice(0, 16),
    });
    return { allowed: false, status: 401, reason: "api-key-required" };
  }

  const context = await validateApiKey(token, appId, env);
  if (!context) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-credentials",
      keyFingerprint: (await sha256Hex(token)).slice(0, 16),
    });
    return { allowed: false, status: 401, reason: "invalid-credentials" };
  }
  annotateAuthenticatedRequest(context, appId, requiredScope);

  const scopeCheck = checkScope(context, requiredScope);
  if (!scopeCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: scopeCheck.reason,
    });
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: scopeCheck.reason, context });
    return scopeCheck;
  }

  const rlCheck = await checkRateLimit(env, `${appId}:${context.apiKeyId!}`, await resolveRateLimit(env, appId, requiredScope, rateLimit));
  if (!rlCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: rlCheck.reason,
    });
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: rlCheck.reason, context });
    return rlCheck;
  }

  await writeAuditLog(env, {
    userId: context.userId,
    appId,
    apiKeyId: context.apiKeyId,
    action: requiredScope,
    result: "allowed",
  });
  recordAuthDecision({ appId, requiredScope, outcome: "allowed", context });

  return { allowed: true, status: 200, context };
}

/**
 * Standard entry point for app workers. Pulls credentials from the
 * request (Authorization header — either a Clerk session JWT or a
 * `kitsos_` API key), runs scope + rate-limit checks, and writes an
 * audit log entry. Resource-grant and usage-limit checks are left to
 * the caller since they need endpoint-specific parameters.
 *
 * Usage in an app worker:
 *
 *   const auth = await authenticate(request, env, "dns:record:write");
 *   if (!auth.allowed) return new Response(auth.reason, { status: auth.status });
 *   const ctx = auth.context!;
 */
export async function authenticate(
  request: Request,
  env: Env,
  requiredScope: string,
  appId: string,
  rateLimit: RateLimitOptions = DEFAULT_RATE_LIMIT
): Promise<CheckResult & { context?: AuthContext }> {
  const authHeader = request.headers.get("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");

  if (!token) {
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: "missing-credentials" });
    return { allowed: false, status: 401, reason: "missing-credentials" };
  }

  let context: AuthContext | null = null;

  if (token.startsWith("kitsos_")) {
    context = await validateApiKey(token, appId, env);
  } else {
    const session = await verifyClerkSession(token, env);
    if (session) {
      await ensureUserRow(session.userId, env);
      context = {
        method: "session",
        userId: session.userId,
        appId,
        scopes: [requiredScope], // session auth (Admin UI etc.) trusted at full scope; refine per-app if needed
        groupIds: [],
      };
    }
  }

  if (!context) {
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: "invalid-credentials" });
    return { allowed: false, status: 401, reason: "invalid-credentials" };
  }
  annotateAuthenticatedRequest(context, appId, requiredScope);

  const scopeCheck = checkScope(context, requiredScope);
  if (!scopeCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: scopeCheck.reason,
    });
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: scopeCheck.reason, context });
    return scopeCheck;
  }

  const rlCheck = await checkRateLimit(
    env,
    `${appId}:${context.apiKeyId ?? `session:${context.userId}`}`,
    await resolveRateLimit(env, appId, requiredScope, rateLimit)
  );
  if (!rlCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: rlCheck.reason,
    });
    recordAuthDecision({ appId, requiredScope, outcome: "denied", reason: rlCheck.reason, context });
    return rlCheck;
  }

  await writeAuditLog(env, {
    userId: context.userId,
    appId,
    apiKeyId: context.apiKeyId,
    action: requiredScope,
    result: "allowed",
  });
  recordAuthDecision({ appId, requiredScope, outcome: "allowed", context });

  return { allowed: true, status: 200, context };
}
