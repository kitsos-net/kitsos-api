import type { Env, AuthContext, CheckResult, RateLimitOptions } from "./types";
import { verifyClerkSession, ensureUserRow } from "./clerk";
import { acceptPrivateMcpDelegation, mcpDelegationHeaders } from "./delegation";
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
  checkUsageLimit,
  writeAuditLog,
  sha256Hex,
  constantTimeEqual,
  expandScopes,
  getPolicyScopes,
  getMcpPolicyScopes,
  invalidateApiKeyCache,
  invalidateAppApiKeyCaches,
  invalidateGroupApiKeyCaches,
  invalidateUserApiKeyCaches,
} from "./checks";

export * from "./types";
export * from "./limits";
export {
  verifyClerkSession,
  ensureUserRow,
  validateApiKey,
  checkScope,
  checkResourceGrant,
  checkRateLimit,
  checkUsageLimit,
  writeAuditLog,
  sha256Hex,
  constantTimeEqual,
  expandScopes,
  getPolicyScopes,
  getMcpPolicyScopes,
  invalidateApiKeyCache,
  invalidateAppApiKeyCaches,
  invalidateGroupApiKeyCaches,
  invalidateUserApiKeyCaches,
  acceptPrivateMcpDelegation,
  mcpDelegationHeaders,
  annotateAuthenticatedRequest,
  recordAuthDecision,
  recordRateLimitDecision,
};

export function withRetryAfter(response: Response, result: CheckResult): Response {
  if (result.retryAfterSeconds) {
    response.headers.set("Retry-After", String(result.retryAfterSeconds));
  }
  return response;
}

const DEFAULT_RATE_LIMIT: RateLimitOptions = { windowSeconds: 60, maxRequests: 60 };

export async function authenticateMcpDelegation(
  env: Env,
  requiredScope: string,
  appId: string,
): Promise<(CheckResult & { context?: AuthContext }) | null> {
  const delegation = env.MCP_DELEGATION;
  if (!delegation) return null;
  if (
    !delegation.userId
    || !delegation.clientId
    || !delegation.grantId
    || !Array.isArray(delegation.scopes)
  ) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-mcp-delegation",
    });
    return { allowed: false, status: 401, reason: "invalid-mcp-delegation" };
  }
  const policy = await getMcpPolicyScopes(env, delegation.userId, appId);
  if (!policy) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-credentials",
    });
    return { allowed: false, status: 401, reason: "invalid-credentials" };
  }
  const allowed = new Set(expandScopes(policy.scopes));
  const context: AuthContext = {
    method: "mcp",
    userId: delegation.userId,
    appId,
    credentialId: delegation.grantId,
    clientId: delegation.clientId,
    scopes: expandScopes(delegation.scopes.filter((scope) => allowed.has(scope))),
    groupIds: policy.groupIds,
  };
  annotateAuthenticatedRequest(context, appId, requiredScope);
  const scopeCheck = checkScope(context, requiredScope);
  if (!scopeCheck.allowed) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: scopeCheck.reason,
      context,
    });
    return { ...scopeCheck, context };
  }
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
  const delegated = await authenticateMcpDelegation(env, requiredScope, appId);
  if (delegated) {
    if (!delegated.allowed) {
      await writeAuditLog(env, {
        userId: delegated.context?.userId,
        appId,
        action: requiredScope,
        result: "denied",
        reason: delegated.reason,
        context: delegated.context,
      });
      return delegated;
    }
    const context = delegated.context!;
    const rateBucket = `mcp:${context.userId}:${context.clientId}:${appId}`;
    const rlCheck = await checkRateLimit(
      env,
      rateBucket,
      rateLimit,
    );
    recordRateLimitDecision(
      appId,
      rateBucket,
      rlCheck.allowed ? "allowed" : "rate_limited",
      rlCheck.retryAfterSeconds,
      rlCheck.reason,
    );
    if (!rlCheck.allowed) {
      await writeAuditLog(env, {
        userId: context.userId,
        appId,
        action: requiredScope,
        result: "denied",
        reason: rlCheck.reason,
        context,
      });
      recordAuthDecision({
        appId,
        requiredScope,
        outcome: "denied",
        reason: rlCheck.reason,
        context,
      });
      return rlCheck;
    }
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      action: requiredScope,
      result: "allowed",
      context,
    });
    recordAuthDecision({ appId, requiredScope, outcome: "allowed", context });
    return delegated;
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");

  if (!token) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "missing-credentials",
    });
    return { allowed: false, status: 401, reason: "missing-credentials" };
  }
  if (token.length > 8192) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-credentials",
    });
    return { allowed: false, status: 401, reason: "invalid-credentials" };
  }

  let context: AuthContext | null = null;

  if (token.startsWith("kitsos_")) {
    context = await validateApiKey(token, appId, env);
  } else {
    const session = await verifyClerkSession(token, env);
    if (session) {
      await ensureUserRow(session.userId, env);
      const policy = await getPolicyScopes(env, session.userId, appId);
      if (policy) {
        context = {
          method: "session",
          userId: session.userId,
          appId,
          scopes: policy.scopes,
          groupIds: policy.groupIds,
        };
      }
    }
  }

  if (!context) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-credentials",
      ...(token.startsWith("kitsos_")
        ? { keyFingerprint: (await sha256Hex(token)).slice(0, 16) }
        : {}),
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
      context,
    });
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: scopeCheck.reason,
      context,
    });
    return scopeCheck;
  }

  const rateBucket = context.apiKeyId
    ? `api-key:${context.apiKeyId}:${appId}`
    : `session:${context.userId}`;
  const rlCheck = await checkRateLimit(
    env,
    rateBucket,
    rateLimit
  );
  recordRateLimitDecision(
    appId,
    rateBucket,
    rlCheck.allowed ? "allowed" : "rate_limited",
    rlCheck.retryAfterSeconds,
    rlCheck.reason,
  );
  if (!rlCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: rlCheck.reason,
      context,
    });
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: rlCheck.reason,
      context,
    });
    return rlCheck;
  }

  await writeAuditLog(env, {
    userId: context.userId,
    appId,
    apiKeyId: context.apiKeyId,
    action: requiredScope,
    result: "allowed",
    context,
  });
  recordAuthDecision({ appId, requiredScope, outcome: "allowed", context });

  return { allowed: true, status: 200, context };
}

/**
 * API-key-only counterpart to `authenticate`. Use this for machine-to-machine
 * endpoints such as Grafana data sources, where accepting a browser session
 * would accidentally make a user JWT a valid service credential.
 */
export async function authenticateApiKey(
  request: Request,
  env: Env,
  requiredScope: string,
  appId: string,
  rateLimit: RateLimitOptions = DEFAULT_RATE_LIMIT,
  authorization: { requiredGroupId?: string } = {},
): Promise<CheckResult & { context?: AuthContext }> {
  const authHeader = request.headers.get("Authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");

  if (!token) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "missing-credentials",
    });
    return { allowed: false, status: 401, reason: "missing-credentials" };
  }
  if (token.length > 256) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "invalid-credentials",
    });
    return { allowed: false, status: 401, reason: "invalid-credentials" };
  }
  if (!token.startsWith("kitsos_")) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "api-key-required",
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
      context,
    });
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: scopeCheck.reason,
      context,
    });
    return scopeCheck;
  }

  if (
    authorization.requiredGroupId !== undefined
    && !authorization.requiredGroupId
  ) {
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: "required-group-not-configured",
      context,
    });
    return {
      allowed: false,
      status: 503,
      reason: "required-group-not-configured",
    };
  }

  const rateBucket = `api-key:${context.apiKeyId}:${appId}`;
  const rlCheck = await checkRateLimit(env, rateBucket, rateLimit);
  recordRateLimitDecision(
    appId,
    rateBucket,
    rlCheck.allowed ? "allowed" : "rate_limited",
    rlCheck.retryAfterSeconds,
    rlCheck.reason,
  );
  if (!rlCheck.allowed) {
    await writeAuditLog(env, {
      userId: context.userId,
      appId,
      apiKeyId: context.apiKeyId,
      action: requiredScope,
      result: "denied",
      reason: rlCheck.reason,
      context,
    });
    recordAuthDecision({
      appId,
      requiredScope,
      outcome: "denied",
      reason: rlCheck.reason,
      context,
    });
    return rlCheck;
  }

  if (authorization.requiredGroupId !== undefined) {
    // Resolve privileged membership from D1 on every request rather than
    // trusting the cached AuthContext. Admin removal must take effect
    // immediately, independently of the API-key cache TTL.
    const membership = await env.DB.prepare(
      `SELECT 1
       FROM group_members gm
       JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = ? AND gm.user_id = ? AND u.status = 'active'
       LIMIT 1`
    )
      .bind(authorization.requiredGroupId, context.userId)
      .first();
    if (!membership) {
      const denied = { allowed: false, status: 403, reason: "not-admin" } as const;
      await writeAuditLog(env, {
        userId: context.userId,
        appId,
        apiKeyId: context.apiKeyId,
        action: requiredScope,
        result: "denied",
        reason: denied.reason,
        context,
      });
      recordAuthDecision({
        appId,
        requiredScope,
        outcome: "denied",
        reason: denied.reason,
        context,
      });
      return denied;
    }
  }

  await writeAuditLog(env, {
    userId: context.userId,
    appId,
    apiKeyId: context.apiKeyId,
    action: requiredScope,
    result: "allowed",
    context,
  });
  recordAuthDecision({ appId, requiredScope, outcome: "allowed", context });

  return { allowed: true, status: 200, context };
}
