import { trace } from "@opentelemetry/api";
import type { AuthContext } from "./types";

type DecisionFields = {
  appId: string;
  requiredScope: string;
  outcome: "allowed" | "denied";
  reason?: string;
  context?: AuthContext;
  keyFingerprint?: string;
};

export function recordAuthDecision(fields: DecisionFields): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const eventOutcome = fields.reason === "rate-limit-exceeded"
    ? "rate_limited"
    : fields.reason === "rate-limit-storage-unavailable"
      ? "error"
      : fields.outcome;
  const attributes = {
    "event.category": "authentication",
    "event.outcome": eventOutcome,
    ...(fields.reason ? { "event.reason": fields.reason } : {}),
    "kitsos.api.name": fields.appId,
    "kitsos.request.scope": fields.requiredScope,
    ...(fields.context ? {
      "kitsos.user.id": fields.context.userId,
      "kitsos.auth.method": fields.context.method,
    } : {}),
    ...(fields.context?.apiKeyId ? { "kitsos.api_key.id": fields.context.apiKeyId } : {}),
    ...(fields.keyFingerprint ? { "kitsos.api_key.fingerprint": fields.keyFingerprint } : {}),
  };
  span.addEvent("auth.decision", attributes);
}

export function recordResourceDecision(
  context: AuthContext,
  resourceType: string,
  resourceId: string | undefined,
  outcome: "allowed" | "denied",
  reason?: string
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const attributes = {
    "event.category": "authorization",
    "event.outcome": outcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.user.id": context.userId,
    "kitsos.api.name": context.appId,
    "kitsos.resource.type": resourceType,
    ...(resourceId ? { "kitsos.resource.id": resourceId } : {}),
    ...(context.apiKeyId ? { "kitsos.api_key.id": context.apiKeyId } : {}),
  };
  span.addEvent("resource.authorization", attributes);
}

export function recordUsageDecision(
  userId: string,
  appId: string,
  limitType: string,
  outcome: "allowed" | "denied" | "error",
  current: number,
  cost: number,
  limit: number,
  reason?: string
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const eventOutcome = reason === "usage-limit-exceeded" && outcome === "denied"
    ? "rate_limited"
    : outcome;
  const attributes = {
    "event.category": "usage",
    "event.outcome": eventOutcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.user.id": userId,
    "kitsos.api.name": appId,
    "limit.type": limitType,
    "limit.value": limit,
    "usage.current": current,
    "usage.cost": cost,
    "usage.next": current + cost,
  };
  span.addEvent("usage.decision", attributes);
}

export function recordRateLimitDecision(
  appId: string,
  bucket: string,
  outcome: "allowed" | "rate_limited" | "error",
  retryAfterSeconds?: number,
  failureReason?: string
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const reason = failureReason
    ?? (outcome === "rate_limited" ? "rate-limit-exceeded" : undefined);
  const attributes = {
    "event.category": "rate_limit",
    "event.outcome": outcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.api.name": appId,
    "limit.bucket": bucket,
    ...(retryAfterSeconds ? { "limit.retry_after_seconds": retryAfterSeconds } : {}),
  };
  span.addEvent("rate_limit.decision", attributes);
}

/**
 * Adds low-cardinality authentication dimensions to the active HTTP server
 * span. Axiom stores these custom attributes in `attributes.custom`.
 *
 * User and API-key IDs are internal identifiers, never credentials. Email
 * addresses, raw API keys and request bodies are deliberately not recorded.
 */
export function annotateAuthenticatedRequest(
  context: AuthContext,
  appId?: string,
  requiredScope?: string
): void {
  const span = trace.getActiveSpan();
  if (!span) return;

  span.setAttributes({
    "kitsos.user.id": context.userId,
    "kitsos.auth.method": context.method,
    "kitsos.api_key.used": context.method === "api_key",
    ...(context.apiKeyId ? { "kitsos.api_key.id": context.apiKeyId } : {}),
    ...(requiredScope ? { "kitsos.request.scope": requiredScope } : {}),
  });
}

export function annotateSessionRequest(userId: string): void {
  trace.getActiveSpan()?.setAttributes({
    "kitsos.user.id": userId,
    "kitsos.auth.method": "session",
  });
}
