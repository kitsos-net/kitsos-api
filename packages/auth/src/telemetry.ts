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
  const eventOutcome = fields.reason?.includes("rate-limit")
    ? "rate_limited"
    : fields.outcome;
  const attributes = {
    "event.name": "auth.decision",
    "event.category": "authentication",
    "event.outcome": eventOutcome,
    ...(fields.reason ? { "event.reason": fields.reason } : {}),
    "kitsos.event.name": "auth.decision",
    "kitsos.event.outcome": eventOutcome,
    ...(fields.reason ? { "kitsos.event.reason": fields.reason } : {}),
    "kitsos.api.name": fields.appId,
    "kitsos.app.id": fields.appId,
    "kitsos.request.scope": fields.requiredScope,
    ...(fields.reason ? { "error.code": fields.reason } : {}),
    ...(fields.context ? {
      "kitsos.user.id": fields.context.userId,
      "kitsos.auth.method": fields.context.method,
    } : {}),
    ...(fields.context?.apiKeyId ? { "kitsos.api_key.id": fields.context.apiKeyId } : {}),
    ...(fields.keyFingerprint ? { "kitsos.api_key.fingerprint": fields.keyFingerprint } : {}),
  };
  span.addEvent("auth.decision", attributes);
  span.setAttributes(attributes);
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
    "event.name": "resource.authorization",
    "event.category": "authorization",
    "event.outcome": outcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.event.name": "resource.authorization",
    "kitsos.event.outcome": outcome,
    ...(reason ? { "kitsos.event.reason": reason } : {}),
    "kitsos.user.id": context.userId,
    "kitsos.api.name": context.appId,
    "kitsos.app.id": context.appId,
    "kitsos.resource.type": resourceType,
    ...(resourceId ? { "kitsos.resource.id": resourceId } : {}),
    ...(context.apiKeyId ? { "kitsos.api_key.id": context.apiKeyId } : {}),
    ...(reason ? { "error.code": reason } : {}),
  };
  span.addEvent("resource.authorization", attributes);
  span.setAttributes(attributes);
}

export function recordUsageDecision(
  userId: string,
  appId: string,
  limitType: string,
  outcome: "allowed" | "denied",
  current: number,
  cost: number,
  limit: number,
  reason?: string
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const eventOutcome = reason?.includes("limit") && outcome === "denied"
    ? "rate_limited"
    : outcome;
  const attributes = {
    "event.name": "usage.decision",
    "event.category": "usage",
    "event.outcome": eventOutcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.event.name": "usage.decision",
    "kitsos.event.outcome": eventOutcome,
    ...(reason ? { "kitsos.event.reason": reason } : {}),
    "kitsos.user.id": userId,
    "kitsos.api.name": appId,
    "kitsos.app.id": appId,
    "limit.type": limitType,
    "limit.value": limit,
    "usage.current": current,
    "usage.cost": cost,
    "usage.next": current + cost,
    ...(reason ? { "error.code": reason } : {}),
  };
  span.addEvent("usage.decision", attributes);
  span.setAttributes(attributes);
}

export function recordRateLimitDecision(
  appId: string,
  bucket: string,
  outcome: "allowed" | "rate_limited",
  retryAfterSeconds?: number
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const reason = outcome === "rate_limited" ? "rate-limit-exceeded" : undefined;
  const attributes = {
    "event.name": "rate_limit.decision",
    "event.category": "rate_limit",
    "event.outcome": outcome,
    ...(reason ? { "event.reason": reason } : {}),
    "kitsos.event.name": "rate_limit.decision",
    "kitsos.event.outcome": outcome,
    ...(reason ? { "kitsos.event.reason": reason, "error.code": reason } : {}),
    "kitsos.api.name": appId,
    "kitsos.app.id": appId,
    "limit.bucket": bucket,
    ...(retryAfterSeconds ? { "limit.retry_after_seconds": retryAfterSeconds } : {}),
  };
  span.addEvent("rate_limit.decision", attributes);
  span.setAttributes(attributes);
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
    "kitsos.api.name": appId ?? context.appId,
    "kitsos.app.id": appId ?? context.appId,
    "kitsos.auth.method": context.method,
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
