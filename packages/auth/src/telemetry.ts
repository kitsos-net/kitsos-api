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
  const attributes = {
    "event.name": "auth.decision",
    "event.outcome": fields.outcome,
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
    "event.outcome": outcome,
    "kitsos.user.id": context.userId,
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
  const attributes = {
    "event.name": "usage.decision",
    "event.outcome": outcome,
    "kitsos.user.id": userId,
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
