import { trace } from "@opentelemetry/api";
import type { AuthContext } from "./types";

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
