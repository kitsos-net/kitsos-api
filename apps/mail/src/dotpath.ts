/**
 * Resolves a single dot-notation path against a JSON payload.
 * Missing paths resolve to an empty string rather than throwing —
 * a malformed upstream payload should degrade gracefully, not crash
 * the send.
 */
function resolveDotPath(obj: unknown, path: string): string {
  if (path === "now") return new Date().toISOString();

  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return "";
    current = (current as Record<string, unknown>)[part];
  }
  return current == null ? "" : String(current);
}

/**
 * Applies a webhook's {templateVar: "dot.path"} mapping against an
 * incoming payload, producing the flat variable map a template needs.
 */
export function resolvePayload(
  mapping: Record<string, string>,
  payload: unknown
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [templateVar, path] of Object.entries(mapping)) {
    result[templateVar] = resolveDotPath(payload, path);
  }
  return result;
}
