const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_RECIPIENTS = 50;

export function isNonEmptyString(value: unknown, maxLength = 500): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= maxLength;
}

export function isEmail(value: unknown): value is string {
  return isNonEmptyString(value, 320) && EMAIL_PATTERN.test(value);
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function isEmailList(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= MAX_RECIPIENTS
    && value.every(isEmail);
}

export function isStringRecord(
  value: unknown,
  maxEntries = 200,
  maxValueLength = 64 * 1024
): value is Record<string, string> {
  return typeof value === "object"
    && value !== null
    && !Array.isArray(value)
    && Object.entries(value).length <= maxEntries
    && Object.entries(value).every(([key, item]) =>
      isNonEmptyString(key, 100) && typeof item === "string" && item.length <= maxValueLength
    );
}

export function safeTemplateUrl(value: unknown): string | null {
  if (!isNonEmptyString(value, 2048)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
    const hostname = url.hostname.toLowerCase();
    if (
      hostname === "localhost"
      || hostname.endsWith(".localhost")
      || hostname.endsWith(".local")
      || hostname === "[::1]"
      || hostname === "0.0.0.0"
      || /^127\./.test(hostname)
      || /^10\./.test(hostname)
      || /^192\.168\./.test(hostname)
      || /^169\.254\./.test(hostname)
      || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)
    ) {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}
