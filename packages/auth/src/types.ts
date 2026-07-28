export interface Env {
  DB: D1Database;
  AUTH_CACHE: KVNamespace;
  USAGE_COUNTERS: KVNamespace;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
}

export type AuthMethod = "session" | "api_key";

export interface AuthContext {
  method: AuthMethod;
  userId: string;
  appId: string;
  apiKeyId?: string;
  scopes: string[];         // effective scopes (from key AND policy, intersected)
  groupIds: string[];
}

export interface CheckResult {
  allowed: boolean;
  status: number;           // 200 | 401 | 403 | 429 | 503
  reason?: string;          // machine-readable, mirrors X-Forbidden-Reason
  retryAfterSeconds?: number;
}

export interface ResourceCheckOptions {
  resourceType: string;
  value: string;
  scope: string;
}

export interface RateLimitOptions {
  windowSeconds: number;
  maxRequests: number;
}

export interface UsageLimitOptions {
  limitType: string;        // e.g. "emails_per_day"
  cost?: number;             // default 1
}

export interface ApiKeyResourceGrant {
  resourceType: string;
  resourceId: string;
  scopes?: string[];
}
