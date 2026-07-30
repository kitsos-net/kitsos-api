export interface Env {
  DB: D1Database;
  AUTH_CACHE: KVNamespace;
  USAGE_COUNTERS: KVNamespace;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  /** Present only on a private Worker service-binding entrypoint. */
  MCP_DELEGATION?: McpDelegation;
}

export type AuthMethod = "session" | "api_key" | "mcp";

export interface McpDelegation {
  userId: string;
  clientId: string;
  grantId: string;
  scopes: string[];
}

export interface AuthContext {
  method: AuthMethod;
  userId: string;
  appId: string;
  apiKeyId?: string;
  credentialId?: string;
  clientId?: string;
  scopes: string[];         // effective scopes (from key AND policy, intersected)
  groupIds: string[];
}

export interface CheckResult {
  allowed: boolean;
  status: number;           // 401 | 403 | 429 | 200
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
