import type { McpDelegation } from "@kitsos/auth";
import type { TelemetryEnv } from "@kitsos/telemetry";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface Env extends TelemetryEnv {
  DB: D1Database;
  AUTH_CACHE: KVNamespace;
  USAGE_COUNTERS: KVNamespace;
  CLERK_PUBLISHABLE_KEY: string;
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  IDENTITY: Fetcher;
  MAIL: Fetcher;
  HIDE_MY_EMAIL: Fetcher;
  UTILITY: Fetcher;
  VERIFY: Fetcher;
  KEYS_API: Fetcher;
}

export interface McpProps {
  userId: string;
  clientId: string;
  delegationId: string;
  scopes: string[];
}

export interface ToolContext {
  env: Env;
  delegation: McpDelegation;
  scopes: Set<string>;
  telemetry: {
    toolName?: string;
    upstreamService?: string;
    upstreamStatus?: number;
    outcome?: "success" | "error";
    reason?: string;
  };
}
