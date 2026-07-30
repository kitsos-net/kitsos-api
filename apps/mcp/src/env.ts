import type { McpDelegation } from "@kitsos/auth";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface Env {
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
}
