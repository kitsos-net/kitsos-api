import type { GrantSummary } from "@cloudflare/workers-oauth-provider";
import { getEffectiveLimit } from "@kitsos/auth";
import type { Env } from "./env";
import { SCOPE_BY_ID } from "./scopes";

export const MAX_CLIENT_NAME_LENGTH = 100;
export const MAX_DESCRIPTION_LENGTH = 500;

export async function connectedAppsLimit(
  env: Env,
  userId: string,
): Promise<number> {
  return getEffectiveLimit(env, userId, "mcp_connections");
}

export interface McpConnectionRow {
  delegation_id: string;
  user_id: string;
  client_id: string;
  client_name: string | null;
  description: string | null;
  granted_scopes: string;
  configured_scopes: string;
  created_at: number;
  updated_at: number;
}

export function delegationIdFromGrant(grant: GrantSummary): string | null {
  const value = grant.metadata?.delegationId;
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value)
    ? value
    : null;
}

export function normalizeClientName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (!normalized) return null;
  return [...normalized].slice(0, MAX_CLIENT_NAME_LENGTH).join("");
}

export function normalizeDescription(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new Error("invalid-description");
  const normalized = value.trim();
  if (
    [...normalized].length > MAX_DESCRIPTION_LENGTH
    || new TextEncoder().encode(normalized).byteLength > 2_000
  ) {
    throw new Error("description-too-long");
  }
  return normalized || null;
}

export function validScopeSelection(
  value: unknown,
  grantedScopes: string[],
): string[] | null {
  if (
    !Array.isArray(value)
    || value.length < 1
    || value.length > SCOPE_BY_ID.size
    || value.some((scope) => typeof scope !== "string")
  ) {
    return null;
  }
  const granted = new Set(grantedScopes.filter((scope) => SCOPE_BY_ID.has(scope)));
  const selected = [...new Set(value as string[])];
  return selected.every((scope) => granted.has(scope)) ? selected : null;
}

function grantScopes(grant: GrantSummary): string[] {
  return [...new Set(grant.scope.filter((scope) => SCOPE_BY_ID.has(scope)))];
}

export async function syncConnections(
  env: Env,
  userId: string,
  grants: GrantSummary[],
): Promise<void> {
  const statements = grants.flatMap((grant) => {
    const delegationId = delegationIdFromGrant(grant);
    const scopes = grantScopes(grant);
    if (!delegationId || !scopes.length || grant.clientId.length > 256) return [];
    const clientName = normalizeClientName(grant.metadata?.clientName);
    return [env.DB.prepare(
      `INSERT OR IGNORE INTO mcp_connections
         (delegation_id, user_id, client_id, client_name, description,
          granted_scopes, configured_scopes, created_at, updated_at)
       VALUES (?, ?, ?, ?, NULL, ?, ?, ?, unixepoch())`,
    ).bind(
      delegationId,
      userId,
      grant.clientId,
      clientName,
      JSON.stringify(scopes),
      JSON.stringify(scopes),
      grant.createdAt,
    )];
  });
  if (statements.length) await env.DB.batch(statements);
}

export async function reconcileConnections(
  env: Env,
  userId: string,
  grants: GrantSummary[],
): Promise<void> {
  await syncConnections(env, userId, grants);
  const active = grants
    .map(delegationIdFromGrant)
    .filter((value): value is string => value !== null);
  if (!active.length) {
    await env.DB.prepare(
      "DELETE FROM mcp_connections WHERE user_id = ?",
    ).bind(userId).run();
    return;
  }
  const placeholders = active.map(() => "?").join(",");
  await env.DB.prepare(
    `DELETE FROM mcp_connections
     WHERE user_id = ? AND delegation_id NOT IN (${placeholders})`,
  ).bind(userId, ...active).run();
}

export async function createConnection(
  env: Env,
  input: {
    delegationId: string;
    userId: string;
    clientId: string;
    clientName: string | null;
    description: string | null;
    scopes: string[];
    limit: number;
  },
): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO mcp_connections
       (delegation_id, user_id, client_id, client_name, description,
        granted_scopes, configured_scopes)
     SELECT ?, ?, ?, ?, ?, ?, ?
     WHERE (
       SELECT COUNT(*) FROM mcp_connections WHERE user_id = ?
     ) < ?`,
  ).bind(
    input.delegationId,
    input.userId,
    input.clientId,
    input.clientName,
    input.description,
    JSON.stringify(input.scopes),
    JSON.stringify(input.scopes),
    input.userId,
    input.limit,
  ).run();
  return (result.meta.changes ?? 0) === 1;
}

export async function deleteConnection(
  env: Env,
  userId: string,
  delegationId: string,
): Promise<void> {
  await env.DB.prepare(
    "DELETE FROM mcp_connections WHERE user_id = ? AND delegation_id = ?",
  ).bind(userId, delegationId).run();
}

export async function connectionRows(
  env: Env,
  userId: string,
): Promise<McpConnectionRow[]> {
  const rows = await env.DB.prepare(
    `SELECT delegation_id, user_id, client_id, client_name, description,
            granted_scopes, configured_scopes, created_at, updated_at
     FROM mcp_connections
     WHERE user_id = ?
     ORDER BY created_at DESC`,
  ).bind(userId).all<McpConnectionRow>();
  return rows.results;
}

export async function updateConnection(
  env: Env,
  input: {
    userId: string;
    delegationId: string;
    description: string | null;
    scopes: string[];
  },
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE mcp_connections
     SET description = ?, configured_scopes = ?, updated_at = unixepoch()
     WHERE user_id = ? AND delegation_id = ?`,
  ).bind(
    input.description,
    JSON.stringify(input.scopes),
    input.userId,
    input.delegationId,
  ).run();
  return (result.meta.changes ?? 0) === 1;
}

export async function configuredScopes(
  env: Env,
  userId: string,
  delegationId: string,
  grantedScopes: string[],
): Promise<string[]> {
  const row = await env.DB.prepare(
    `SELECT configured_scopes
     FROM mcp_connections
     WHERE user_id = ? AND delegation_id = ?`,
  ).bind(userId, delegationId).first<{ configured_scopes: string }>();
  if (!row) return grantedScopes;
  try {
    const configured: unknown = JSON.parse(row.configured_scopes);
    const selected = validScopeSelection(configured, grantedScopes);
    return selected ?? [];
  } catch {
    return [];
  }
}
