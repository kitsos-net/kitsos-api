import type { Env, McpDelegation } from "./types";

const USER_HEADER = "X-Kitsos-MCP-User";
const CLIENT_HEADER = "X-Kitsos-MCP-Client";
const GRANT_HEADER = "X-Kitsos-MCP-Grant";
const SCOPES_HEADER = "X-Kitsos-MCP-Scopes";
const INTERNAL_HEADERS = [USER_HEADER, CLIENT_HEADER, GRANT_HEADER, SCOPES_HEADER];
const ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,256}$/;
const SCOPE_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z0-9-]+)+$/;

/**
 * Converts the identity headers supplied by the MCP Worker's private service
 * binding into an environment-only delegation. Public Worker entrypoints must
 * never call this helper: browsers can forge request headers, but they cannot
 * invoke a named WorkerEntrypoint through a service binding.
 */
export function acceptPrivateMcpDelegation<T extends Env>(
  env: T,
  request: Request,
): { env: T; request: Request; delegation: McpDelegation } | null {
  const userId = request.headers.get(USER_HEADER) ?? "";
  const clientId = request.headers.get(CLIENT_HEADER) ?? "";
  const grantId = request.headers.get(GRANT_HEADER) ?? "";
  const rawScopes = request.headers.get(SCOPES_HEADER) ?? "";
  if (
    !ID_PATTERN.test(userId)
    || !ID_PATTERN.test(clientId)
    || !ID_PATTERN.test(grantId)
    || rawScopes.length < 1
    || rawScopes.length > 4096
  ) {
    return null;
  }

  const scopes = [...new Set(rawScopes.split(" ").filter(Boolean))];
  if (
    scopes.length < 1
    || scopes.length > 64
    || scopes.some((scope) => !SCOPE_PATTERN.test(scope) || scope.length > 100)
  ) {
    return null;
  }

  const delegation: McpDelegation = { userId, clientId, grantId, scopes };
  const delegatedEnv = Object.create(env) as T;
  Object.defineProperty(delegatedEnv, "MCP_DELEGATION", {
    value: Object.freeze(delegation),
    enumerable: false,
    writable: false,
  });

  const headers = new Headers(request.headers);
  for (const header of INTERNAL_HEADERS) headers.delete(header);
  headers.delete("Authorization");
  return {
    env: delegatedEnv,
    request: new Request(request, { headers }),
    delegation,
  };
}

export function mcpDelegationHeaders(delegation: McpDelegation): Headers {
  const headers = new Headers();
  headers.set(USER_HEADER, delegation.userId);
  headers.set(CLIENT_HEADER, delegation.clientId);
  headers.set(GRANT_HEADER, delegation.grantId);
  headers.set(SCOPES_HEADER, delegation.scopes.join(" "));
  return headers;
}
