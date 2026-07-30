import type { AuthRequest, ClientInfo } from "@cloudflare/workers-oauth-provider";
import {
  expandScopes,
  getMcpPolicyScopes,
} from "@kitsos/auth";
import {
  connectionRows,
  connectedAppsLimit,
  createConnection,
  delegationIdFromGrant,
  deleteConnection,
  MAX_CLIENT_NAME_LENGTH,
  MAX_DESCRIPTION_LENGTH,
  normalizeClientName,
  normalizeDescription,
  reconcileConnections,
  syncConnections,
  updateConnection,
  validScopeSelection,
} from "./connections";
import type { Env, McpProps } from "./env";
import {
  SCOPE_BY_ID,
  SCOPE_CATALOG,
  SUPPORTED_SCOPES,
  exposableScopeIds,
} from "./scopes";
import {
  connectionsPage,
  consentPage,
  securityHeaders,
} from "./ui";

const CONSENT_TTL_SECONDS = 10 * 60;
const COOKIE = "__Host-kitsos_mcp_consent";

interface ConsentState {
  request: AuthRequest;
  client: Pick<ClientInfo, "clientId" | "clientName">;
  csrf: string;
  createdAt: number;
}

function randomToken(bytes = 24): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...value))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function parseCookie(request: Request, name: string): string | null {
  for (const part of (request.headers.get("Cookie") ?? "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return null;
}

function consentCookie(value: string, maxAge: number): string {
  return `${COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = new Headers(extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(error: unknown, status = 400): Response {
  const message = error instanceof Error ? error.message : "invalid-request";
  return json({ error: "invalid-request", message }, status);
}

async function currentUser(request: Request, env: Env): Promise<string | null> {
  const token = (request.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token || token.length > 8192) return null;
  const response = await env.IDENTITY.fetch("https://identity.internal/verify", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) return null;
  const identity = await response.json<{ userId?: unknown }>().catch(() => null);
  return typeof identity?.userId === "string" ? identity.userId : null;
}

function validPostOrigin(request: Request): boolean {
  if (request.method !== "POST") return true;
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

async function readConsentState(request: Request, env: Env): Promise<{
  key: string;
  state: ConsentState;
} | null> {
  const nonce = parseCookie(request, COOKIE);
  if (!nonce || !/^[A-Za-z0-9_-]{20,100}$/.test(nonce)) return null;
  const state = await env.OAUTH_KV.get<ConsentState>(`consent:${nonce}`, "json");
  if (!state || Date.now() / 1000 - state.createdAt > CONSENT_TTL_SECONDS) return null;
  return { key: `consent:${nonce}`, state };
}

async function availableScopes(
  env: Env,
  userId: string,
  requested: string[],
) {
  const requestedSet = new Set(requested.length ? requested : SUPPORTED_SCOPES);
  const exposable = await exposableScopeIds(env);
  const policyByApp = new Map<string, Set<string>>();
  await Promise.all([...new Set(SCOPE_CATALOG.map((scope) => scope.appId))].map(async (appId) => {
    const policy = await getMcpPolicyScopes(env, userId, appId);
    policyByApp.set(appId, new Set(policy?.scopes ?? []));
  }));
  return SCOPE_CATALOG.filter((scope) => (
    exposable.has(scope.id)
    &&
    requestedSet.has(scope.id)
    && policyByApp.get(scope.appId)?.has(scope.id)
  ));
}

async function authorizePage(request: Request, env: Env): Promise<Response> {
  const oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
  if (!client) return errorResponse(new Error("Unbekannter OAuth-Client."), 400);
  if (
    client.clientId.length > 256
    || (
      client.clientName !== undefined
      && [...client.clientName].length > MAX_CLIENT_NAME_LENGTH
    )
  ) {
    return errorResponse(new Error("Die OAuth-App enthält zu lange Metadaten."), 400);
  }
  if (oauthRequest.scope.some((scope) => !SCOPE_BY_ID.has(scope))) {
    return errorResponse(new Error("Der Client hat eine nicht unterstützte Berechtigung angefragt."), 400);
  }
  const expectedResource = new URL("/mcp", request.url).toString();
  const resources = oauthRequest.resource === undefined
    ? []
    : Array.isArray(oauthRequest.resource) ? oauthRequest.resource : [oauthRequest.resource];
  if (resources.some((resource) => resource !== expectedResource)) {
    return errorResponse(new Error("Die angefragte OAuth-Ressource stimmt nicht mit diesem MCP-Server überein."), 400);
  }

  const nonce = randomToken();
  const csrf = randomToken();
  const state: ConsentState = {
    request: oauthRequest,
    client: { clientId: client.clientId, clientName: client.clientName },
    csrf,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await env.OAUTH_KV.put(`consent:${nonce}`, JSON.stringify(state), {
    expirationTtl: CONSENT_TTL_SECONDS,
  });

  const cspNonce = randomToken(18);
  const headers = securityHeaders(cspNonce, env.CLERK_PUBLISHABLE_KEY);
  headers.set("Set-Cookie", consentCookie(nonce, CONSENT_TTL_SECONDS));
  return new Response(consentPage(env.CLERK_PUBLISHABLE_KEY, cspNonce, csrf), { headers });
}

async function consentContext(request: Request, env: Env): Promise<Response> {
  const [stored, userId] = await Promise.all([
    readConsentState(request, env),
    currentUser(request, env),
  ]);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  if (!stored) return json({ error: "authorization-expired" }, 410);
  const scopes = await availableScopes(env, userId, stored.state.request.scope);
  return json({
    client: {
      id: stored.state.client.clientId,
      name: stored.state.client.clientName || "Unbenannte App",
    },
    scopes: scopes.map((scope) => ({
      ...scope,
      preselected: scope.accessType === "read",
    })),
    limits: {
      descriptionLength: MAX_DESCRIPTION_LENGTH,
    },
  });
}

async function approveConsent(request: Request, env: Env): Promise<Response> {
  if (!validPostOrigin(request)) return json({ error: "invalid-origin" }, 403);
  const [stored, userId, body] = await Promise.all([
    readConsentState(request, env),
    currentUser(request, env),
    request.json<{
      csrf?: string;
      scopes?: unknown;
      description?: unknown;
    }>().catch(() => null),
  ]);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  if (!stored) return json({ error: "authorization-expired" }, 410);
  if (
    !body
    || body.csrf !== stored.state.csrf
    || !Array.isArray(body.scopes)
    || body.scopes.some((scope) => typeof scope !== "string")
  ) {
    return json({ error: "invalid-consent" }, 400);
  }

  const available = await availableScopes(env, userId, stored.state.request.scope);
  const availableIds = new Set(available.map((scope) => scope.id));
  const selected = [...new Set(body.scopes as string[])];
  if (!selected.length || selected.some((scope) => !availableIds.has(scope))) {
    return json({ error: "invalid-scope-selection" }, 400);
  }
  const description = normalizeDescription(body.description);
  const [grants, connectionLimit] = await Promise.all([
    env.OAUTH_PROVIDER.listUserGrants(userId, { limit: 100 }),
    connectedAppsLimit(env, userId),
  ]);
  await reconcileConnections(env, userId, grants.items);

  const delegationId = crypto.randomUUID();
  const clientName = normalizeClientName(stored.state.client.clientName);
  const created = await createConnection(env, {
    userId,
    clientId: stored.state.client.clientId,
    clientName,
    delegationId,
    description,
    scopes: selected,
    limit: connectionLimit,
  });
  if (!created) {
    return json({
      error: "connected-app-limit-exceeded",
      message: `Du kannst derzeit höchstens ${connectionLimit} Apps gleichzeitig verbinden.`,
      limit: connectionLimit,
    }, 409);
  }
  const props: McpProps = {
    userId,
    clientId: stored.state.client.clientId,
    delegationId,
    scopes: selected,
  };
  let redirectTo: string;
  try {
    const result = await env.OAUTH_PROVIDER.completeAuthorization({
      request: stored.state.request,
      userId,
      metadata: {
        clientName: clientName || "Unbenannte App",
        delegationId,
        scopes: selected,
      },
      scope: selected,
      props,
    });
    redirectTo = result.redirectTo;
  } catch (error) {
    await deleteConnection(env, userId, delegationId);
    throw error;
  }
  await env.OAUTH_KV.delete(stored.key);
  return json({ redirectTo }, 200, {
    "Set-Cookie": consentCookie("", 0),
  });
}

async function denyConsent(request: Request, env: Env): Promise<Response> {
  if (!validPostOrigin(request)) return json({ error: "invalid-origin" }, 403);
  const [stored, userId, body] = await Promise.all([
    readConsentState(request, env),
    currentUser(request, env),
    request.json<{ csrf?: string }>().catch(() => null),
  ]);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  if (!stored) return json({ error: "authorization-expired" }, 410);
  if (!body || body.csrf !== stored.state.csrf) return json({ error: "invalid-consent" }, 400);

  const redirect = new URL(stored.state.request.redirectUri);
  redirect.searchParams.set("error", "access_denied");
  redirect.searchParams.set("error_description", "The user denied the authorization request.");
  if (stored.state.request.state) redirect.searchParams.set("state", stored.state.request.state);
  await env.OAUTH_KV.delete(stored.key);
  return json({ redirectTo: redirect.toString() }, 200, {
    "Set-Cookie": consentCookie("", 0),
  });
}

function renderConnections(env: Env): Response {
  const nonce = randomToken(18);
  return new Response(connectionsPage(env.CLERK_PUBLISHABLE_KEY, nonce), {
    headers: securityHeaders(nonce, env.CLERK_PUBLISHABLE_KEY),
  });
}

async function connectionsContext(request: Request, env: Env): Promise<Response> {
  const userId = await currentUser(request, env);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  const [result, connectionLimit] = await Promise.all([
    env.OAUTH_PROVIDER.listUserGrants(userId, { limit: 100 }),
    connectedAppsLimit(env, userId),
  ]);
  await reconcileConnections(env, userId, result.items);
  const rows = await connectionRows(env, userId);
  const rowsByDelegation = new Map(rows.map((row) => [row.delegation_id, row]));
  return json({
    connections: result.items.flatMap((grant) => {
      const delegationId = delegationIdFromGrant(grant);
      if (!delegationId) return [];
      const row = rowsByDelegation.get(delegationId);
      let configured = grant.scope.filter((scope) => SCOPE_BY_ID.has(scope));
      if (row) {
        try {
          configured = validScopeSelection(
            JSON.parse(row.configured_scopes),
            grant.scope,
          ) ?? [];
        } catch {
          configured = [];
        }
      }
      const available = grant.scope
        .map((scope) => SCOPE_BY_ID.get(scope))
        .filter((scope) => scope !== undefined);
      return [{
        id: grant.id,
        clientId: grant.clientId,
        clientName: row?.client_name
          ?? normalizeClientName(grant.metadata?.clientName)
          ?? undefined,
        description: row?.description ?? "",
        scopes: configured,
        availableScopes: available,
        scopeCount: expandScopes(configured).length,
        createdAt: grant.createdAt,
      }];
    }),
    limits: {
      connectedApps: connectionLimit,
      descriptionLength: MAX_DESCRIPTION_LENGTH,
    },
  });
}

async function editConnection(request: Request, env: Env): Promise<Response> {
  if (!validPostOrigin(request)) return json({ error: "invalid-origin" }, 403);
  const [userId, body] = await Promise.all([
    currentUser(request, env),
    request.json<{
      grantId?: unknown;
      description?: unknown;
      scopes?: unknown;
    }>().catch(() => null),
  ]);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  if (
    !body
    || typeof body.grantId !== "string"
    || !/^[A-Za-z0-9_-]{1,256}$/.test(body.grantId)
  ) {
    return json({ error: "invalid-grant-id" }, 400);
  }
  const result = await env.OAUTH_PROVIDER.listUserGrants(userId, { limit: 100 });
  const grant = result.items.find((item) => item.id === body.grantId);
  if (!grant) return json({ error: "connection-not-found" }, 404);
  const delegationId = delegationIdFromGrant(grant);
  if (!delegationId) return json({ error: "invalid-connection" }, 409);
  const scopes = validScopeSelection(body.scopes, grant.scope);
  if (!scopes) return json({ error: "invalid-scope-selection" }, 400);
  const description = normalizeDescription(body.description);
  await syncConnections(env, userId, [grant]);
  const updated = await updateConnection(env, {
    userId,
    delegationId,
    description,
    scopes,
  });
  if (!updated) return json({ error: "connection-not-found" }, 404);
  return json({
    success: true,
    description,
    scopes,
    scopeCount: expandScopes(scopes).length,
  });
}

async function revokeConnection(request: Request, env: Env): Promise<Response> {
  if (!validPostOrigin(request)) return json({ error: "invalid-origin" }, 403);
  const [userId, body] = await Promise.all([
    currentUser(request, env),
    request.json<{ grantId?: string }>().catch(() => null),
  ]);
  if (!userId) return json({ error: "not-authenticated" }, 401);
  if (!body?.grantId || !/^[A-Za-z0-9_-]{1,256}$/.test(body.grantId)) {
    return json({ error: "invalid-grant-id" }, 400);
  }
  const grants = await env.OAUTH_PROVIDER.listUserGrants(userId, { limit: 100 });
  const grant = grants.items.find((item) => item.id === body.grantId);
  if (!grant) return json({ error: "connection-not-found" }, 404);
  await env.OAUTH_PROVIDER.revokeGrant(body.grantId, userId);
  const delegationId = delegationIdFromGrant(grant);
  if (delegationId) await deleteConnection(env, userId, delegationId);
  return json({ success: true });
}

export const authHandler: ExportedHandler<Env> = {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/authorize") {
        return authorizePage(request, env);
      }
      if (request.method === "GET" && url.pathname === "/consent/context") {
        return consentContext(request, env);
      }
      if (request.method === "POST" && url.pathname === "/consent/approve") {
        return approveConsent(request, env);
      }
      if (request.method === "POST" && url.pathname === "/consent/deny") {
        return denyConsent(request, env);
      }
      if (request.method === "GET" && url.pathname === "/connections") {
        return renderConnections(env);
      }
      if (request.method === "GET" && url.pathname === "/connections/context") {
        return connectionsContext(request, env);
      }
      if (request.method === "POST" && url.pathname === "/connections/update") {
        return editConnection(request, env);
      }
      if (request.method === "POST" && url.pathname === "/connections/revoke") {
        return revokeConnection(request, env);
      }
      if (request.method === "GET" && url.pathname === "/") {
        return Response.redirect(new URL("/connections", request.url).toString(), 302);
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true, service: "kitsos-mcp" });
      }
      return json({ error: "not-found" }, 404);
    } catch (error) {
      console.error("mcp-auth-handler", error instanceof Error ? error.message : error);
      return errorResponse(error, 400);
    }
  },
};
