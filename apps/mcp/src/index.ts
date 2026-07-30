import { WorkerEntrypoint } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { checkRateLimit } from "@kitsos/auth";
import { createMcpHandler } from "agents/mcp/server";
import { authHandler } from "./auth-handler";
import type { Env, McpProps, ToolContext } from "./env";
import {
  effectiveMcpScopes,
  isMcpProps,
  SUPPORTED_SCOPES,
} from "./scopes";
import { createKitsosMcpServer } from "./tools";

const MCP_URL = "https://mcp.api.kitsos.net/mcp";
const ORIGIN = "https://mcp.api.kitsos.net";
const MCP_MAX_BODY_BYTES = 256 * 1024;

function rateLimitResponse(retryAfterSeconds = 60): Response {
  return Response.json(
    {
      error: "rate-limit-exceeded",
      message: "Zu viele Anfragen. Bitte versuche es später erneut.",
    },
    {
      status: 429,
      headers: {
        "Cache-Control": "no-store",
        "Retry-After": String(retryAfterSeconds),
      },
    },
  );
}

function requestIp(request: Request): string {
  const value = request.headers.get("CF-Connecting-IP") ?? "unknown";
  return /^[0-9A-Fa-f:.]{2,64}$/.test(value) ? value : "unknown";
}

async function publicEndpointRateLimit(
  request: Request,
  env: Env,
  pathname: string,
): Promise<Response | null> {
  const options = pathname === "/register"
    ? { windowSeconds: 60 * 60, maxRequests: 10 }
    : pathname === "/token"
      ? { windowSeconds: 60, maxRequests: 60 }
      : pathname === "/authorize"
        ? { windowSeconds: 60, maxRequests: 30 }
        : null;
  if (!options) return null;
  const result = await checkRateLimit(
    env,
    `mcp-public:${pathname}:${requestIp(request)}`,
    options,
  );
  return result.allowed ? null : rateLimitResponse(result.retryAfterSeconds);
}

async function boundedRequest(
  request: Request,
  maxBytes: number,
): Promise<Request | Response> {
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) {
    return Response.json({ error: "request-too-large" }, { status: 413 });
  }
  if (!request.body) return request;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    length += result.value.byteLength;
    if (length > maxBytes) {
      await reader.cancel();
      return Response.json({ error: "request-too-large" }, { status: 413 });
    }
    chunks.push(result.value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body,
    redirect: request.redirect,
  });
}

function invalidRegistration(message: string): Response {
  return Response.json(
    { error: "invalid_client_metadata", error_description: message },
    { status: 400, headers: { "Cache-Control": "no-store" } },
  );
}

function validateRegistration(requestBody: Uint8Array): Response | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(requestBody));
  } catch {
    return invalidRegistration("Invalid JSON payload");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return invalidRegistration("Client metadata must be an object");
  }
  const metadata = value as Record<string, unknown>;
  const boundedString = (field: string, max: number): boolean => {
    const item = metadata[field];
    return item === undefined
      || (
        typeof item === "string"
        && [...item].length <= max
        && new TextEncoder().encode(item).byteLength <= max * 4
      );
  };
  if (!boundedString("client_name", 100)) {
    return invalidRegistration("client_name must not exceed 100 characters");
  }
  for (const field of ["logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri"]) {
    if (!boundedString(field, 2_048)) {
      return invalidRegistration(`${field} must not exceed 2048 characters`);
    }
  }
  const boundedArray = (
    field: string,
    maxItems: number,
    maxLength: number,
  ): boolean => {
    const item = metadata[field];
    return item === undefined
      || (
        Array.isArray(item)
        && item.length <= maxItems
        && item.every((entry) => (
          typeof entry === "string" && [...entry].length <= maxLength
        ))
      );
  };
  if (!boundedArray("redirect_uris", 10, 2_048)) {
    return invalidRegistration("redirect_uris is limited to 10 entries");
  }
  if (!boundedArray("contacts", 5, 254)) {
    return invalidRegistration("contacts is limited to 5 entries");
  }
  if (
    !boundedArray("grant_types", 5, 64)
    || !boundedArray("response_types", 5, 64)
  ) {
    return invalidRegistration("OAuth type metadata is too large");
  }
  return null;
}

export class McpApiHandler extends WorkerEntrypoint<Env, McpProps> {
  async fetch(request: Request): Promise<Response> {
    const props: unknown = this.ctx.props;
    if (!isMcpProps(props)) {
      return Response.json({ error: "invalid-oauth-token-properties" }, { status: 401 });
    }
    const connectionRate = await checkRateLimit(
      this.env,
      `mcp-server:connection:${props.delegationId}`,
      { windowSeconds: 60, maxRequests: 120 },
    );
    if (!connectionRate.allowed) {
      return rateLimitResponse(connectionRate.retryAfterSeconds);
    }
    const userRate = await checkRateLimit(
      this.env,
      `mcp-server:user:${props.userId}`,
      { windowSeconds: 60, maxRequests: 300 },
    );
    if (!userRate.allowed) return rateLimitResponse(userRate.retryAfterSeconds);
    const scopes = await effectiveMcpScopes(
      this.env,
      props.userId,
      props.delegationId,
      props.scopes,
    );
    const context: ToolContext = {
      env: this.env,
      scopes,
      delegation: {
        userId: props.userId,
        clientId: props.clientId,
        grantId: props.delegationId,
        scopes: [...scopes],
      },
    };
    const handler = createMcpHandler(
      () => createKitsosMcpServer(context),
      {
        route: "/mcp",
        allowedHostnames: ["mcp.api.kitsos.net"],
        allowedOriginHostnames: ["mcp.api.kitsos.net"],
        authContext: { props: { ...props } },
      },
    );
    return handler(request, this.env, this.ctx);
  }
}

const oauthProvider = new OAuthProvider<Env>({
  apiRoute: "/mcp",
  apiHandler: McpApiHandler,
  defaultHandler: authHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: SUPPORTED_SCOPES,
  allowImplicitFlow: false,
  allowPlainPKCE: false,
  allowTokenExchangeGrant: false,
  accessTokenTTL: 60 * 60,
  refreshTokenTTL: 30 * 24 * 60 * 60,
  resourceMetadata: {
    resource: MCP_URL,
    authorization_servers: [ORIGIN],
    scopes_supported: SUPPORTED_SCOPES,
    bearer_methods_supported: ["header"],
    resource_name: "Kitsos API MCP",
  },
  tokenExchangeCallback(options) {
    if (!isMcpProps(options.props)) return;
    return {
      accessTokenProps: {
        ...options.props,
        scopes: options.requestedScope,
      } satisfies McpProps,
    };
  },
  onError({ status, code, description, headers }) {
    console.warn(JSON.stringify({
      service: "kitsos-mcp",
      event: "oauth-error",
      status,
      code,
      description,
    }));
    return Response.json(
      { error: code, error_description: description },
      { status, headers },
    );
  },
});

const worker: ExportedHandler<Env> = {
  async fetch(request, env, ctx) {
    const pathname = new URL(request.url).pathname;
    const limited = await publicEndpointRateLimit(request, env, pathname);
    if (limited) return limited;

    if (
      pathname === "/mcp"
      && request.method === "POST"
      && Number(request.headers.get("Content-Length") ?? "0") > MCP_MAX_BODY_BYTES
    ) {
      return Response.json({ error: "request-too-large" }, { status: 413 });
    }

    const bodyLimit = pathname === "/register"
      ? 32 * 1024
      : pathname === "/token"
        ? 16 * 1024
        : (
          request.method === "POST"
          && (
            pathname.startsWith("/consent/")
            || pathname.startsWith("/connections/")
          )
        )
          ? 16 * 1024
          : null;
    let forwarded: Request = request;
    if (bodyLimit !== null) {
      const bounded = await boundedRequest(request, bodyLimit);
      if (bounded instanceof Response) return bounded;
      forwarded = bounded;
    }

    if (pathname === "/register" && request.method === "POST") {
      const registrationBody = new Uint8Array(await forwarded.clone().arrayBuffer());
      const invalid = validateRegistration(registrationBody);
      if (invalid) return invalid;
    }
    return oauthProvider.fetch(forwarded, env, ctx);
  },
};

export default worker;
