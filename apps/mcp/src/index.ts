import { WorkerEntrypoint } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
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

export class McpApiHandler extends WorkerEntrypoint<Env, McpProps> {
  async fetch(request: Request): Promise<Response> {
    const props: unknown = this.ctx.props;
    if (!isMcpProps(props)) {
      return Response.json({ error: "invalid-oauth-token-properties" }, { status: 401 });
    }
    const scopes = await effectiveMcpScopes(this.env, props.userId, props.scopes);
    const context: ToolContext = {
      env: this.env,
      scopes,
      delegation: {
        userId: props.userId,
        clientId: props.clientId,
        grantId: props.delegationId,
        scopes: props.scopes,
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

export default oauthProvider;
