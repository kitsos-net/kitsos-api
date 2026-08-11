import { mcpDelegationHeaders } from "@kitsos/auth";
import { SpanStatusCode, trace } from "@opentelemetry/api";
import type { ToolContext } from "./env";

export type UpstreamName = "MAIL" | "HIDE_MY_EMAIL" | "UTILITY" | "VERIFY" | "KEYS_API";

export interface UpstreamCall {
  service: UpstreamName;
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
}

export interface UpstreamResult {
  ok: boolean;
  status: number;
  data: unknown;
}

export async function callUpstream(
  context: ToolContext,
  toolName: string,
  call: UpstreamCall,
): Promise<UpstreamResult> {
  try {
    const result = await callUpstreamRequest(context, call);
    recordToolSpan(toolName, call.service, result);
    return result;
  } catch (error) {
    recordToolSpan(toolName, call.service, {
      ok: false,
      status: 0,
      data: { error: "upstream-fetch-failed" },
    });
    throw error;
  }
}

function recordToolSpan(
  toolName: string,
  service: UpstreamName,
  result: UpstreamResult,
): void {
  const errorCode = !result.ok
    && typeof result.data === "object"
    && result.data !== null
    && typeof (result.data as { error?: unknown }).error === "string"
    ? (result.data as { error: string }).error
    : undefined;
  const span = trace.getTracer("kitsos.mcp.tools").startSpan(`mcp.tool ${toolName}`, {
    attributes: {
      "kitsos.mcp.tool.name": toolName,
      "kitsos.mcp.upstream.service": service.toLowerCase(),
      "http.upstream.status_code": result.status,
    },
  });
  span.addEvent("mcp.tool.call", {
    "event.category": "mcp",
    "event.outcome": result.ok ? "success" : "error",
    "kitsos.mcp.tool.name": toolName,
    "kitsos.mcp.upstream.service": service.toLowerCase(),
    "http.upstream.status_code": result.status,
    ...(errorCode ? { "event.reason": errorCode } : {}),
  });
  if (!result.ok) span.setStatus({ code: SpanStatusCode.ERROR });
  span.end();
}

async function callUpstreamRequest(
  context: ToolContext,
  call: UpstreamCall,
): Promise<UpstreamResult> {
  const url = new URL(call.path, `https://${call.service.toLowerCase()}.internal`);
  for (const [name, value] of Object.entries(call.query ?? {})) {
    if (value !== undefined) url.searchParams.set(name, String(value));
  }
  const headers = mcpDelegationHeaders(context.delegation);
  headers.set("Accept", "application/json, text/plain;q=0.9");
  const init: RequestInit = {
    method: call.method ?? "GET",
    headers,
  };
  if (call.body !== undefined) {
    headers.set("Content-Type", "application/json");
    init.body = JSON.stringify(call.body);
  }

  let response: Response;
  try {
    response = await context.env[call.service].fetch(new Request(url, init));
  } catch {
    throw new Error("MCP upstream request failed");
  }
  if (response.status === 204) {
    return { ok: true, status: 204, data: { success: true } };
  }
  const text = await response.text();
  let data: unknown = text;
  if (response.headers.get("content-type")?.includes("application/json")) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: "invalid-upstream-json" };
    }
  }
  return { ok: response.ok, status: response.status, data };
}

export function toolResponse(result: UpstreamResult) {
  const text = typeof result.data === "string"
    ? result.data
    : JSON.stringify(result.data, null, 2);
  return {
    content: [{ type: "text" as const, text }],
    isError: !result.ok,
  };
}
