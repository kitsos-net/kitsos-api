import { instrument, OTLPExporter, ResolveConfigFn } from "@microlabs/otel-cf-workers";
import { SpanStatusCode, trace, type Attributes } from "@opentelemetry/api";

export interface TelemetryEnv {
  AXIOM_TOKEN: string;
  AXIOM_DATASET: string;
}

export type EventFields = Record<string, string | number | boolean | undefined>;
export type EventOutcome = "success" | "allowed" | "denied" | "rate_limited" | "error" | "noop";

type RequestOutcome =
  | "success"
  | "redirect"
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "client_error"
  | "server_error";

const AXIOM_EU_TRACES_URL = "https://eu-central-1.aws.edge.axiom.co/v1/traces";
const TELEMETRY_SCHEMA_VERSION = 3;

function safePath(pathname: string): string {
  return pathname
    .split("/")
    .map((segment) => {
      if (!segment) return segment;
      let decoded = segment;
      try {
        decoded = decodeURIComponent(segment);
      } catch {
        // Keep the encoded segment if it is malformed.
      }
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) {
        return ":id";
      }
      if (decoded.includes("@")) return ":value";
      if (decoded.length >= 24 && /^[a-z0-9_-]+$/i.test(decoded)) return ":token";
      return segment;
    })
    .join("/");
}

function classifyStatus(status: number): { outcome: RequestOutcome; reason: string } {
  if (status < 300) return { outcome: "success", reason: "request-completed" };
  if (status < 400) return { outcome: "redirect", reason: "http-redirect" };
  if (status === 400 || status === 422) return { outcome: "invalid_request", reason: "invalid-request" };
  if (status === 401) return { outcome: "unauthorized", reason: "authentication-failed" };
  if (status === 403) return { outcome: "forbidden", reason: "authorization-failed" };
  if (status === 404) return { outcome: "not_found", reason: "route-or-resource-not-found" };
  if (status === 409) return { outcome: "conflict", reason: "request-conflict" };
  if (status === 429) return { outcome: "rate_limited", reason: "rate-limit-exceeded" };
  if (status < 500) return { outcome: "client_error", reason: "client-error" };
  return { outcome: "server_error", reason: "server-error" };
}

function requestAttributes(
  request: Request,
  status: number
): Attributes {
  const url = new URL(request.url);
  const classification = classifyStatus(status);
  const cf = request.cf as IncomingRequestCfProperties | undefined;

  return {
    "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
    "url.path": safePath(url.pathname),
    "kitsos.request.outcome": classification.outcome,
    "kitsos.request.reason": classification.reason,
    "cloudflare.ray_id": request.headers.get("CF-Ray") ?? "",
    "cloudflare.colo": cf?.colo ?? "",
    "client.country": cf?.country ?? "",
    "client.asn": typeof cf?.asn === "number" ? cf.asn : 0,
  };
}

function stripSensitiveSpanAttributes(spans: Parameters<OTLPExporter["export"]>[0]) {
  for (const span of spans) {
    const attributes = span.attributes as Record<string, unknown>;
    attributes["kitsos.telemetry.schema_version"] = TELEMETRY_SCHEMA_VERSION;
    const path = attributes["url.path"];
    if (typeof path === "string") {
      attributes["url.path"] = safePath(path);
    }

    for (const key of [
      // Sensitive or high-cardinality request data.
      "url.full",
      "url.query",
      "http.url",
      "http.target",
      "http.request.header.authorization",
      "http.request.header.cookie",
      "http.response.header.set-cookie",
      "user_agent.original",
      // Duplicates of standard OTel request fields.
      "kitsos.api.name",
      "kitsos.app.id",
      "kitsos.request.method",
      "kitsos.request.path",
      "kitsos.request.status_code",
      "kitsos.request.duration_ms",
      // Semantic events live only in the span's events array.
      "event.name",
      "event.category",
      "event.outcome",
      "event.reason",
      "kitsos.event.name",
      "kitsos.event.outcome",
      "kitsos.event.reason",
      "error.code",
      "error.message",
      "kitsos.resource.id",
      "kitsos.resource.type",
      "limit.type",
      "limit.value",
      "limit.bucket",
      "limit.retry_after_seconds",
      "usage.current",
      "usage.cost",
      "usage.next",
      // Low-value transport metadata and duplicate Cloudflare dimensions.
      "http.accepts",
      "http.mime_type",
      "http.request.body.size",
      "messaging.destination.name",
      "rpc.message.id",
      "network.protocol.name",
      "network.protocol.version",
      "url.scheme",
      "server.address",
      "faas.invocation_id",
      "faas.trigger",
      "net.asn",
      "net.colo",
      "net.country",
      "net.request_priority",
      "net.tcp_rtt",
      "net.tls_cipher",
      "net.tls_version",
    ]) {
      delete attributes[key];
    }

    if (span.status) {
      span.status.message = undefined;
    }

    const resourceAttributes = (span.resource as unknown as {
      attributes?: Record<string, unknown>;
    }).attributes;
    if (resourceAttributes) {
      delete resourceAttributes["cloud.platform"];
      delete resourceAttributes["cloud.provider"];
      delete resourceAttributes["cloud.region"];
      delete resourceAttributes["faas.max_memory"];
    }
  }
  return spans;
}

/**
 * Adds a query-friendly semantic event to the active request span.
 * Never pass credentials, confirmation tokens, message bodies, or secrets.
 */
export function recordEvent(
  name: string,
  outcome: EventOutcome,
  fields: EventFields = {}
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const attributes: Attributes = {
    "event.category": name.split(".", 1)[0] || "application",
    "event.outcome": outcome,
    "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
    ...(typeof fields["error.code"] === "string"
      ? { "event.reason": fields["error.code"] }
      : {}),
  };
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined && key !== "error.code") attributes[key] = value;
  }
  span.addEvent(name, attributes);
}

export function recordError(
  name: string,
  errorCode: string,
  message: string,
  fields: EventFields = {}
): void {
  const span = trace.getActiveSpan();
  recordEvent(name, "error", {
    ...fields,
    "error.code": errorCode,
    "error.message": message,
  });
  span?.setStatus({ code: SpanStatusCode.ERROR });
}

/**
 * Wraps a Worker's fetch handler (a Hono app's default export works fine —
 * it exposes `.fetch`) with OpenTelemetry auto-instrumentation, exporting
 * traces to Axiom via OTLP/HTTP. Requires `AXIOM_TOKEN` / `AXIOM_DATASET`
 * secrets and `compatibility_flags = ["nodejs_compat"]` in wrangler.toml.
 *
 * Every fetch request gets stable request dimensions. Query strings, full
 * URLs, credentials and cookie attributes are removed before export.
 *
 * Usage in an app's index.ts:
 *
 *   export default withTelemetry({ fetch: app.fetch }, "keys-api");
 */
export function withTelemetry<Env extends TelemetryEnv>(
  handler: ExportedHandler<Env>,
  serviceName: string
) {
  const originalFetch = handler.fetch;
  const requestAwareHandler: ExportedHandler<Env> = originalFetch
    ? {
        ...handler,
        async fetch(request, env, ctx) {
          const span = trace.getActiveSpan();
          const sanitizedPath = safePath(new URL(request.url).pathname);
          const authorization = request.headers.get("Authorization") ?? "";
          const presentedToken = authorization.replace(/^Bearer\s+/i, "");
          const apiKeyUsed = presentedToken.startsWith("kitsos_");
          span?.setAttributes({
            "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
            "url.path": sanitizedPath,
            "kitsos.api_key.used": apiKeyUsed,
            "kitsos.auth.method": apiKeyUsed
              ? "api_key"
              : authorization
                ? "bearer"
                : "anonymous",
            "cloudflare.ray_id": request.headers.get("CF-Ray") ?? "",
          });

          try {
            const response = await originalFetch.call(handler, request, env, ctx);
            const attributes = requestAttributes(
              request,
              response.status
            );
            span?.setAttributes(attributes);
            if (response.status >= 500) {
              span?.setStatus({ code: SpanStatusCode.ERROR });
            }
            return response;
          } catch (error) {
            const attributes = requestAttributes(
              request,
              500
            );
            attributes["kitsos.request.reason"] = "unhandled-exception";
            span?.setAttributes(attributes);
            span?.setStatus({ code: SpanStatusCode.ERROR });
            throw error;
          }
        },
      }
    : handler;

  const config: ResolveConfigFn = (env: Env) => {
    const exporter = new OTLPExporter({
      url: AXIOM_EU_TRACES_URL,
      headers: {
        Authorization: `Bearer ${env.AXIOM_TOKEN}`,
        "X-Axiom-Dataset": env.AXIOM_DATASET,
      },
    });
    const reportingExporter = {
      export(
        spans: Parameters<OTLPExporter["export"]>[0],
        callback: Parameters<OTLPExporter["export"]>[1]
      ) {
        // otel-cf-workers rc.52 accepts a postProcessor option but does not
        // invoke it in its export path. Sanitize again at the final exporter
        // boundary so sensitive URL/header attributes cannot leave the Worker.
        exporter.export(stripSensitiveSpanAttributes(spans), (result) => {
          if (result.error) {
            console.error(JSON.stringify({
              event: "telemetry.export.failed",
              service: serviceName,
              error: result.error.message,
            }));
          }
          callback(result);
        });
      },
      shutdown: () => exporter.shutdown(),
    };
    return {
      exporter: reportingExporter,
      service: { name: serviceName },
      // Retain this for forward compatibility if the library restores its
      // documented post-processor hook. The exporter boundary above remains
      // the authoritative privacy guard.
      postProcessor: stripSensitiveSpanAttributes,
      // Request statistics must be exact rather than extrapolated from a sample.
      sampling: { headSampler: { ratio: 1 } },
    };
  };

  return instrument(requestAwareHandler, config);
}
