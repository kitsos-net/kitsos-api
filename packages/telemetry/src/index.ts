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
const TELEMETRY_SCHEMA_VERSION = 2;

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
  serviceName: string,
  status: number,
  durationMs: number
): Attributes {
  const url = new URL(request.url);
  const classification = classifyStatus(status);
  const cf = request.cf as IncomingRequestCfProperties | undefined;

  return {
    "event.name": "request.completed",
    "event.category": "http",
    "event.outcome": classification.outcome,
    "event.reason": classification.reason,
    "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
    "kitsos.api.name": serviceName,
    "kitsos.request.method": request.method,
    "kitsos.request.path": safePath(url.pathname),
    "kitsos.request.status_code": status,
    "kitsos.request.outcome": classification.outcome,
    "kitsos.request.reason": classification.reason,
    "kitsos.request.duration_ms": durationMs,
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
    delete attributes["url.full"];
    delete attributes["url.query"];
    delete attributes["http.url"];
    delete attributes["http.target"];
    delete attributes["http.request.header.authorization"];
    delete attributes["http.request.header.cookie"];
    delete attributes["http.response.header.set-cookie"];

    const sanitizedPath = attributes["kitsos.request.path"];
    if (typeof sanitizedPath === "string") {
      attributes["url.path"] = sanitizedPath;
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
    "event.name": name,
    "event.category": name.split(".", 1)[0] || "application",
    "event.outcome": outcome,
    "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
  };
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) attributes[key] = value;
  }
  span.addEvent(name, attributes);
  span.setAttributes({
    "kitsos.event.name": name,
    "kitsos.event.outcome": outcome,
    ...(typeof fields["error.code"] === "string"
      ? { "kitsos.event.reason": fields["error.code"] }
      : {}),
    ...attributes,
  });
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
  span?.setStatus({ code: SpanStatusCode.ERROR, message: errorCode });
}

/**
 * Wraps a Worker's fetch handler (a Hono app's default export works fine —
 * it exposes `.fetch`) with OpenTelemetry auto-instrumentation, exporting
 * traces to Axiom via OTLP/HTTP. Requires `AXIOM_TOKEN` / `AXIOM_DATASET`
 * secrets and `compatibility_flags = ["nodejs_compat"]` in wrangler.toml.
 *
 * Every fetch request gets a request.completed event and stable request
 * dimensions. Query strings, full URLs, credentials and cookie attributes are
 * removed before export.
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
          const startedAt = Date.now();
          const span = trace.getActiveSpan();
          const sanitizedPath = safePath(new URL(request.url).pathname);
          span?.setAttributes({
            "kitsos.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
            "kitsos.api.name": serviceName,
            "kitsos.request.method": request.method,
            "kitsos.request.path": sanitizedPath,
            "cloudflare.ray_id": request.headers.get("CF-Ray") ?? "",
          });

          try {
            const response = await originalFetch.call(handler, request, env, ctx);
            const attributes = requestAttributes(
              request,
              serviceName,
              response.status,
              Date.now() - startedAt
            );
            span?.addEvent("request.completed", attributes);
            span?.setAttributes(attributes);
            if (response.status >= 500) {
              span?.setStatus({ code: SpanStatusCode.ERROR, message: "server-error" });
            }
            return response;
          } catch (error) {
            const attributes = requestAttributes(
              request,
              serviceName,
              500,
              Date.now() - startedAt
            );
            attributes["event.reason"] = "unhandled-exception";
            attributes["kitsos.request.reason"] = "unhandled-exception";
            span?.addEvent("request.completed", attributes);
            span?.setAttributes(attributes);
            span?.setStatus({ code: SpanStatusCode.ERROR, message: "unhandled-exception" });
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
