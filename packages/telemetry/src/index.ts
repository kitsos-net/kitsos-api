import { instrument, OTLPExporter, ResolveConfigFn } from "@microlabs/otel-cf-workers";
import { SpanStatusCode, trace, type Attributes } from "@opentelemetry/api";

export interface TelemetryEnv {
  AXIOM_TOKEN: string;
  AXIOM_DATASET: string;
}

export type EventFields = Record<string, string | number | boolean | undefined>;

/**
 * Adds a query-friendly semantic event to the active request span.
 * Never pass credentials, confirmation tokens, message bodies, or secrets.
 */
export function recordEvent(
  name: string,
  outcome: "success" | "denied" | "error" | "noop",
  fields: EventFields = {}
): void {
  const span = trace.getActiveSpan();
  if (!span) return;
  const attributes: Attributes = {
    "event.name": name,
    "event.outcome": outcome,
  };
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) attributes[key] = value;
  }
  span.addEvent(name, attributes);
  span.setAttributes({
    "kitsos.event.name": name,
    "kitsos.event.outcome": outcome,
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
 * Usage in an app's index.ts:
 *
 *   export default withTelemetry(app, "keys-api");
 */
export function withTelemetry<Env extends TelemetryEnv>(
  handler: ExportedHandler<Env>,
  serviceName: string
) {
  const config: ResolveConfigFn = (env: Env) => {
    const exporter = new OTLPExporter({
      url: "https://eu-central-1.aws.edge.axiom.co/v1/traces",
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
        exporter.export(spans, (result) => {
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
      // Request statistics must be exact rather than extrapolated from a sample.
      sampling: { headSampler: { ratio: 1 } },
    };
  };

  return instrument(handler, config);
}
