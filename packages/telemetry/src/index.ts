import { instrument, ResolveConfigFn } from "@microlabs/otel-cf-workers";
import type { Attributes } from "@opentelemetry/api";

export interface TelemetryEnv {
  AXIOM_TOKEN: string;
  AXIOM_DATASET: string;
  AXIOM_TRACES_URL?: string;
}

const AXIOM_EU_TRACES_URL =
  "https://eu-central-1.aws.edge.axiom.co/v1/traces";

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
  const redactUrl = (value: string): string => {
    try {
      const url = new URL(value);
      for (const name of ["token", "key", "secret"]) {
        if (url.searchParams.has(name)) url.searchParams.set(name, "[REDACTED]");
      }
      return url.toString();
    } catch {
      return value;
    }
  };

  const config: ResolveConfigFn = (env: Env) => ({
    exporter: {
      url: env.AXIOM_TRACES_URL ?? AXIOM_EU_TRACES_URL,
      headers: {
        Authorization: `Bearer ${env.AXIOM_TOKEN}`,
        "X-Axiom-Dataset": env.AXIOM_DATASET,
      },
    },
    service: { name: serviceName },
    postProcessor: (spans) => spans.map((span) => {
      const attributes = span.attributes as Attributes;
      if (typeof attributes["url.full"] === "string") {
        attributes["url.full"] = redactUrl(attributes["url.full"]);
      }
      if (typeof attributes["url.query"] === "string") {
        const query = new URLSearchParams(attributes["url.query"].replace(/^\?/, ""));
        for (const name of ["token", "key", "secret"]) {
          if (query.has(name)) query.set(name, "[REDACTED]");
        }
        attributes["url.query"] = query.size > 0 ? `?${query}` : "";
      }
      return span;
    }),
  });

  return instrument(handler, config);
}
