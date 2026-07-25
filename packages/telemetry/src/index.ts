import { instrument, ResolveConfigFn } from "@microlabs/otel-cf-workers";

export interface TelemetryEnv {
  AXIOM_TOKEN: string;
  AXIOM_DATASET: string;
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
  const config: ResolveConfigFn = (env: Env) => ({
    exporter: {
      url: "https://eu-central-1.aws.edge.axiom.co/v1/traces",
      headers: {
        Authorization: `Bearer ${env.AXIOM_TOKEN}`,
        "X-Axiom-Dataset": env.AXIOM_DATASET,
      },
    },
    service: { name: serviceName },
  });

  return instrument(handler, config);
}
