import type { Env as AuthEnv } from "@kitsos/auth";
import type { TelemetryEnv } from "@kitsos/telemetry";

export interface Env extends AuthEnv, TelemetryEnv {
  BREVO_API_KEY: string;
  CORS_ORIGINS?: string;
}
