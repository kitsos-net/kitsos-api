import type { Env as AuthEnv } from "@kitsos/auth";
import type { TelemetryEnv } from "@kitsos/telemetry";

export interface Env extends AuthEnv, TelemetryEnv {
  CORS_ORIGINS?: string;
  CF_ACCOUNT_ID: string;
  CF_EMAIL_API_TOKEN: string;
}
