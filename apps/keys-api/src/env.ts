import type { Env as AuthEnv } from "@kitsos/auth";
import type { TelemetryEnv } from "@kitsos/telemetry";

export interface Env extends AuthEnv, TelemetryEnv {
  ADMIN_GROUP_ID: string;
  CORS_ORIGINS?: string;
}
