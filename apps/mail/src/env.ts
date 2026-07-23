import type { Env as AuthEnv } from "@kitsos/auth";

export interface Env extends AuthEnv {
  BREVO_API_KEY: string;
}
