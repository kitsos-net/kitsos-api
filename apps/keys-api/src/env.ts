import type { Env as AuthEnv } from "@kitsos/auth";

export interface Env extends AuthEnv {
  ADMIN_GROUP_ID: string;
}
