import type { Env } from "./types";

export const LIMIT_DEFINITIONS = {
  emails_per_day: {
    appId: "mail",
    defaultValue: 20,
    maximumValue: 10_000,
    daily: true,
  },
  mail_templates: {
    appId: "mail",
    defaultValue: 20,
    maximumValue: 1_000,
    daily: false,
  },
  mail_webhooks: {
    appId: "mail",
    defaultValue: 10,
    maximumValue: 1_000,
    daily: false,
  },
  hme_aliases: {
    appId: "hide-my-email",
    defaultValue: 100,
    maximumValue: 10_000,
    daily: false,
  },
  verified_resources: {
    appId: "verify",
    defaultValue: 100,
    maximumValue: 5_000,
    daily: false,
  },
  verification_attempts_per_day: {
    appId: "verify",
    defaultValue: 20,
    maximumValue: 500,
    daily: true,
  },
  api_keys: {
    appId: "keys-api",
    defaultValue: 50,
    maximumValue: 1_000,
    daily: false,
  },
} as const;

export type LimitType = keyof typeof LIMIT_DEFINITIONS;

export function isLimitType(value: string): value is LimitType {
  return Object.hasOwn(LIMIT_DEFINITIONS, value);
}

export function isValidLimitConfiguration(
  appId: string,
  limitType: string,
  value: number
): limitType is LimitType {
  if (!isLimitType(limitType)) return false;
  const definition = LIMIT_DEFINITIONS[limitType];
  return definition.appId === appId
    && Number.isInteger(value)
    && value >= 1
    && value <= definition.maximumValue;
}

export async function getEffectiveLimit(
  env: Env,
  userId: string,
  limitType: LimitType
): Promise<number> {
  const definition = LIMIT_DEFINITIONS[limitType];
  const row = await env.DB.prepare(
    `SELECT limit_value FROM usage_limits
     WHERE user_id = ? AND app_id = ? AND limit_type = ?
     ORDER BY is_override DESC, created_at DESC
     LIMIT 1`
  )
    .bind(userId, definition.appId, limitType)
    .first<{ limit_value: number }>();
  const configured = row?.limit_value;
  if (!Number.isInteger(configured) || configured! < 1) {
    return definition.defaultValue;
  }
  return Math.min(configured!, definition.maximumValue);
}

export async function consumeDailyLimit(
  env: Env,
  userId: string,
  limitType: LimitType,
  cost = 1
): Promise<{ allowed: boolean; limit: number; remaining: number }> {
  const definition = LIMIT_DEFINITIONS[limitType];
  if (!definition.daily || !Number.isInteger(cost) || cost < 1) {
    throw new Error("invalid daily limit consumption");
  }
  const limit = await getEffectiveLimit(env, userId, limitType);
  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const row = await env.DB.prepare(
    `INSERT INTO daily_usage_counters
       (user_id, app_id, limit_type, day_bucket, count)
     SELECT ?, ?, ?, ?, ?
     WHERE ? <= ?
     ON CONFLICT(user_id, app_id, limit_type, day_bucket)
     DO UPDATE SET count = count + excluded.count
       WHERE count + excluded.count <= ?
     RETURNING count`
  )
    .bind(
      userId,
      definition.appId,
      limitType,
      dayBucket,
      cost,
      cost,
      limit,
      limit
    )
    .first<{ count: number }>();
  const count = row?.count ?? limit;
  return {
    allowed: Boolean(row),
    limit,
    remaining: Math.max(0, limit - count),
  };
}

export async function consumeHardDailyLimit(
  env: Env,
  userId: string,
  appId: string,
  limitType: string,
  hardLimit: number
): Promise<boolean> {
  if (
    !/^[a-z][a-z0-9_]{0,63}$/.test(limitType)
    || !Number.isInteger(hardLimit)
    || hardLimit < 1
  ) {
    throw new Error("invalid hard daily limit");
  }
  const dayBucket = Math.floor(Date.now() / 1000 / 86400);
  const row = await env.DB.prepare(
    `INSERT INTO daily_usage_counters
       (user_id, app_id, limit_type, day_bucket, count)
     VALUES (?, ?, ?, ?, 1)
     ON CONFLICT(user_id, app_id, limit_type, day_bucket)
     DO UPDATE SET count = count + 1
       WHERE count < ?
     RETURNING count`
  )
    .bind(userId, appId, limitType, dayBucket, hardLimit)
    .first<{ count: number }>();
  return Boolean(row);
}
