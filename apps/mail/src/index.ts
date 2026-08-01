import { Hono } from "hono";
import { WorkerEntrypoint } from "cloudflare:workers";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import {
  authenticate,
  checkResourceGrant,
  checkScope,
  constantTimeEqual,
  consumeDailyLimit,
  consumeHardDailyLimit,
  getEffectiveLimit,
  sha256Hex,
  acceptPrivateMcpDelegation,
} from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import { resolvePayload } from "./dotpath";
import { sendViaBrevo } from "./brevo";
import { getTemplateHtml, invalidateTemplateCache, renderTemplate } from "./template";
import {
  isEmail,
  isEmailList,
  isNonEmptyString,
  isStringRecord,
  normalizeEmail,
  safeTemplateUrl,
} from "./validation";
import type { Env } from "./env";

const APP_ID = "mail";
const MAX_EMAIL_CONTENT_CHARACTERS = 3 * 1024 * 1024;
type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>().basePath("/v1");

app.use("*", async (c, next) => {
  if (c.req.url.length > 8192) return c.json({ error: "uri-too-long" }, 414);
  await next();
});
app.use("*", bodyLimit({
  maxSize: 4 * 1024 * 1024,
  onError: (c) => c.json({ error: "request-body-too-large" }, 413),
}));
app.use("/webhook/*", bodyLimit({
  maxSize: 256 * 1024,
  onError: (c) => c.json({ error: "request-body-too-large" }, 413),
}));
const metadataBodyLimit = bodyLimit({
  maxSize: 64 * 1024,
  onError: (c) => c.json({ error: "request-body-too-large" }, 413),
});
app.use("/templates", metadataBodyLimit);
app.use("/templates/*", metadataBodyLimit);
app.use("/webhooks", metadataBodyLimit);
app.use("/webhooks/*", metadataBodyLimit);
app.use("*", cors({
  origin: (origin, c) => {
    const configured = (c.env as Env).CORS_ORIGINS
      ?? "https://apidev.kitsos.net,https://myaccount.kitsos.net,https://docs.api.kitsos.net";
    return configured.split(",").map((item) => item.trim()).includes(origin) ? origin : null;
  },
  allowHeaders: ["Authorization", "Content-Type", "X-Webhook-Secret"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

function id() {
  return crypto.randomUUID();
}

function pagination(limitValue?: string, offsetValue?: string) {
  const limit = Number(limitValue ?? 100);
  const offset = Number(offsetValue ?? 0);
  return Number.isInteger(limit) && limit >= 1 && limit <= 500
    && Number.isInteger(offset) && offset >= 0 && offset <= 100_000
    ? { limit, offset }
    : null;
}

function decodeJsonFields(
  rows: Record<string, unknown>[],
  fields: string[]
): Record<string, unknown>[] {
  return rows.map((row) => {
    const decoded = { ...row };
    for (const field of fields) {
      if (typeof decoded[field] === "string") {
        try {
          decoded[field] = JSON.parse(decoded[field] as string);
        } catch {
          decoded[field] = field === "mapping" ? {} : [];
        }
      }
    }
    return decoded;
  });
}

// ============================================================
// Public — webhook trigger, no @kitsos/auth (secret-gated instead)
// ============================================================
app.post("/webhook/:webhookId", async (c) => {
  const webhookId = c.req.param("webhookId");
  const providedSecret = c.req.header("X-Webhook-Secret") ?? "";
  if (!providedSecret) return c.json({ error: "missing-secret" }, 401);
  if (providedSecret.length > 256) return c.json({ error: "invalid-secret" }, 401);

  const webhook = await c.env.DB.prepare("SELECT * FROM mail_webhooks WHERE id = ?")
    .bind(webhookId)
    .first<{
      id: string;
      user_id: string;
      template_id: string;
      from_address: string;
      to_addresses: string;
      mapping: string;
      secret_hash: string;
    }>();
  if (!webhook) return c.json({ error: "not-found" }, 404);

  const providedHash = await sha256Hex(providedSecret);
  if (!constantTimeEqual(providedHash, webhook.secret_hash)) {
    return c.json({ error: "invalid-secret" }, 401);
  }

  const grant = await checkResourceGrant(
    c.env,
    {
      method: "api_key",
      userId: webhook.user_id,
      appId: APP_ID,
      scopes: ["mail:send"],
      groupIds: [],
    },
    "email_address",
    webhook.from_address
  );
  if (!grant.allowed) return c.json({ error: "webhook-disabled" }, 403);

  const template = await c.env.DB.prepare("SELECT * FROM mail_templates WHERE id = ? AND user_id = ?")
    .bind(webhook.template_id, webhook.user_id)
    .first<{ url: string }>();
  if (!template) return c.json({ error: "template-not-found" }, 500);

  let toAddresses: unknown;
  let mapping: unknown;
  try {
    toAddresses = JSON.parse(webhook.to_addresses);
    mapping = JSON.parse(webhook.mapping);
  } catch {
    return c.json({ error: "invalid-webhook-configuration" }, 500);
  }
  if (!isEmailList(toAddresses) || !isStringRecord(mapping, 200, 500)) {
    return c.json({ error: "invalid-webhook-configuration" }, 500);
  }

  const payload = await c.req.json().catch(() => null);
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return c.json({ error: "invalid-json-body" }, 400);
  }
  const data = resolvePayload(mapping, payload);

  let html: string;
  try {
    html = renderTemplate(await getTemplateHtml(c.env, webhook.template_id, template.url), data);
  } catch (e) {
    return c.json({ error: "template-fetch-failed" }, 502);
  }

  const subject = data.subject || `Notification from ${webhookId}`;
  if (!isNonEmptyString(subject, 998)) {
    return c.json({ error: "invalid-subject" }, 400);
  }
  const emailLimit = await consumeDailyLimit(
    c.env,
    webhook.user_id,
    "emails_per_day",
    toAddresses.length
  );
  if (!emailLimit.allowed) return c.json({ error: "daily-limit-exceeded" }, 429);
  const result = await sendViaBrevo(c.env, {
    from: webhook.from_address,
    to: toAddresses,
    subject,
    html,
  });

  if (!result.ok) return c.json({ error: "send-failed" }, 502);
  return c.json({ sent: true });
});

// ============================================================
// Authenticated — /send
// ============================================================
app.post("/send", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:send", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const ctx = auth.context!;

  const body = await c.req.json<{
    from: string;
    to: string[];
    subject: string;
    template?: string;
    data?: Record<string, string>;
    html?: string;
    text?: string;
  }>().catch(() => null);
  if (
    !body
    || !isEmail(body.from)
    || !isEmailList(body.to)
    || !isNonEmptyString(body.subject, 998)
    || (body.template !== undefined && !isNonEmptyString(body.template, 100))
    || (body.data !== undefined && !isStringRecord(body.data))
    || (body.html !== undefined && (
      typeof body.html !== "string" || body.html.length > MAX_EMAIL_CONTENT_CHARACTERS
    ))
    || (body.text !== undefined && (
      typeof body.text !== "string" || body.text.length > MAX_EMAIL_CONTENT_CHARACTERS
    ))
    || (!body.template && !body.html && !body.text)
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }

  const grant = await checkResourceGrant(
    c.env,
    ctx,
    "email_address",
    normalizeEmail(body.from)
  );
  if (!grant.allowed) return c.json({ error: grant.reason }, 403);

  let html = body.html;
  if (body.template) {
    const template = await c.env.DB.prepare("SELECT * FROM mail_templates WHERE id = ? AND user_id = ?")
      .bind(body.template, ctx.userId)
      .first<{ url: string }>();
    if (!template) return c.json({ error: "template-not-found" }, 404);
    try {
      html = renderTemplate(await getTemplateHtml(c.env, body.template, template.url), body.data ?? {});
    } catch (error) {
      console.log("mail template fetch failed", String(error));
      return c.json({ error: "template-fetch-failed" }, 502);
    }
  }

  const emailLimit = await consumeDailyLimit(
    c.env,
    ctx.userId,
    "emails_per_day",
    body.to.length
  );
  if (!emailLimit.allowed) return c.json({ error: "daily-limit-exceeded" }, 429);
  const result = await sendViaBrevo(c.env, {
    from: normalizeEmail(body.from),
    to: body.to.map(normalizeEmail),
    subject: body.subject,
    html,
    text: body.text,
  });
  if (!result.ok) return c.json({ error: "send-failed" }, 502);
  return c.json({ sent: true });
});

// ============================================================
// Authenticated — /templates
// ============================================================
app.get("/templates", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:read", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const page = pagination(c.req.query("limit"), c.req.query("offset"));
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare(
    "SELECT * FROM mail_templates WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
  )
    .bind(auth.context!.userId, page.limit, page.offset)
    .all();
  return c.json(decodeJsonFields(r.results, ["variables"]));
});

app.post("/templates", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const body = await c.req.json<{ name: string; url: string; variables: string[] }>().catch(() => null);
  const templateUrl = safeTemplateUrl(body?.url);
  if (
    !body
    || !isNonEmptyString(body.name, 100)
    || !templateUrl
    || !Array.isArray(body.variables)
    || body.variables.length > 100
    || !body.variables.every((variable) => isNonEmptyString(variable, 100))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const templateId = id();
  const withinHardCreationLimit = await consumeHardDailyLimit(
    c.env,
    auth.context!.userId,
    APP_ID,
    "template_creations_per_day",
    100
  );
  if (!withinHardCreationLimit) {
    return c.json({ error: "template-creation-abuse-limit-exceeded" }, 429);
  }
  const templateLimit = await getEffectiveLimit(c.env, auth.context!.userId, "mail_templates");
  const created = await c.env.DB.prepare(
    `INSERT INTO mail_templates (id, user_id, name, url, variables)
     SELECT ?, ?, ?, ?, ?
     WHERE (
       SELECT COUNT(*) FROM mail_templates WHERE user_id = ?
     ) < ?`
  )
    .bind(
      templateId,
      auth.context!.userId,
      body.name.trim(),
      templateUrl,
      JSON.stringify([...new Set(body.variables)]),
      auth.context!.userId,
      templateLimit
    )
    .run();
  if (created.meta.changes !== 1) {
    return c.json({ error: "template-limit-exceeded", limit: templateLimit }, 429);
  }
  return c.json({ id: templateId }, 201);
});

app.patch("/templates/:templateId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const templateId = c.req.param("templateId");
  const body = await c.req.json<{ url?: string; variables?: string[] }>().catch(() => null);
  if (!body) return c.json({ error: "invalid-json-body" }, 400);
  const templateUrl = body.url === undefined ? undefined : safeTemplateUrl(body.url);
  if (
    (body.url !== undefined && !templateUrl)
    || (body.variables !== undefined && (
      !Array.isArray(body.variables)
      || body.variables.length > 100
      || !body.variables.every((variable) => isNonEmptyString(variable, 100))
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }

  if (templateUrl) {
    await c.env.DB.prepare("UPDATE mail_templates SET url = ? WHERE id = ? AND user_id = ?")
      .bind(templateUrl, templateId, auth.context!.userId)
      .run();
    await invalidateTemplateCache(c.env, templateId);
  }
  if (body.variables) {
    await c.env.DB.prepare("UPDATE mail_templates SET variables = ? WHERE id = ? AND user_id = ?")
      .bind(JSON.stringify([...new Set(body.variables)]), templateId, auth.context!.userId)
      .run();
  }
  return c.body(null, 204);
});

app.delete("/templates/:templateId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const webhook = await c.env.DB.prepare(
    "SELECT 1 FROM mail_webhooks WHERE template_id = ? AND user_id = ? LIMIT 1"
  )
    .bind(c.req.param("templateId"), auth.context!.userId)
    .first();
  if (webhook) return c.json({ error: "template-in-use" }, 409);
  await c.env.DB.prepare("DELETE FROM mail_templates WHERE id = ? AND user_id = ?")
    .bind(c.req.param("templateId"), auth.context!.userId)
    .run();
  await invalidateTemplateCache(c.env, c.req.param("templateId"));
  return c.body(null, 204);
});

// ============================================================
// Authenticated — /webhooks
// ============================================================
app.get("/webhooks", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:read", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const page = pagination(c.req.query("limit"), c.req.query("offset"));
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB
    .prepare("SELECT id, name, template_id, from_address, to_addresses, mapping, created_at FROM mail_webhooks WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
    .bind(auth.context!.userId, page.limit, page.offset)
    .all();
  return c.json(decodeJsonFields(r.results, ["to_addresses", "mapping"])); // secret_hash never returned
});

app.post("/webhooks", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const ctx = auth.context!;
  if (!checkScope(ctx, "mail:send").allowed) {
    return c.json({ error: "scope-missing" }, 403);
  }

  const body = await c.req.json<{
    name: string;
    templateId: string;
    fromAddress: string;
    toAddresses: string[];
    mapping: Record<string, string>;
  }>().catch(() => null);
  if (
    !body
    || !isNonEmptyString(body.name, 100)
    || !isNonEmptyString(body.templateId, 100)
    || !isEmail(body.fromAddress)
    || !isEmailList(body.toAddresses)
    || !isStringRecord(body.mapping, 200, 500)
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }

  const template = await c.env.DB.prepare(
    "SELECT 1 FROM mail_templates WHERE id = ? AND user_id = ?"
  )
    .bind(body.templateId, ctx.userId)
    .first();
  if (!template) return c.json({ error: "template-not-found" }, 404);

  const fromAddress = normalizeEmail(body.fromAddress);
  const toAddresses = body.toAddresses.map(normalizeEmail);
  const grant = await checkResourceGrant(c.env, ctx, "email_address", fromAddress);
  if (!grant.allowed) return c.json({ error: grant.reason }, 403);

  const webhookId = id();
  const withinHardCreationLimit = await consumeHardDailyLimit(
    c.env,
    ctx.userId,
    APP_ID,
    "webhook_creations_per_day",
    100
  );
  if (!withinHardCreationLimit) {
    return c.json({ error: "webhook-creation-abuse-limit-exceeded" }, 429);
  }
  const secret = crypto.randomUUID().replace(/-/g, "");
  const secretHash = await sha256Hex(secret);

  const webhookLimit = await getEffectiveLimit(c.env, ctx.userId, "mail_webhooks");
  const created = await c.env.DB.prepare(
    `INSERT INTO mail_webhooks
       (id, user_id, name, secret_hash, template_id, from_address, to_addresses, mapping)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
     WHERE (
       SELECT COUNT(*) FROM mail_webhooks WHERE user_id = ?
     ) < ?`
  )
    .bind(
      webhookId,
      ctx.userId,
      body.name,
      secretHash,
      body.templateId,
      fromAddress,
      JSON.stringify(toAddresses),
      JSON.stringify(body.mapping),
      ctx.userId,
      webhookLimit
    )
    .run();
  if (created.meta.changes !== 1) {
    return c.json({ error: "webhook-limit-exceeded", limit: webhookLimit }, 429);
  }

  // secret shown only here — not recoverable afterwards
  return c.json({ id: webhookId, secret, url: `https://mail.api.kitsos.net/v1/webhook/${webhookId}` }, 201);
});

app.patch("/webhooks/:webhookId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  if (!checkScope(auth.context!, "mail:send").allowed) {
    return c.json({ error: "scope-missing" }, 403);
  }
  const webhookId = c.req.param("webhookId");
  const body = await c.req.json<{
    templateId?: string;
    fromAddress?: string;
    toAddresses?: string[];
    mapping?: Record<string, string>;
  }>().catch(() => null);
  if (!body) return c.json({ error: "invalid-json-body" }, 400);

  const existing = await c.env.DB.prepare(
    "SELECT 1 FROM mail_webhooks WHERE id = ? AND user_id = ?"
  )
    .bind(webhookId, auth.context!.userId)
    .first();
  if (!existing) return c.json({ error: "not-found" }, 404);

  if (body.templateId !== undefined) {
    if (!isNonEmptyString(body.templateId, 100)) return c.json({ error: "invalid-template-id" }, 400);
    const template = await c.env.DB.prepare(
      "SELECT 1 FROM mail_templates WHERE id = ? AND user_id = ?"
    )
      .bind(body.templateId, auth.context!.userId)
      .first();
    if (!template) return c.json({ error: "template-not-found" }, 404);
  }
  if (body.fromAddress !== undefined) {
    if (!isEmail(body.fromAddress)) return c.json({ error: "invalid-from-address" }, 400);
    const grant = await checkResourceGrant(
      c.env,
      auth.context!,
      "email_address",
      normalizeEmail(body.fromAddress)
    );
    if (!grant.allowed) return c.json({ error: grant.reason }, 403);
  }
  if (body.toAddresses !== undefined && !isEmailList(body.toAddresses)) {
    return c.json({ error: "invalid-to-addresses" }, 400);
  }
  if (body.mapping !== undefined && !isStringRecord(body.mapping, 200, 500)) {
    return c.json({ error: "invalid-mapping" }, 400);
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  if (body.templateId) { updates.push("template_id = ?"); values.push(body.templateId); }
  if (body.fromAddress) { updates.push("from_address = ?"); values.push(normalizeEmail(body.fromAddress)); }
  if (body.toAddresses) { updates.push("to_addresses = ?"); values.push(JSON.stringify(body.toAddresses.map(normalizeEmail))); }
  if (body.mapping) { updates.push("mapping = ?"); values.push(JSON.stringify(body.mapping)); }
  if (updates.length === 0) return c.body(null, 204);

  values.push(webhookId, auth.context!.userId);
  await c.env.DB.prepare(`UPDATE mail_webhooks SET ${updates.join(", ")} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();
  return c.body(null, 204);
});

app.delete("/webhooks/:webhookId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  await c.env.DB.prepare("DELETE FROM mail_webhooks WHERE id = ? AND user_id = ?")
    .bind(c.req.param("webhookId"), auth.context!.userId)
    .run();
  return c.body(null, 204);
});

app.get("/health", (c) => c.json({ ok: true }));
app.notFound((c) => c.json({ error: "not-found" }, 404));
app.onError((_error, c) => c.json({ error: "internal-error" }, 500));

const instrumented = withTelemetry(app, "mail");

export class McpEntrypoint extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    const delegated = acceptPrivateMcpDelegation(this.env, request);
    if (!delegated) return Response.json({ error: "invalid-mcp-delegation" }, { status: 401 });
    return instrumented.fetch!(
      delegated.request as Request<unknown, IncomingRequestCfProperties>,
      delegated.env,
      this.ctx,
    );
  }
}

export default instrumented;
