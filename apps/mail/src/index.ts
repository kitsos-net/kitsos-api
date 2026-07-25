import { Hono } from "hono";
import { authenticate, checkResourceGrant, checkKeyResourceAccess, checkRateLimit, checkUsageLimitForUser, getUsageLimit, sha256Hex, withRetryAfter } from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import { resolvePayload } from "./dotpath";
import { sendViaBrevo } from "./brevo";
import { getTemplateHtml, invalidateTemplateCache, renderTemplate } from "./template";
import type { Env } from "./env";

const APP_ID = "mail";
const VERIFICATION_FROM_ADDRESS = "noreply@notify.kitsos.net";
const VERIFICATION_SCOPE = "mail:send:verification";

type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>();

function id() {
  return crypto.randomUUID();
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ============================================================
// Public — webhook trigger, no @kitsos/auth (secret-gated instead)
// ============================================================
app.post("/webhook/:webhookId", async (c) => {
  const webhookId = c.req.param("webhookId");
  const rate = await checkRateLimit(c.env, `mail:webhook:${webhookId}`, { windowSeconds: 60, maxRequests: 30 });
  if (!rate.allowed) return withRetryAfter(c.json({ error: rate.reason }, 429), rate);
  const providedSecret = c.req.header("X-Webhook-Secret") ?? "";
  if (!providedSecret) return c.json({ error: "missing-secret" }, 401);

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
  if (providedHash !== webhook.secret_hash) return c.json({ error: "invalid-secret" }, 401);

  const template = await c.env.DB.prepare("SELECT * FROM mail_templates WHERE id = ?")
    .bind(webhook.template_id)
    .first<{ url: string }>();
  if (!template) return c.json({ error: "template-not-found" }, 500);

  const payload = await c.req.json().catch(() => ({}));
  const data = resolvePayload(JSON.parse(webhook.mapping), payload);

  let html: string;
  try {
    html = renderTemplate(await getTemplateHtml(c.env, webhook.template_id, template.url), data);
  } catch (e) {
    return c.json({ error: "template-fetch-failed", detail: String(e) }, 502);
  }

  const subject = data.subject || `Notification from ${webhookId}`;
  const usage = await checkUsageLimitForUser(c.env, webhook.user_id, APP_ID, {
    limitType: "emails_per_day", cost: JSON.parse(webhook.to_addresses).length,
  });
  if (!usage.allowed) return withRetryAfter(c.json({ error: usage.reason }, 429), usage);
  const result = await sendViaBrevo(c.env, {
    from: webhook.from_address,
    to: JSON.parse(webhook.to_addresses),
    subject,
    html,
  });

  if (!result.ok) return c.json({ error: "send-failed", detail: result.error }, 502);
  return c.json({ sent: true });
});

// Internal verification delivery. This deliberately cannot send arbitrary
// content or choose a sender: it is limited to one sender and one message.
app.post("/internal/verification-email", async (c) => {
  const auth = await authenticate(
    c.req.raw,
    c.env,
    VERIFICATION_SCOPE,
    APP_ID,
    { windowSeconds: 60, maxRequests: 20 }
  );
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);

  const body = await c.req.json<{
    to?: string;
    confirmUrl?: string;
    resource?: string;
  }>().catch(() => null);
  if (!body?.to || !body.confirmUrl || !body.resource || !body.to.includes("@")) {
    return c.json({ error: "invalid-request" }, 400);
  }

  let confirmUrl: URL;
  try {
    confirmUrl = new URL(body.confirmUrl);
  } catch {
    return c.json({ error: "invalid-confirm-url" }, 400);
  }
  if (confirmUrl.protocol !== "https:" || confirmUrl.hostname !== "verify.api.kitsos.net") {
    return c.json({ error: "invalid-confirm-url" }, 400);
  }

  const grant = await checkResourceGrant(
    c.env,
    auth.context!,
    "email_address",
    VERIFICATION_FROM_ADDRESS,
    VERIFICATION_SCOPE
  );
  if (!grant.allowed) return c.json({ error: grant.reason }, grant.status as 403);

  const resource = escapeHtml(body.resource);
  const url = escapeHtml(confirmUrl.toString());
  const result = await sendViaBrevo(c.env, {
    from: VERIFICATION_FROM_ADDRESS,
    to: [body.to],
    subject: "Kitsos — Bestätige deine Verifizierung",
    html: `<p>Bestätige die Verifizierung für <strong>${resource}</strong>.</p><p><a href="${url}">Verifizierung bestätigen</a></p>`,
    text: `Bestätige die Verifizierung für ${body.resource}: ${confirmUrl}`,
  });
  if (!result.ok) return c.json({ error: "send-failed", detail: result.error }, 502);

  return c.json({ sent: true });
});

// ============================================================
// Authenticated — /send
// ============================================================
app.post("/send", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:send", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const ctx = auth.context!;

  const body = await c.req.json<{
    from: string;
    to: string[];
    subject: string;
    template?: string;
    data?: Record<string, string>;
    html?: string;
    text?: string;
  }>();

  const grant = await checkResourceGrant(c.env, ctx, "email_address", body.from, "mail:send");
  if (!grant.allowed) return c.json({ error: grant.reason }, grant.status as 403);

  const usage = await checkUsageLimitForUser(c.env, ctx.userId, APP_ID, { limitType: "emails_per_day", cost: body.to.length });
  if (!usage.allowed) return withRetryAfter(c.json({ error: usage.reason }, 429), usage);

  let html = body.html;
  if (body.template) {
    const template = await c.env.DB.prepare("SELECT * FROM mail_templates WHERE id = ? AND user_id = ?")
      .bind(body.template, ctx.userId)
      .first<{ url: string }>();
    if (!template) return c.json({ error: "template-not-found" }, 404);
    const access = await checkKeyResourceAccess(c.env, ctx, "mail_template", body.template, "mail:template:read");
    if (!access.allowed) return c.json({ error: access.reason }, 403);
    html = renderTemplate(await getTemplateHtml(c.env, body.template, template.url), body.data ?? {});
  }

  const result = await sendViaBrevo(c.env, { from: body.from, to: body.to, subject: body.subject, html, text: body.text });
  if (!result.ok) return c.json({ error: "send-failed", detail: result.error }, 502);
  return c.json({ sent: true });
});

// ============================================================
// Authenticated — /templates
// ============================================================
app.get("/templates", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:template:read", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const r = await c.env.DB.prepare("SELECT * FROM mail_templates WHERE user_id = ?").bind(auth.context!.userId).all();
  return c.json(r.results);
});

app.post("/templates", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:template:write", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const body = await c.req.json<{ name: string; url: string; variables: string[] }>();
  const templateId = id();
  await c.env.DB.prepare("INSERT INTO mail_templates (id, user_id, name, url, variables) VALUES (?, ?, ?, ?, ?)")
    .bind(templateId, auth.context!.userId, body.name, body.url, JSON.stringify(body.variables))
    .run();
  return c.json({ id: templateId }, 201);
});

app.patch("/templates/:templateId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:template:write", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const templateId = c.req.param("templateId");
  const access = await checkKeyResourceAccess(c.env, auth.context!, "mail_template", templateId, "mail:template:write");
  if (!access.allowed) return c.json({ error: access.reason }, 403);
  const body = await c.req.json<{ url?: string; variables?: string[] }>();

  if (body.url) {
    await c.env.DB.prepare("UPDATE mail_templates SET url = ? WHERE id = ? AND user_id = ?")
      .bind(body.url, templateId, auth.context!.userId)
      .run();
    await invalidateTemplateCache(c.env, templateId);
  }
  if (body.variables) {
    await c.env.DB.prepare("UPDATE mail_templates SET variables = ? WHERE id = ? AND user_id = ?")
      .bind(JSON.stringify(body.variables), templateId, auth.context!.userId)
      .run();
  }
  return c.body(null, 204);
});

app.delete("/templates/:templateId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:template:delete", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const access = await checkKeyResourceAccess(c.env, auth.context!, "mail_template", c.req.param("templateId"), "mail:template:delete");
  if (!access.allowed) return c.json({ error: access.reason }, 403);
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
  const auth = await authenticate(c.req.raw, c.env, "mail:webhook:read", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const r = await c.env.DB
    .prepare("SELECT id, name, template_id, from_address, to_addresses, mapping, created_at FROM mail_webhooks WHERE user_id = ?")
    .bind(auth.context!.userId)
    .all();
  return c.json(r.results); // secret_hash never returned
});

app.post("/webhooks", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:webhook:write", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const ctx = auth.context!;

  const body = await c.req.json<{
    name: string;
    templateId: string;
    fromAddress: string;
    toAddresses: string[];
    mapping: Record<string, string>;
  }>();

  const grant = await checkResourceGrant(c.env, ctx, "email_address", body.fromAddress, "mail:send");
  if (!grant.allowed) return c.json({ error: grant.reason }, grant.status as 403);

  const maxWebhooks = await getUsageLimit(c.env, ctx.userId, APP_ID, "webhooks");
  const countRow = await c.env.DB.prepare("SELECT COUNT(*) as n FROM mail_webhooks WHERE user_id = ?")
    .bind(ctx.userId)
    .first<{ n: number }>();
  if (maxWebhooks !== null && (countRow?.n ?? 0) >= maxWebhooks) {
    return c.json({ error: "webhook-limit-exceeded" }, 403);
  }

  const webhookId = id();
  const secret = crypto.randomUUID().replace(/-/g, "");
  const secretHash = await sha256Hex(secret);

  await c.env.DB.prepare(
    `INSERT INTO mail_webhooks (id, user_id, name, secret_hash, template_id, from_address, to_addresses, mapping)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(webhookId, ctx.userId, body.name, secretHash, body.templateId, body.fromAddress, JSON.stringify(body.toAddresses), JSON.stringify(body.mapping))
    .run();

  // secret shown only here — not recoverable afterwards
  return c.json({ id: webhookId, secret, url: `https://mail.api.kitsos.net/webhook/${webhookId}` }, 201);
});

app.patch("/webhooks/:webhookId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:webhook:write", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const webhookId = c.req.param("webhookId");
  const body = await c.req.json<{
    templateId?: string;
    fromAddress?: string;
    toAddresses?: string[];
    mapping?: Record<string, string>;
  }>();

  const updates: string[] = [];
  const values: unknown[] = [];
  if (body.templateId) { updates.push("template_id = ?"); values.push(body.templateId); }
  if (body.fromAddress) { updates.push("from_address = ?"); values.push(body.fromAddress); }
  if (body.toAddresses) { updates.push("to_addresses = ?"); values.push(JSON.stringify(body.toAddresses)); }
  if (body.mapping) { updates.push("mapping = ?"); values.push(JSON.stringify(body.mapping)); }
  if (updates.length === 0) return c.body(null, 204);

  values.push(webhookId, auth.context!.userId);
  await c.env.DB.prepare(`UPDATE mail_webhooks SET ${updates.join(", ")} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();
  return c.body(null, 204);
});

app.delete("/webhooks/:webhookId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "mail:webhook:delete", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  await c.env.DB.prepare("DELETE FROM mail_webhooks WHERE id = ? AND user_id = ?")
    .bind(c.req.param("webhookId"), auth.context!.userId)
    .run();
  return c.body(null, 204);
});

app.get("/health", (c) => c.json({ ok: true }));

export default withTelemetry(app, "mail");
