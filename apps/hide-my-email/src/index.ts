import { Hono } from "hono";
import { cors } from "hono/cors";
import { authenticateApiKey, checkResourceGrant, getUsageLimit, withRetryAfter } from "@kitsos/auth";
import { recordError, recordEvent, withTelemetry } from "@kitsos/telemetry";
import { generateAlias } from "./alias";
import type { Env } from "./env";

const APP_ID = "hide-my-email";
const DOMAIN = "hme.kitsos.net";

type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>();

app.use("*", cors({
  origin: "*",
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
}));

function id() {
  return crypto.randomUUID();
}

app.get("/health", (c) => c.json({ ok: true }));

app.get("/aliases", async (c) => {
  const auth = await authenticateApiKey(c.req.raw, c.env, "hme:read", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const r = await c.env.DB.prepare(
    "SELECT id, alias, domain, forward_to, label, status, emails_forwarded, last_forwarded_at, created_at FROM hme_aliases WHERE user_id = ? ORDER BY created_at DESC"
  )
    .bind(auth.context!.userId)
    .all();
  return c.json(r.results);
});

app.post("/aliases", async (c) => {
  const auth = await authenticateApiKey(c.req.raw, c.env, "hme:create", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const ctx = auth.context!;

  const body = await c.req.json<{ forwardTo: string; label?: string }>();

  const grant = await checkResourceGrant(c.env, ctx, "email_address", body.forwardTo, "hme:receive");
  if (!grant.allowed) return c.json({ error: grant.reason }, grant.status as 403);

  const maxAliases = await getUsageLimit(c.env, ctx.userId, APP_ID, "aliases");
  const count = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM hme_aliases WHERE user_id = ?").bind(ctx.userId).first<{ n: number }>();
  if (maxAliases !== null && (count?.n ?? 0) >= maxAliases) {
    recordEvent("hme.alias.create", "denied", {
      "kitsos.user.id": ctx.userId,
      "kitsos.api_key.id": ctx.apiKeyId,
      "limit.type": "aliases",
      "limit.value": maxAliases,
      "usage.current": count?.n ?? 0,
      "error.code": "usage-limit-exceeded",
    });
    return c.json({ error: "usage-limit-exceeded" }, 429);
  }

  // A handful of retries in case of a collision — alias space is large enough that this is rare
  let alias = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateAlias();
    const existing = await c.env.DB.prepare("SELECT 1 FROM hme_aliases WHERE alias = ?").bind(candidate).first();
    if (!existing) { alias = candidate; break; }
  }
  if (!alias) {
    recordError("hme.alias.create", "alias-generation-failed", "Could not generate a unique alias", {
      "kitsos.user.id": ctx.userId,
      "kitsos.api_key.id": ctx.apiKeyId,
    });
    return c.json({ error: "alias-generation-failed" }, 500);
  }

  const aliasId = id();
  await c.env.DB.prepare(
    "INSERT INTO hme_aliases (id, user_id, alias, domain, forward_to, label) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(aliasId, ctx.userId, alias, DOMAIN, body.forwardTo, body.label ?? null)
    .run();

  recordEvent("hme.alias.create", "success", {
    "kitsos.user.id": ctx.userId,
    "kitsos.api_key.id": ctx.apiKeyId,
    "kitsos.resource.id": aliasId,
  });
  return c.json({ id: aliasId, email: `${alias}@${DOMAIN}`, forwardTo: body.forwardTo }, 201);
});

app.patch("/aliases/:aliasId", async (c) => {
  const auth = await authenticateApiKey(c.req.raw, c.env, "hme:edit", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const ctx = auth.context!;
  const aliasId = c.req.param("aliasId");
  const body = await c.req.json<{ status?: "active" | "disabled"; label?: string; forwardTo?: string }>();

  if (body.forwardTo) {
    const grant = await checkResourceGrant(c.env, ctx, "email_address", body.forwardTo, "hme:receive");
    if (!grant.allowed) return c.json({ error: grant.reason }, grant.status as 403);
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  if (body.status) { updates.push("status = ?"); values.push(body.status); }
  if (body.label !== undefined) { updates.push("label = ?"); values.push(body.label); }
  if (body.forwardTo) { updates.push("forward_to = ?"); values.push(body.forwardTo); }
  if (updates.length === 0) return c.body(null, 204);

  values.push(aliasId, ctx.userId);
  await c.env.DB.prepare(`UPDATE hme_aliases SET ${updates.join(", ")} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();
  recordEvent("hme.alias.update", "success", {
    "kitsos.user.id": ctx.userId,
    "kitsos.api_key.id": ctx.apiKeyId,
    "kitsos.resource.id": aliasId,
  });
  return c.body(null, 204);
});

app.delete("/aliases/:aliasId", async (c) => {
  const auth = await authenticateApiKey(c.req.raw, c.env, "hme:delete", APP_ID);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  const aliasId = c.req.param("aliasId");
  await c.env.DB.prepare("DELETE FROM hme_aliases WHERE id = ? AND user_id = ?")
    .bind(aliasId, auth.context!.userId)
    .run();
  recordEvent("hme.alias.delete", "success", {
    "kitsos.user.id": auth.context!.userId,
    "kitsos.api_key.id": auth.context!.apiKeyId,
    "kitsos.resource.id": aliasId,
  });
  return c.body(null, 204);
});

/**
 * Handles incoming mail via Cloudflare Email Routing (configured in the
 * dashboard — see README). Looks up the recipient's local part in
 * `hme_aliases`; if active, forwards to the stored `forward_to` address.
 * Cloudflare only relays to destination addresses that are verified in
 * Email Routing, and only rejects (not silently drops) on unknown/disabled
 * aliases so senders get a proper bounce.
 */
async function email(message: ForwardableEmailMessage, env: Env, _ctx: ExecutionContext): Promise<void> {
  const localPart = message.to.split("@")[0];

  const row = await env.DB.prepare("SELECT id, user_id, forward_to, status FROM hme_aliases WHERE alias = ?")
    .bind(localPart)
    .first<{ id: string; user_id: string; forward_to: string; status: string }>();

  if (!row || row.status !== "active") {
    recordEvent("hme.email.forward", "denied", {
      "error.code": row ? "alias-disabled" : "alias-not-found",
      ...(row ? {
        "kitsos.user.id": row.user_id,
        "kitsos.resource.id": row.id,
      } : {}),
    });
    message.setReject("Unknown or disabled alias");
    return;
  }

  await message.forward(row.forward_to);
  recordEvent("hme.email.forward", "success", {
    "kitsos.user.id": row.user_id,
    "kitsos.resource.id": row.id,
  });

  await env.DB.prepare(
    "UPDATE hme_aliases SET emails_forwarded = emails_forwarded + 1, last_forwarded_at = unixepoch() WHERE id = ?"
  )
    .bind(row.id)
    .run()
    .catch(() => {});
}

export default withTelemetry({
  fetch: app.fetch,
  email,
} satisfies ExportedHandler<Env>, "hide-my-email");
