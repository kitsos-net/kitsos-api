import { Hono } from "hono";
import { WorkerEntrypoint } from "cloudflare:workers";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import {
  authenticate,
  checkResourceGrant,
  consumeHardDailyLimit,
  getEffectiveLimit,
  acceptPrivateMcpDelegation,
} from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import { generateAlias } from "./alias";
import type { Env } from "./env";

const APP_ID = "hide-my-email";
const DOMAIN = "hme.kitsos.net";
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

type Vars = { userId: string };
const app = new Hono<{ Bindings: Env; Variables: Vars }>().basePath("/v1");

app.use("*", async (c, next) => {
  if (c.req.url.length > 8192) return c.json({ error: "uri-too-long" }, 414);
  await next();
});
app.use("*", bodyLimit({
  maxSize: 64 * 1024,
  onError: (c) => c.json({ error: "request-body-too-large" }, 413),
}));
app.use("*", cors({
  origin: (origin, c) => {
    const configured = (c.env as Env).CORS_ORIGINS
      ?? "https://apidev.kitsos.net,https://myaccount.kitsos.net";
    const allowedOrigins = configured.split(",").map((item) => item.trim());
    allowedOrigins.push("https://docs.api.kitsos.net");
    return allowedOrigins.includes(origin) ? origin : null;
  },
  allowHeaders: ["Authorization", "Content-Type"],
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

app.get("/health", (c) => c.json({ ok: true }));

app.get("/aliases", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "hme:read", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const page = pagination(c.req.query("limit"), c.req.query("offset"));
  if (!page) return c.json({ error: "invalid-pagination" }, 400);
  const r = await c.env.DB.prepare(
    "SELECT id, alias, domain, forward_to, label, status, emails_forwarded, last_forwarded_at, created_at FROM hme_aliases WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
  )
    .bind(auth.context!.userId, page.limit, page.offset)
    .all();
  return c.json(r.results);
});

app.post("/aliases", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "hme:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const ctx = auth.context!;

  const body = await c.req.json<{ forwardTo: string; label?: string }>().catch(() => null);
  if (
    !body
    || typeof body.forwardTo !== "string"
    || !EMAIL_PATTERN.test(body.forwardTo)
    || body.forwardTo.length > 320
    || (body.label !== undefined && (typeof body.label !== "string" || body.label.length > 200))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }
  const forwardTo = body.forwardTo.trim().toLowerCase();

  const grant = await checkResourceGrant(c.env, ctx, "email_address", forwardTo);
  if (!grant.allowed) return c.json({ error: grant.reason }, 403);

  const withinHardCreationLimit = await consumeHardDailyLimit(
    c.env,
    ctx.userId,
    APP_ID,
    "alias_creations_per_day",
    500
  );
  if (!withinHardCreationLimit) {
    return c.json({ error: "alias-creation-abuse-limit-exceeded" }, 429);
  }
  const aliasLimit = await getEffectiveLimit(c.env, ctx.userId, "hme_aliases");
  const aliasId = id();
  let alias = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateAlias();
    try {
      const created = await c.env.DB.prepare(
        `INSERT INTO hme_aliases (id, user_id, alias, domain, forward_to, label)
         SELECT ?, ?, ?, ?, ?, ?
         WHERE (
           SELECT COUNT(*) FROM hme_aliases WHERE user_id = ?
         ) < ?`
      )
        .bind(
          aliasId,
          ctx.userId,
          candidate,
          DOMAIN,
          forwardTo,
          body.label ?? null,
          ctx.userId,
          aliasLimit
        )
        .run();
      if (created.meta.changes !== 1) {
        return c.json({ error: "alias-limit-exceeded", limit: aliasLimit }, 429);
      }
      alias = candidate;
      break;
    } catch (error) {
      if (!String(error).toLowerCase().includes("unique")) throw error;
    }
  }
  if (!alias) return c.json({ error: "alias-generation-failed" }, 500);

  return c.json({ id: aliasId, email: `${alias}@${DOMAIN}`, forwardTo }, 201);
});

app.patch("/aliases/:aliasId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "hme:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  const ctx = auth.context!;
  const aliasId = c.req.param("aliasId");
  const body = await c.req.json<{ status?: "active" | "disabled"; label?: string; forwardTo?: string }>().catch(() => null);
  if (
    !body
    || (body.status !== undefined && !["active", "disabled"].includes(body.status))
    || (body.label !== undefined && (typeof body.label !== "string" || body.label.length > 200))
    || (body.forwardTo !== undefined && (
      typeof body.forwardTo !== "string"
      || !EMAIL_PATTERN.test(body.forwardTo)
      || body.forwardTo.length > 320
    ))
  ) {
    return c.json({ error: "invalid-request-body" }, 400);
  }

  if (body.forwardTo) {
    const grant = await checkResourceGrant(
      c.env,
      ctx,
      "email_address",
      body.forwardTo.trim().toLowerCase()
    );
    if (!grant.allowed) return c.json({ error: grant.reason }, 403);
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  if (body.status) { updates.push("status = ?"); values.push(body.status); }
  if (body.label !== undefined) { updates.push("label = ?"); values.push(body.label); }
  if (body.forwardTo) { updates.push("forward_to = ?"); values.push(body.forwardTo.trim().toLowerCase()); }
  if (updates.length === 0) return c.body(null, 204);

  values.push(aliasId, ctx.userId);
  await c.env.DB.prepare(`UPDATE hme_aliases SET ${updates.join(", ")} WHERE id = ? AND user_id = ?`)
    .bind(...values)
    .run();
  return c.body(null, 204);
});

app.delete("/aliases/:aliasId", async (c) => {
  const auth = await authenticate(c.req.raw, c.env, "hme:manage", APP_ID);
  if (!auth.allowed) return c.json({ error: auth.reason }, auth.status as 401 | 403 | 429);
  await c.env.DB.prepare("DELETE FROM hme_aliases WHERE id = ? AND user_id = ?")
    .bind(c.req.param("aliasId"), auth.context!.userId)
    .run();
  return c.body(null, 204);
});

app.notFound((c) => c.json({ error: "not-found" }, 404));
app.onError((_error, c) => c.json({ error: "internal-error" }, 500));

const instrumented = withTelemetry(app, "hide-my-email");

/**
 * Handles incoming mail via Cloudflare Email Routing (configured in the
 * dashboard — see README). Looks up the recipient's local part in
 * `hme_aliases`; if active, forwards to the stored `forward_to` address.
 * Cloudflare only relays to destination addresses that are verified in
 * Email Routing, and only rejects (not silently drops) on unknown/disabled
 * aliases so senders get a proper bounce.
 */
async function email(message: ForwardableEmailMessage, env: Env, _ctx: ExecutionContext): Promise<void> {
  if (message.rawSize > 10 * 1024 * 1024) {
    message.setReject("Message too large");
    return;
  }
  const [localPart, recipientDomain] = message.to.toLowerCase().split("@");
  if (!localPart || recipientDomain !== DOMAIN) {
    message.setReject("Unknown recipient");
    return;
  }

  const row = await env.DB.prepare("SELECT id, user_id, forward_to, status FROM hme_aliases WHERE alias = ?")
    .bind(localPart)
    .first<{ id: string; user_id: string; forward_to: string; status: string }>();

  if (!row || row.status !== "active") {
    message.setReject("Unknown or disabled alias");
    return;
  }

  const grant = await checkResourceGrant(
    env,
    {
      method: "api_key",
      userId: row.user_id,
      appId: APP_ID,
      scopes: ["hme:receive"],
      groupIds: [],
    },
    "email_address",
    row.forward_to
  );
  if (!grant.allowed) {
    message.setReject("Alias destination is no longer verified");
    return;
  }

  const withinUserForwardLimit = await consumeHardDailyLimit(
    env,
    row.user_id,
    APP_ID,
    "hme_forwards_per_day",
    5_000
  );
  const withinAliasForwardLimit = await consumeHardDailyLimit(
    env,
    row.user_id,
    APP_ID,
    `hme_forwards_${row.id.replace(/-/g, "")}`,
    1_000
  );
  if (!withinUserForwardLimit || !withinAliasForwardLimit) {
    message.setReject("Forwarding rate limit exceeded");
    return;
  }

  await message.forward(row.forward_to);

  await env.DB.prepare(
    "UPDATE hme_aliases SET emails_forwarded = emails_forwarded + 1, last_forwarded_at = unixepoch() WHERE id = ?"
  )
    .bind(row.id)
    .run()
    .catch(() => {});
}

export default {
  fetch: instrumented.fetch,
  email,
};

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
