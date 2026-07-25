import { Hono } from "hono";
import type { Context } from "hono";
import { cors } from "hono/cors";
import { authenticateApiKey, checkRateLimit, withRetryAfter } from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import type { Env } from "./env";

const APP_ID = "utility";
const PUBLIC_RATE_LIMIT = { windowSeconds: 60, maxRequests: 5 };
const KEY_RATE_LIMIT = { windowSeconds: 60, maxRequests: 120 };
const ALGORITHMS: Record<string, AlgorithmIdentifier> = {
  "SHA-256": "SHA-256",
  "SHA-384": "SHA-384",
  "SHA-512": "SHA-512",
};
const DNS_TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT"]);

type Vars = { authenticated: boolean };
const app = new Hono<{ Bindings: Env; Variables: Vars }>();
type UtilityContext = Context<{ Bindings: Env; Variables: Vars }>;

app.use("*", cors({
  origin: "*",
  allowHeaders: ["Authorization", "Content-Type"],
  allowMethods: ["GET", "OPTIONS"],
}));

// Cloudflare request logs stay useful even before optional Axiom credentials
// are configured. Do not log query values (hash input and DNS labels may be
// sensitive); method, path and response metadata are sufficient for ops.
app.use("*", async (c, next) => {
  const startedAt = Date.now();
  await next();
  console.log(JSON.stringify({
    service: APP_ID,
    method: c.req.method,
    path: new URL(c.req.url).pathname,
    status: c.res.status,
    durationMs: Date.now() - startedAt,
    rayId: c.req.header("CF-Ray") ?? undefined,
  }));
});

function clientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}

function validHostname(name: string): boolean {
  return name.length > 0 && name.length <= 253 && name.split(".").every(
    (label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
  );
}

async function authorize(c: UtilityContext, scope: string) {
  const authorization = c.req.header("Authorization");
  if (!authorization) {
    const rate = await checkRateLimit(c.env, `utility:public:${clientIp(c.req.raw)}`, PUBLIC_RATE_LIMIT);
    if (!rate.allowed) {
      return withRetryAfter(c.json({
        error: "public-rate-limit-exceeded",
        message: "The public limit is exhausted. Use a Kitsos API key for higher limits.",
      }, 429), rate);
    }
    c.set("authenticated", false);
    return null;
  }

  const auth = await authenticateApiKey(c.req.raw, c.env, scope, APP_ID, KEY_RATE_LIMIT);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  c.set("authenticated", true);
  return null;
}

app.get("/crypt/hash", async (c) => {
  const denied = await authorize(c, "utility:crypt");
  if (denied) return denied;
  const value = c.req.query("value");
  const algorithm = (c.req.query("algorithm") ?? "SHA-256").toUpperCase();
  if (value === undefined || value.length > 16_384 || !ALGORITHMS[algorithm]) {
    return c.json({ error: "invalid-request", message: "value (max 16 KiB) and a SHA-256, SHA-384, or SHA-512 algorithm are required." }, 400);
  }
  const digest = await crypto.subtle.digest(ALGORITHMS[algorithm], new TextEncoder().encode(value));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return c.json({ algorithm, hash, authenticated: c.get("authenticated") });
});

app.get("/time", async (c) => {
  const denied = await authorize(c, "utility:time");
  if (denied) return denied;
  const timeZone = c.req.query("timeZone") ?? "UTC";
  try {
    const now = new Date();
    const formatted = new Intl.DateTimeFormat("en-CA", {
      timeZone, dateStyle: "full", timeStyle: "long",
    }).format(now);
    return c.json({ timeZone, iso: now.toISOString(), unix: Math.floor(now.getTime() / 1000), formatted, authenticated: c.get("authenticated") });
  } catch {
    return c.json({ error: "invalid-time-zone" }, 400);
  }
});

app.get("/geo", async (c) => {
  const denied = await authorize(c, "utility:geo");
  if (denied) return denied;
  const cf = c.req.raw.cf as IncomingRequestCfProperties | undefined;
  return c.json({
    country: cf?.country ?? null,
    region: cf?.region ?? null,
    city: cf?.city ?? null,
    postalCode: cf?.postalCode ?? null,
    latitude: cf?.latitude ?? null,
    longitude: cf?.longitude ?? null,
    timezone: cf?.timezone ?? null,
    authenticated: c.get("authenticated"),
  });
});

app.get("/dns", async (c) => {
  const denied = await authorize(c, "utility:dns");
  if (denied) return denied;
  const name = c.req.query("name")?.replace(/\.$/, "");
  const type = (c.req.query("type") ?? "A").toUpperCase();
  if (!name || !validHostname(name) || !DNS_TYPES.has(type)) {
    return c.json({ error: "invalid-request", message: "A valid hostname and one of A, AAAA, CNAME, MX, TXT are required." }, 400);
  }
  const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
  });
  if (!response.ok) return c.json({ error: "dns-upstream-failed" }, 502);
  const payload = await response.json<{ Status?: number; Answer?: Array<{ name: string; type: number; TTL: number; data: string }> }>();
  return c.json({ name, type, status: payload.Status ?? null, answers: payload.Answer ?? [], authenticated: c.get("authenticated") });
});

app.get("/health", (c) => c.json({ ok: true }));

export default withTelemetry(app, "utility");
