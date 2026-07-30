import { Hono } from "hono";
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Context } from "hono";
import { cors } from "hono/cors";
import {
  acceptPrivateMcpDelegation,
  authenticate,
  authenticateApiKey,
  checkRateLimit,
  withRetryAfter,
} from "@kitsos/auth";
import { withTelemetry } from "@kitsos/telemetry";
import type { Env } from "./env";

const APP_ID = "utility";
const PUBLIC_RATE_LIMIT = { windowSeconds: 60, maxRequests: 5 };
const KEY_RATE_LIMIT = { windowSeconds: 60, maxRequests: 120 };
const HASH_ALGORITHMS: Record<string, AlgorithmIdentifier> = {
  "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512",
};
const DNS_TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28 };
const DNS_PROVIDERS = {
  google: { url: "https://dns.google/resolve", resolver: "8.8.8.8" },
  cloudflare: { url: "https://cloudflare-dns.com/dns-query", resolver: "1.1.1.1" },
  quad9: { url: "https://dns.quad9.net/dns-query", resolver: "9.9.9.9" },
} as const;

type Vars = { authenticated: boolean };
type UtilityContext = Context<{ Bindings: Env; Variables: Vars }>;
const app = new Hono<{ Bindings: Env; Variables: Vars }>().basePath("/v1");

app.use("*", cors({ origin: "*", allowHeaders: ["Authorization", "Content-Type"], allowMethods: ["GET", "OPTIONS"] }));
app.use("*", async (c, next) => {
  if (c.req.url.length > 8192) return c.json({ error: "uri-too-long" }, 414);
  const startedAt = Date.now();
  await next();
  console.log(JSON.stringify({ service: APP_ID, method: c.req.method, path: new URL(c.req.url).pathname, status: c.res.status, durationMs: Date.now() - startedAt, rayId: c.req.header("CF-Ray") ?? undefined }));
});

function clientIp(request: Request) { return request.headers.get("CF-Connecting-IP") ?? "unknown"; }
function text(c: UtilityContext, body: string, status: 200 | 400 | 404 | 429 | 502 = 200) {
  return c.text(body, status, { "Content-Type": "text/plain; charset=utf-8" });
}
function int(value: string | undefined, fallback: number) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}
function validDnsName(name: string) {
  return name.length <= 253 && name.split(".").every((label) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(label));
}

async function authorize(c: UtilityContext, scope: string): Promise<Response | null> {
  if (c.env.MCP_DELEGATION) {
    const auth = await authenticate(c.req.raw, c.env, scope, APP_ID, KEY_RATE_LIMIT);
    if (!auth.allowed) {
      return withRetryAfter(
        c.json({ error: auth.reason }, auth.status as 401 | 403 | 429),
        auth,
      );
    }
    c.set("authenticated", true);
    return null;
  }
  if (!c.req.header("Authorization")) {
    const rate = await checkRateLimit(c.env, `utility:public:${clientIp(c.req.raw)}`, PUBLIC_RATE_LIMIT);
    if (!rate.allowed) return withRetryAfter(c.json({ error: "public-rate-limit-exceeded", message: "The public limit is exhausted. Use a Kitsos API key for higher limits." }, 429), rate);
    c.set("authenticated", false);
    return null;
  }
  const auth = await authenticateApiKey(c.req.raw, c.env, scope, APP_ID, KEY_RATE_LIMIT);
  if (!auth.allowed) return withRetryAfter(c.json({ error: auth.reason }, auth.status as 401 | 403 | 429), auth);
  c.set("authenticated", true);
  return null;
}

function passwordCharset(params: URLSearchParams) {
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  if (params.has("symbols")) chars += "!@#$%^&*()_+~`|}{[]:;?><,./-=";
  if (params.has("strong")) chars += "!?#$";
  return chars;
}
function randomUint32() { return crypto.getRandomValues(new Uint32Array(1))[0]; }
function randomIntInclusive(min: number, max: number) {
  const range = max - min + 1;
  const maxUint32Exclusive = 0x1_0000_0000;
  const unbiasedLimit = Math.floor(maxUint32Exclusive / range) * range;
  let value = randomUint32();
  while (value >= unbiasedLimit) value = randomUint32();
  return min + (value % range);
}

app.get("/crypt/pass", async (c) => {
  const denied = await authorize(c, "utility:crypt"); if (denied) return denied;
  const length = int(c.req.query("len"), 20);
  if (length === null || length < 1 || length > 16_384) return text(c, "Fehler: len muss zwischen 1 und 16384 liegen", 400);
  const charset = passwordCharset(new URL(c.req.url).searchParams);
  const values = crypto.getRandomValues(new Uint32Array(length));
  return text(c, Array.from(values, (value) => charset[value % charset.length]).join(""));
});

app.get("/crypt/token", async (c) => {
  const denied = await authorize(c, "utility:crypt"); if (denied) return denied;
  const length = int(c.req.query("len"), 32);
  const encoding = c.req.query("enc") ?? "hex";
  if (length === null || length < 1 || length > 65_536 || !["hex", "base64"].includes(encoding)) return text(c, "Fehler: ungültige Länge oder Kodierung", 400);
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  if (encoding === "base64") return text(c, btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
  return text(c, Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""));
});

app.get("/crypt/num", async (c) => {
  const denied = await authorize(c, "utility:crypt"); if (denied) return denied;
  const min = int(c.req.query("min"), 0); const max = int(c.req.query("max"), 100);
  if (min === null || max === null || min > max || max - min > 4_294_967_295) return text(c, "Fehler: ungültiger Zahlenbereich", 400);
  return text(c, String(randomIntInclusive(min, max)));
});

app.get("/crypt/hash", async (c) => {
  const denied = await authorize(c, "utility:crypt"); if (denied) return denied;
  const value = c.req.query("text") ?? c.req.query("value");
  const algorithm = (c.req.query("algo") ?? c.req.query("algorithm") ?? "SHA-256").toUpperCase();
  if (value === undefined || value.length > 16_384 || !HASH_ALGORITHMS[algorithm]) return text(c, "Fehler: Text oder Algorithmus ungültig", 400);
  const digest = await crypto.subtle.digest(HASH_ALGORITHMS[algorithm], new TextEncoder().encode(value));
  return text(c, Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""));
});

app.get("/crypt/help", async (c) => {
  const denied = await authorize(c, "utility:crypt"); if (denied) return denied;
  return text(c, "CRYPT API\n\n/crypt/pass?len=20&symbols&strong\n/crypt/token?len=32&enc=hex|base64\n/crypt/num?min=0&max=100\n/crypt/hash?text=Hello&algo=SHA-256");
});

function timeParts(now: Date, timeZone: string) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).formatToParts(now);
  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
}
app.get("/time", async (c) => {
  const denied = await authorize(c, "utility:time"); if (denied) return denied;
  const cf = c.req.raw.cf as IncomingRequestCfProperties | undefined;
  const requestedZone = c.req.query("tz");
  const timeZone = requestedZone ?? cf?.timezone ?? "UTC";
  try {
    const now = new Date(); const value = timeParts(now, timeZone); const format = c.req.query("format");
    if (format !== undefined) return text(c, format.replace(/\{Y\}/g, value.year).replace(/\{m\}/g, value.month).replace(/\{d\}/g, value.day).replace(/\{H\}/g, value.hour).replace(/\{M\}/g, value.minute).replace(/\{S\}/g, value.second));
    return c.json({ status: "success", timezone: timeZone, method: requestedZone ? "manual" : "auto-detected (IP)", formatted: `${value.day}.${value.month}.${value.year} ${value.hour}:${value.minute}:${value.second}`, iso: now.toISOString() });
  } catch { return text(c, `Fehler: "${timeZone}" ist keine gültige Zeitzone. Siehe /time/zones`, 400); }
});
app.get("/time/zones", async (c) => {
  const denied = await authorize(c, "utility:time"); if (denied) return denied;
  return text(c, `Verfügbare Zeitzonen:\n\n${Intl.supportedValuesOf("timeZone").join("\n")}`);
});
app.get("/time/help", async (c) => {
  const denied = await authorize(c, "utility:time"); if (denied) return denied;
  return text(c, "TIME API\n\n/time?tz=Europe/Berlin\n/time?format={H}:{M}\n/time/zones");
});

function geoData(request: Request) {
  const cf = request.cf as IncomingRequestCfProperties | undefined;
  return { ip: request.headers.get("CF-Connecting-IP") ?? "Unknown", city: cf?.city ?? "Unknown", region: cf?.region ?? "Unknown", regionCode: cf?.regionCode ?? "Unknown", country: cf?.country ?? "Unknown", continent: cf?.continent ?? "Unknown", lat: cf?.latitude ?? "0.00", lon: cf?.longitude ?? "0.00", timezone: cf?.timezone ?? "UTC", asn: cf?.asn ?? "Unknown", isp: cf?.asOrganization ?? "Unknown", colo: cf?.colo ?? "Unknown" };
}
app.get("/geo", async (c) => {
  const denied = await authorize(c, "utility:geo"); if (denied) return denied;
  const data = geoData(c.req.raw);
  if (c.req.query("format") === "txt") return text(c, Object.entries(data).map(([key, value]) => `${key}: ${value}`).join("\n"));
  return c.json(data);
});
app.get("/geo/help", async (c) => {
  const denied = await authorize(c, "utility:geo"); if (denied) return denied;
  return text(c, "GEO API\n\n/geo?format=json|txt\nReturns IP, location, ASN, ISP and Cloudflare colo.");
});

type DnsAnswer = { name: string; type: number; TTL: number; data: string };
async function resolveDns(name: string, type: string, resolver: keyof typeof DNS_PROVIDERS) {
  const provider = DNS_PROVIDERS[resolver];
  const response = await fetch(`${provider.url}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error("DNS upstream failed");
  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (declaredLength > 64 * 1024) throw new Error("DNS upstream response too large");
  const raw = await response.text();
  if (new TextEncoder().encode(raw).byteLength > 64 * 1024) {
    throw new Error("DNS upstream response too large");
  }
  const payload = JSON.parse(raw) as {
    Status?: number;
    ID?: number;
    Flags?: number;
    Question?: unknown[];
    Answer?: DnsAnswer[];
    Authority?: DnsAnswer[];
    Additional?: DnsAnswer[];
  };
  const bounded = (rows: DnsAnswer[] | undefined) => (rows ?? [])
    .filter((row) => typeof row?.data === "string" && row.data.length <= 4096)
    .slice(0, 100);
  return {
    id: payload.ID ?? null,
    flags: payload.Flags ?? null,
    questions: (payload.Question ?? []).slice(0, 100),
    answers: bounded(payload.Answer),
    authorities: bounded(payload.Authority),
    additionals: bounded(payload.Additional),
  };
}
async function dnsEndpoint(c: UtilityContext, provider?: keyof typeof DNS_PROVIDERS) {
  const denied = await authorize(c, "utility:dns"); if (denied) return denied;
  const name = c.req.query("name")?.replace(/\.$/, ""); const type = (c.req.query("type") ?? "A").toUpperCase();
  if (!name || !validDnsName(name) || !DNS_TYPES[type]) return c.json({ error: "Parameter 'name' oder 'type' ungültig." }, 400);
  const startedAt = Date.now();
  try {
    const selected = provider ?? "cloudflare";
    const result = await resolveDns(name, type, selected);
    const headers = c.req.query("cache") === "false" ? { "Cache-Control": "no-store" } : { "Cache-Control": "public, max-age=60" };
    return c.json({ ...result, mode: provider ? "forwarding" : "recursive", ...(provider ? { resolver: DNS_PROVIDERS[selected].resolver } : {}), execution_time_ms: Date.now() - startedAt }, 200, headers);
  } catch (error) { return c.json({ error: error instanceof Error ? error.message : "DNS resolution failed" }, 502); }
}
app.get("/dns", (c) => dnsEndpoint(c));
app.get("/dns/help", async (c) => {
  const denied = await authorize(c, "utility:dns"); if (denied) return denied;
  return text(c, "DNS API\n\n/dns?name=example.com&type=A&cache=false\n/dns/google?name=example.com&type=AAAA\nProviders: google, cloudflare, quad9");
});
app.get("/dns/:provider", (c) => {
  const provider = c.req.param("provider");
  if (!(provider in DNS_PROVIDERS)) return c.json({ error: "Unknown DNS provider" }, 404);
  return dnsEndpoint(c, provider as keyof typeof DNS_PROVIDERS);
});

app.get("/health", (c) => c.json({ ok: true }));
const instrumented = withTelemetry(app, "utility");

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
