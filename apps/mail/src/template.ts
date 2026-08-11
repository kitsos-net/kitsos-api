import type { Env } from "./env";

const TEMPLATE_CACHE_TTL_SECONDS = 3600;
const MAX_TEMPLATE_BYTES = 3 * 1024 * 1024;
const MAX_RENDERED_TEMPLATE_BYTES = 4 * 1024 * 1024;
const TEMPLATE_FETCH_TIMEOUT_MS = 5000;

export class TemplateFetchError extends Error {
  constructor(
    readonly code: string,
    readonly upstreamStatus?: number,
  ) {
    super(code);
    this.name = "TemplateFetchError";
  }
}

async function readBoundedBody(res: Response, maximumBytes: number): Promise<Uint8Array> {
  if (!res.body) return new Uint8Array();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel("template response too large");
      throw new TemplateFetchError("template-response-too-large");
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

/**
 * Fetches a template's HTML from its source URL, cached in KV for an
 * hour so a burst of webhook sends doesn't refetch the same page
 * every time. Cache key includes the template id, not the URL, so
 * `PATCH /templates/:id` can invalidate it directly.
 */
export async function getTemplateHtml(env: Env, templateId: string, url: string): Promise<string> {
  const cacheKey = `tpl:${templateId}`;
  const cached = await env.AUTH_CACHE.get(cacheKey).catch(() => null);
  if (cached) return cached;

  let res: Response;
  try {
    res = await fetch(url, {
      // Workerd does not implement redirect: "error". Manual mode preserves
      // the SSRF boundary: redirects are returned and explicitly rejected.
      redirect: "manual",
      signal: AbortSignal.timeout(TEMPLATE_FETCH_TIMEOUT_MS),
      headers: { accept: "text/html, text/plain;q=0.9" },
    });
  } catch (error) {
    throw new TemplateFetchError(
      error instanceof Error && error.name === "TimeoutError"
        ? "template-fetch-timeout"
        : "template-network-error",
    );
  }
  if (res.status >= 300 && res.status < 400) {
    await res.body?.cancel("template redirect rejected").catch(() => {});
    throw new TemplateFetchError("template-redirect-rejected", res.status);
  }
  if (!res.ok) {
    await res.body?.cancel("template upstream rejected").catch(() => {});
    throw new TemplateFetchError("template-upstream-http-error", res.status);
  }
  const contentLength = Number(res.headers.get("content-length") ?? 0);
  if (contentLength > MAX_TEMPLATE_BYTES) {
    await res.body?.cancel("template response too large").catch(() => {});
    throw new TemplateFetchError("template-response-too-large", res.status);
  }

  const body = await readBoundedBody(res, MAX_TEMPLATE_BYTES);
  const html = new TextDecoder().decode(body);

  // Template delivery must not fail merely because the optional KV cache has
  // exhausted its daily write budget. The bounded HTTPS source remains the
  // authoritative fallback.
  await env.AUTH_CACHE.put(
    cacheKey,
    html,
    { expirationTtl: TEMPLATE_CACHE_TTL_SECONDS },
  ).catch(() => {});
  return html;
}

export async function invalidateTemplateCache(env: Env, templateId: string): Promise<void> {
  await env.AUTH_CACHE.delete(`tpl:${templateId}`).catch(() => {});
}

/** Renders `{{ variableName }}` placeholders — same syntax as Certimate itself. */
export function renderTemplate(html: string, data: Record<string, string>): string {
  const rendered = html.replace(
    /\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g,
    (_match, key) => data[key] ?? ""
  );
  if (new TextEncoder().encode(rendered).byteLength > MAX_RENDERED_TEMPLATE_BYTES) {
    throw new Error("rendered template too large");
  }
  return rendered;
}
