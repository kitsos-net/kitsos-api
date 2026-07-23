import type { Env } from "./env";

const TEMPLATE_CACHE_TTL_SECONDS = 3600;

/**
 * Fetches a template's HTML from its source URL, cached in KV for an
 * hour so a burst of webhook sends doesn't refetch the same page
 * every time. Cache key includes the template id, not the URL, so
 * `PATCH /templates/:id` can invalidate it directly.
 */
export async function getTemplateHtml(env: Env, templateId: string, url: string): Promise<string> {
  const cacheKey = `tpl:${templateId}`;
  const cached = await env.AUTH_CACHE.get(cacheKey);
  if (cached) return cached;

  const res = await fetch(url);
  if (!res.ok) throw new Error(`template fetch failed: ${res.status}`);
  const html = await res.text();

  await env.AUTH_CACHE.put(cacheKey, html, { expirationTtl: TEMPLATE_CACHE_TTL_SECONDS });
  return html;
}

export async function invalidateTemplateCache(env: Env, templateId: string): Promise<void> {
  await env.AUTH_CACHE.delete(`tpl:${templateId}`);
}

/** Renders `{{ variableName }}` placeholders — same syntax as Certimate itself. */
export function renderTemplate(html: string, data: Record<string, string>): string {
  return html.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, key) => data[key] ?? "");
}
