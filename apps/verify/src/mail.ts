import type { Env } from "./env";

/**
 * Sends the magic-link verification email via mail.api.kitsos.net.
 *
 * NOTE: endpoint path / payload shape here is a best guess based on
 * the mail API's general design (scoped API keys, template-based
 * sending) — confirm against the actual mail.api.kitsos.net OpenAPI
 * spec once it exists (see [[kitsos-mail-api]]) and adjust.
 */
export async function sendMagicLinkEmail(
  env: Env,
  to: string,
  confirmUrl: string,
  resourceValue: string
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch("https://mail.api.kitsos.net/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        to,
        template: "resource-verification",
        variables: {
          resource: resourceValue,
          confirm_url: confirmUrl,
        },
      }),
    });
    if (res.ok) return { ok: true };
    const body = await res.text().catch(() => "");
    return { ok: false, error: `mail-api ${res.status}: ${body.slice(0, 200)}` };
  } catch (e) {
    return { ok: false, error: `fetch-failed: ${String(e)}` };
  }
}
