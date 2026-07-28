import type { Env } from "./env";

const DEFAULT_FROM_ADDRESS = "verify@kitsos.net";
const VERIFICATION_TEMPLATE_ID = "resource-verification";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Sends the magic-link verification email via mail.api.kitsos.net,
 * which forwards to Brevo internally — this worker never talks to
 * Brevo directly. Requires `MAIL_API_KEY` to be a kitsos_... key with
 * `mail:send` scope, and `env.MAIL_FROM_ADDRESS` (or the default
 * below) to have a resource_grant for that scope in mail's D1.
 */
export async function sendMagicLinkEmail(
  env: Env,
  to: string,
  confirmUrl: string,
  resourceValue: string
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch("https://mail.api.kitsos.net/v1/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.MAIL_FROM_ADDRESS || DEFAULT_FROM_ADDRESS,
        to: [to],
        subject: "Kitsos — Bestätige deine Verifizierung",
        template: VERIFICATION_TEMPLATE_ID,
        data: {
          // magicLink keeps the previously published CDN template functional
          // while confirm_url is the canonical variable used by the v1 design.
          magicLink: escapeHtml(confirmUrl),
          resource: escapeHtml(resourceValue),
          confirm_url: escapeHtml(confirmUrl),
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
