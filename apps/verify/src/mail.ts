import type { Env } from "./env";

const DEFAULT_FROM_ADDRESS = "verify@kitsos.net";

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
    const res = await fetch("https://mail.api.kitsos.net/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.MAIL_FROM_ADDRESS || DEFAULT_FROM_ADDRESS,
        to: [to],
        subject: "Kitsos — Bestätige deine Verifizierung",
        template: "resource-verification",
        data: {
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
