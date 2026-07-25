import type { Env } from "./env";

/**
 * Sends the magic-link verification email via the constrained internal mail
 * endpoint. This worker never talks to Brevo directly. `MAIL_API_KEY` must
 * have only the `mail:send:verification` scope.
 */
export async function sendMagicLinkEmail(
  env: Env,
  to: string,
  confirmUrl: string,
  resourceValue: string
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch("https://mail.api.kitsos.net/internal/verification-email", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        to,
        confirmUrl,
        resource: resourceValue,
      }),
    });
    if (res.ok) return { ok: true };
    const body = await res.text().catch(() => "");
    return { ok: false, error: `mail-api ${res.status}: ${body.slice(0, 200)}` };
  } catch (e) {
    return { ok: false, error: `fetch-failed: ${String(e)}` };
  }
}
