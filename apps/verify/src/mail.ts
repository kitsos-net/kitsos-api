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
): Promise<boolean> {
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
    return res.ok;
  } catch {
    return false;
  }
}
