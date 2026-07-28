import type { Env } from "./env";

export interface SendEmailParams {
  from: string;
  to: string[];
  subject: string;
  html?: string;
  text?: string;
}

export async function sendViaBrevo(env: Env, params: SendEmailParams): Promise<{ ok: boolean; error?: string }> {
  const payload = JSON.stringify({
    sender: { email: params.from },
    to: params.to.map((email) => ({ email })),
    subject: params.subject,
    htmlContent: params.html,
    textContent: params.text,
  });
  if (new TextEncoder().encode(payload).byteLength > 4 * 1024 * 1024) {
    return { ok: false, error: "outbound message too large" };
  }
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": env.BREVO_API_KEY,
      "Content-Type": "application/json",
      accept: "application/json",
    },
    body: payload,
  });

  if (res.ok) return { ok: true };
  const body = await res.text().catch(() => "");
  return { ok: false, error: `brevo ${res.status}: ${body.slice(0, 200)}` };
}
