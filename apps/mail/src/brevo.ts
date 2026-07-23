import type { Env } from "./env";

export interface SendEmailParams {
  from: string;
  to: string[];
  subject: string;
  html?: string;
  text?: string;
}

export async function sendViaBrevo(env: Env, params: SendEmailParams): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": env.BREVO_API_KEY,
      "Content-Type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      sender: { email: params.from },
      to: params.to.map((email) => ({ email })),
      subject: params.subject,
      htmlContent: params.html,
      textContent: params.text,
    }),
  });

  if (res.ok) return { ok: true };
  const body = await res.text().catch(() => "");
  return { ok: false, error: `brevo ${res.status}: ${body.slice(0, 200)}` };
}
