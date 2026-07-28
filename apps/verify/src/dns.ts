/**
 * Looks up TXT records for a hostname via Cloudflare's DNS-over-HTTPS
 * endpoint (Workers have no native DNS resolver). Returns the decoded
 * TXT record strings.
 */
export async function lookupTxtRecords(hostname: string): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) return [];

  const contentLength = Number(res.headers.get("content-length") ?? 0);
  if (contentLength > 64 * 1024) return [];
  const body = await res.text();
  if (new TextEncoder().encode(body).byteLength > 64 * 1024) return [];
  let data: { Answer?: { data: string; type: number }[] };
  try {
    data = JSON.parse(body) as { Answer?: { data: string; type: number }[] };
  } catch {
    return [];
  }
  if (!data.Answer) return [];

  // TXT answers come back double-quoted (DNS wire format), strip that
  return data.Answer
    .filter((answer) =>
      answer?.type === 16
      && typeof answer.data === "string"
      && answer.data.length <= 4096
    )
    .slice(0, 100)
    .map((answer) => answer.data.replace(/^"|"$/g, ""));
}

export function verificationRecordName(value: string): string {
  return `_kitsos-verify.${value}`;
}

export function generateVerificationToken(): string {
  return `kitsos-verify=${crypto.randomUUID().replace(/-/g, "")}`;
}
