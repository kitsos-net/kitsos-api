/**
 * Looks up TXT records for a hostname via Cloudflare's DNS-over-HTTPS
 * endpoint (Workers have no native DNS resolver). Returns the decoded
 * TXT record strings.
 */
export async function lookupTxtRecords(hostname: string): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`;
  const res = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new Error(`dns-query-failed:${res.status}`);

  const data = await res.json<{ Answer?: { data: string; type: number }[] }>();
  if (!data.Answer) return [];

  // TXT answers come back double-quoted (DNS wire format), strip that
  return data.Answer.filter((a) => a.type === 16).map((a) => a.data.replace(/^"|"$/g, ""));
}

export function verificationRecordName(value: string): string {
  return `_kitsos-verify.${value}`;
}

export function generateVerificationToken(): string {
  return `kitsos-verify=${crypto.randomUUID().replace(/-/g, "")}`;
}
