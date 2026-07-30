import { expandScopes, getMcpPolicyScopes } from "@kitsos/auth";
import { configuredScopes } from "./connections";
import type { Env, McpProps } from "./env";

export type AccessType = "read" | "write" | "send";

export interface ScopeDefinition {
  id: string;
  appId: string;
  product: string;
  title: string;
  description: string;
  accessType: AccessType;
}

export const SCOPE_CATALOG: readonly ScopeDefinition[] = [
  {
    id: "account:read",
    appId: "keys-api",
    product: "Account",
    title: "Kontodaten lesen",
    description: "Profil, aktuelle Nutzung, Limits und eigene Limit-Anfragen anzeigen.",
    accessType: "read",
  },
  {
    id: "account:limits:request",
    appId: "keys-api",
    product: "Account",
    title: "Limit-Erhöhungen anfragen",
    description: "Neue Anfragen zur Erhöhung eines Produktlimits erstellen.",
    accessType: "write",
  },
  {
    id: "verify:read",
    appId: "verify",
    product: "Verify",
    title: "Verifizierungen lesen",
    description: "Eigene Ressourcen und deren Verifizierungsstatus anzeigen.",
    accessType: "read",
  },
  {
    id: "verify:manage",
    appId: "verify",
    product: "Verify",
    title: "Verifizierungen verwalten",
    description: "Ressourcen registrieren und DNS-Verifizierungen prüfen.",
    accessType: "write",
  },
  {
    id: "mail:read",
    appId: "mail",
    product: "Mail",
    title: "Mail-Konfiguration lesen",
    description: "Eigene Templates und Webhooks anzeigen.",
    accessType: "read",
  },
  {
    id: "mail:send",
    appId: "mail",
    product: "Mail",
    title: "E-Mails senden",
    description: "E-Mails von bereits verifizierten Absenderadressen senden.",
    accessType: "send",
  },
  {
    id: "mail:manage",
    appId: "mail",
    product: "Mail",
    title: "Mail-Konfiguration verwalten",
    description: "Templates und Webhooks erstellen, ändern und löschen.",
    accessType: "write",
  },
  {
    id: "hme:read",
    appId: "hide-my-email",
    product: "Hide My Email",
    title: "Aliase lesen",
    description: "Eigene Weiterleitungsaliase und deren Status anzeigen.",
    accessType: "read",
  },
  {
    id: "hme:manage",
    appId: "hide-my-email",
    product: "Hide My Email",
    title: "Aliase verwalten",
    description: "Weiterleitungsaliase erstellen, ändern und löschen.",
    accessType: "write",
  },
  {
    id: "utility:crypt",
    appId: "utility",
    product: "Utility",
    title: "Krypto-Hilfen verwenden",
    description: "Passwörter, Zufallswerte, Tokens und Hashes erzeugen.",
    accessType: "read",
  },
  {
    id: "utility:time",
    appId: "utility",
    product: "Utility",
    title: "Zeit-Hilfen verwenden",
    description: "Aktuelle Zeit und verfügbare Zeitzonen abrufen.",
    accessType: "read",
  },
  {
    id: "utility:geo",
    appId: "utility",
    product: "Utility",
    title: "Verbindungsstandort lesen",
    description: "Cloudflare-Standort- und Netzwerkmetadaten der MCP-Anfrage abrufen.",
    accessType: "read",
  },
  {
    id: "utility:dns",
    appId: "utility",
    product: "Utility",
    title: "DNS-Abfragen ausführen",
    description: "Öffentliche DNS-Einträge über unterstützte Resolver abfragen.",
    accessType: "read",
  },
] as const;

export const SUPPORTED_SCOPES = SCOPE_CATALOG.map((scope) => scope.id);
export const SCOPE_BY_ID = new Map(SCOPE_CATALOG.map((scope) => [scope.id, scope]));

export async function exposableScopeIds(env: Env): Promise<Set<string>> {
  const rows = await env.DB.prepare(
    "SELECT scope FROM app_scopes WHERE mcp_exposable = 1",
  ).all<{ scope: string }>();
  return new Set(rows.results
    .map((row) => row.scope)
    .filter((scope) => SCOPE_BY_ID.has(scope)));
}

export async function effectiveMcpScopes(
  env: Env,
  userId: string,
  delegationId: string,
  grantedScopes: string[],
): Promise<Set<string>> {
  const configured = await configuredScopes(
    env,
    userId,
    delegationId,
    grantedScopes,
  );
  const granted = new Set(expandScopes(configured));
  const effective = new Set<string>();
  const exposable = await exposableScopeIds(env);
  const appIds = [...new Set(SCOPE_CATALOG.map((scope) => scope.appId))];
  await Promise.all(appIds.map(async (appId) => {
    const policy = await getMcpPolicyScopes(env, userId, appId);
    if (!policy) return;
    const allowed = new Set(policy.scopes);
    for (const scope of SCOPE_CATALOG) {
      if (
        scope.appId === appId
        && exposable.has(scope.id)
        && granted.has(scope.id)
        && allowed.has(scope.id)
      ) {
        effective.add(scope.id);
      }
    }
  }));
  return effective;
}

export function isMcpProps(value: unknown): value is McpProps {
  if (!value || typeof value !== "object") return false;
  const props = value as Partial<McpProps>;
  return (
    typeof props.userId === "string"
    && typeof props.clientId === "string"
    && typeof props.delegationId === "string"
    && Array.isArray(props.scopes)
    && props.scopes.every((scope) => typeof scope === "string" && SCOPE_BY_ID.has(scope))
  );
}
