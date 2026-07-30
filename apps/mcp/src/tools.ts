import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { ToolContext } from "./env";
import { callUpstream, toolResponse } from "./upstream";

const pagination = {
  limit: z.number().int().min(1).max(100).default(50),
  offset: z.number().int().min(0).default(0),
};
const id = z.string().min(1).max(100);
const email = z.string().email().max(320);
const readOnly = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const create = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};
const update = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const remove = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: false,
};

function has(context: ToolContext, scope: string): boolean {
  return context.scopes.has(scope);
}

export function createKitsosMcpServer(context: ToolContext): McpServer {
  const server = new McpServer({
    name: "Kitsos API",
    version: "1.0.0",
    title: "Kitsos",
    description: "Kitsos Verify, Mail, Hide My Email, Utility and account self-service.",
  });

  if (has(context, "account:read")) {
    server.registerTool(
      "kitsos_account_get",
      {
        title: "Kitsos-Konto anzeigen",
        description: "Zeigt das eigene Kitsos-Benutzerprofil. API-Schlüssel werden nie ausgegeben.",
        inputSchema: z.object({}),
        annotations: readOnly,
      },
      async () => toolResponse(await callUpstream(context, {
        service: "KEYS_API",
        path: "/v1/me",
      })),
    );
    server.registerTool(
      "kitsos_account_limits_list",
      {
        title: "Kitsos-Limits anzeigen",
        description: "Zeigt effektive Produktlimits, aktuelle Nutzung und verbleibendes Kontingent.",
        inputSchema: z.object({}),
        annotations: readOnly,
      },
      async () => toolResponse(await callUpstream(context, {
        service: "KEYS_API",
        path: "/v1/me/limits",
      })),
    );
    server.registerTool(
      "kitsos_account_limit_requests_list",
      {
        title: "Limit-Anfragen anzeigen",
        description: "Listet die eigenen Anfragen auf Limit-Erhöhungen.",
        inputSchema: z.object(pagination),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "KEYS_API",
        path: "/v1/me/limit-increase-requests",
        query: args,
      })),
    );
  }

  if (has(context, "account:limits:request")) {
    server.registerTool(
      "kitsos_account_limit_request_create",
      {
        title: "Limit-Erhöhung anfragen",
        description: "Erstellt eine neue Anfrage zur Erhöhung eines Kitsos-Produktlimits.",
        inputSchema: z.object({
          appId: z.string().min(1).max(63),
          limitType: z.enum([
            "emails_per_day",
            "mail_templates",
            "mail_webhooks",
            "hme_aliases",
            "verified_resources",
            "verification_attempts_per_day",
            "mcp_connections",
          ]),
          requestedValue: z.number().int().min(1).max(10_000),
          reason: z.string().max(2_000).optional(),
        }),
        annotations: create,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "KEYS_API",
        method: "POST",
        path: "/v1/me/limit-increase-requests",
        body: args,
      })),
    );
  }

  if (has(context, "verify:read")) {
    server.registerTool(
      "kitsos_verify_resources_list",
      {
        title: "Verifizierungen anzeigen",
        description: "Listet eigene Ressourcen mit ihrem aktuellen Verifizierungsstatus.",
        inputSchema: z.object(pagination),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "VERIFY",
        path: "/v1/resources",
        query: args,
      })),
    );
  }

  if (has(context, "verify:manage")) {
    server.registerTool(
      "kitsos_verify_resource_start",
      {
        title: "Ressource verifizieren",
        description: "Registriert eine Ressource und startet eine DNS-TXT- oder Magic-Link-Verifizierung.",
        inputSchema: z.object({
          appId: z.string().min(1).max(63),
          resourceType: z.string().min(1).max(64),
          value: z.string().min(1).max(320),
          method: z.enum(["dns_txt", "magic_link"]),
          scopes: z.array(z.string().min(1).max(100)).min(1).max(100),
        }),
        annotations: create,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "VERIFY",
        method: "POST",
        path: "/v1/resources",
        body: args,
      })),
    );
    server.registerTool(
      "kitsos_verify_dns_check",
      {
        title: "DNS-Verifizierung prüfen",
        description: "Prüft den DNS-TXT-Eintrag einer begonnenen Verifizierung.",
        inputSchema: z.object({ resourceId: id }),
        annotations: update,
      },
      async ({ resourceId }) => toolResponse(await callUpstream(context, {
        service: "VERIFY",
        method: "POST",
        path: `/v1/resources/${encodeURIComponent(resourceId)}/check-dns`,
      })),
    );
  }

  if (has(context, "mail:read")) {
    server.registerTool(
      "kitsos_mail_templates_list",
      {
        title: "Mail-Templates anzeigen",
        description: "Listet die eigenen Kitsos-Mail-Templates.",
        inputSchema: z.object(pagination),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        path: "/v1/templates",
        query: args,
      })),
    );
    server.registerTool(
      "kitsos_mail_webhooks_list",
      {
        title: "Mail-Webhooks anzeigen",
        description: "Listet eigene Mail-Webhooks. Webhook-Secrets werden nicht ausgegeben.",
        inputSchema: z.object(pagination),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        path: "/v1/webhooks",
        query: args,
      })),
    );
  }

  if (has(context, "mail:send")) {
    server.registerTool(
      "kitsos_mail_send",
      {
        title: "E-Mail senden",
        description: "Sendet eine E-Mail von einer bereits verifizierten Absenderadresse.",
        inputSchema: z.object({
          from: email,
          to: z.array(email).min(1).max(50),
          subject: z.string().min(1).max(998),
          template: id.optional(),
          data: z.record(z.string(), z.string().max(65_536)).optional(),
          html: z.string().max(3_145_728).optional(),
          text: z.string().max(3_145_728).optional(),
        }),
        annotations: {
          ...create,
          openWorldHint: true,
        },
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "POST",
        path: "/v1/send",
        body: args,
      })),
    );
  }

  if (has(context, "mail:manage")) {
    server.registerTool(
      "kitsos_mail_template_create",
      {
        title: "Mail-Template erstellen",
        description: "Erstellt ein URL-basiertes Mail-Template.",
        inputSchema: z.object({
          name: z.string().min(1).max(100),
          url: z.string().url().max(2_048),
          variables: z.array(z.string().min(1).max(100)).max(100),
        }),
        annotations: create,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "POST",
        path: "/v1/templates",
        body: args,
      })),
    );
    server.registerTool(
      "kitsos_mail_template_update",
      {
        title: "Mail-Template ändern",
        description: "Ändert URL oder Variablen eines eigenen Mail-Templates.",
        inputSchema: z.object({
          templateId: id,
          url: z.string().url().max(2_048).optional(),
          variables: z.array(z.string().min(1).max(100)).max(100).optional(),
        }),
        annotations: update,
      },
      async ({ templateId, ...body }) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "PATCH",
        path: `/v1/templates/${encodeURIComponent(templateId)}`,
        body,
      })),
    );
    server.registerTool(
      "kitsos_mail_template_delete",
      {
        title: "Mail-Template löschen",
        description: "Löscht ein eigenes Mail-Template.",
        inputSchema: z.object({ templateId: id }),
        annotations: remove,
      },
      async ({ templateId }) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "DELETE",
        path: `/v1/templates/${encodeURIComponent(templateId)}`,
      })),
    );
    server.registerTool(
      "kitsos_mail_webhook_create",
      {
        title: "Mail-Webhook erstellen",
        description: "Erstellt einen Webhook und gibt dessen Secret genau einmal zurück.",
        inputSchema: z.object({
          name: z.string().min(1).max(100),
          templateId: id,
          fromAddress: email,
          toAddresses: z.array(email).min(1).max(50),
          mapping: z.record(z.string(), z.string().max(500)),
        }),
        annotations: create,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "POST",
        path: "/v1/webhooks",
        body: args,
      })),
    );
    server.registerTool(
      "kitsos_mail_webhook_update",
      {
        title: "Mail-Webhook ändern",
        description: "Ändert einen eigenen Mail-Webhook.",
        inputSchema: z.object({
          webhookId: id,
          templateId: id.optional(),
          fromAddress: email.optional(),
          toAddresses: z.array(email).min(1).max(50).optional(),
          mapping: z.record(z.string(), z.string().max(500)).optional(),
        }),
        annotations: update,
      },
      async ({ webhookId, ...body }) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "PATCH",
        path: `/v1/webhooks/${encodeURIComponent(webhookId)}`,
        body,
      })),
    );
    server.registerTool(
      "kitsos_mail_webhook_delete",
      {
        title: "Mail-Webhook löschen",
        description: "Löscht einen eigenen Mail-Webhook.",
        inputSchema: z.object({ webhookId: id }),
        annotations: remove,
      },
      async ({ webhookId }) => toolResponse(await callUpstream(context, {
        service: "MAIL",
        method: "DELETE",
        path: `/v1/webhooks/${encodeURIComponent(webhookId)}`,
      })),
    );
  }

  if (has(context, "hme:read")) {
    server.registerTool(
      "kitsos_hme_aliases_list",
      {
        title: "Hide-My-Email-Aliase anzeigen",
        description: "Listet eigene Weiterleitungsaliase.",
        inputSchema: z.object(pagination),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "HIDE_MY_EMAIL",
        path: "/v1/aliases",
        query: args,
      })),
    );
  }

  if (has(context, "hme:manage")) {
    server.registerTool(
      "kitsos_hme_alias_create",
      {
        title: "Hide-My-Email-Alias erstellen",
        description: "Erstellt einen Alias zu einer bereits verifizierten Zieladresse.",
        inputSchema: z.object({
          forwardTo: email,
          label: z.string().max(200).optional(),
        }),
        annotations: create,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "HIDE_MY_EMAIL",
        method: "POST",
        path: "/v1/aliases",
        body: args,
      })),
    );
    server.registerTool(
      "kitsos_hme_alias_update",
      {
        title: "Hide-My-Email-Alias ändern",
        description: "Ändert Status, Label oder Zieladresse eines eigenen Alias.",
        inputSchema: z.object({
          aliasId: id,
          status: z.enum(["active", "disabled"]).optional(),
          label: z.string().max(200).optional(),
          forwardTo: email.optional(),
        }),
        annotations: update,
      },
      async ({ aliasId, ...body }) => toolResponse(await callUpstream(context, {
        service: "HIDE_MY_EMAIL",
        method: "PATCH",
        path: `/v1/aliases/${encodeURIComponent(aliasId)}`,
        body,
      })),
    );
    server.registerTool(
      "kitsos_hme_alias_delete",
      {
        title: "Hide-My-Email-Alias löschen",
        description: "Löscht einen eigenen Weiterleitungsalias.",
        inputSchema: z.object({ aliasId: id }),
        annotations: remove,
      },
      async ({ aliasId }) => toolResponse(await callUpstream(context, {
        service: "HIDE_MY_EMAIL",
        method: "DELETE",
        path: `/v1/aliases/${encodeURIComponent(aliasId)}`,
      })),
    );
  }

  if (has(context, "utility:crypt")) {
    server.registerTool(
      "kitsos_utility_password_generate",
      {
        title: "Sicheres Passwort erzeugen",
        description: "Erzeugt ein kryptografisch zufälliges Passwort.",
        inputSchema: z.object({
          length: z.number().int().min(1).max(16_384).default(20),
          symbols: z.boolean().default(false),
          strong: z.boolean().default(false),
        }),
        annotations: readOnly,
      },
      async ({ length, symbols, strong }) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/crypt/pass",
        query: { len: length, symbols: symbols || undefined, strong: strong || undefined },
      })),
    );
    server.registerTool(
      "kitsos_utility_token_generate",
      {
        title: "Zufallstoken erzeugen",
        description: "Erzeugt kryptografisch zufällige Bytes als Hex oder URL-safe Base64.",
        inputSchema: z.object({
          bytes: z.number().int().min(1).max(65_536).default(32),
          encoding: z.enum(["hex", "base64"]).default("hex"),
        }),
        annotations: readOnly,
      },
      async ({ bytes, encoding }) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/crypt/token",
        query: { len: bytes, enc: encoding },
      })),
    );
    server.registerTool(
      "kitsos_utility_number_generate",
      {
        title: "Zufallszahl erzeugen",
        description: "Erzeugt eine gleichverteilte ganze Zufallszahl im inklusiven Bereich.",
        inputSchema: z.object({
          min: z.number().int().default(0),
          max: z.number().int().default(100),
        }),
        annotations: readOnly,
      },
      async (args) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/crypt/num",
        query: args,
      })),
    );
    server.registerTool(
      "kitsos_utility_hash",
      {
        title: "Text hashen",
        description: "Berechnet einen SHA-Hash eines Textes.",
        inputSchema: z.object({
          text: z.string().max(16_384),
          algorithm: z.enum(["SHA-1", "SHA-256", "SHA-384", "SHA-512"]).default("SHA-256"),
        }),
        annotations: readOnly,
      },
      async ({ text, algorithm }) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/crypt/hash",
        query: { text, algo: algorithm },
      })),
    );
  }

  if (has(context, "utility:time")) {
    server.registerTool(
      "kitsos_utility_time_get",
      {
        title: "Aktuelle Zeit abrufen",
        description: "Gibt die aktuelle Zeit in einer IANA-Zeitzone zurück.",
        inputSchema: z.object({
          timezone: z.string().max(100).optional(),
          format: z.string().max(200).optional(),
        }),
        annotations: readOnly,
      },
      async ({ timezone, format }) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/time",
        query: { tz: timezone, format },
      })),
    );
    server.registerTool(
      "kitsos_utility_timezones_list",
      {
        title: "Zeitzonen anzeigen",
        description: "Listet unterstützte IANA-Zeitzonen.",
        inputSchema: z.object({}),
        annotations: readOnly,
      },
      async () => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/time/zones",
      })),
    );
  }

  if (has(context, "utility:geo")) {
    server.registerTool(
      "kitsos_utility_geo_get",
      {
        title: "Verbindungsstandort abrufen",
        description: "Gibt Cloudflare-Standort- und Netzwerkmetadaten der MCP-Verbindung zurück.",
        inputSchema: z.object({}),
        annotations: readOnly,
      },
      async () => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: "/v1/geo",
      })),
    );
  }

  if (has(context, "utility:dns")) {
    server.registerTool(
      "kitsos_utility_dns_lookup",
      {
        title: "DNS-Eintrag abfragen",
        description: "Fragt einen öffentlichen DNS-Eintrag über einen unterstützten Resolver ab.",
        inputSchema: z.object({
          name: z.string().min(1).max(253),
          type: z.enum(["A", "AAAA", "CNAME", "TXT", "NS", "SOA"]).default("A"),
          provider: z.enum(["default", "google", "cloudflare", "quad9"]).default("default"),
          cache: z.boolean().default(true),
        }),
        annotations: {
          ...readOnly,
          openWorldHint: true,
        },
      },
      async ({ name, type, provider, cache }) => toolResponse(await callUpstream(context, {
        service: "UTILITY",
        path: provider === "default" ? "/v1/dns" : `/v1/dns/${provider}`,
        query: { name, type, cache },
      })),
    );
  }

  return server;
}
