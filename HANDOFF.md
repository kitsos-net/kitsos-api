# Kitsos API Platform — Handoff

Stand: 28. Juli 2026. Dieses Dokument fasst alles aus dem Chat zusammen, in dem
`kitsos-net/kitsos-api` von null aufgebaut wurde, damit ein neuer Chat nahtlos
weitermachen kann.

## Repo & Infrastruktur

- **Repo:** `github.com/kitsos-net/kitsos-api` (privat)
- **D1 Database:** `kitsos-api` (`c5ccab68-5f60-4b28-8ce9-20c57b8622ea`) — volles
  Schema in `packages/auth/0001_init.sql` + Migrationen bis
  `0007_product_limits.sql`
- **KV Namespaces:**
  - `kitsos-api-auth-cache` (`86fb5bad46c6458d91cbb322b7178ccf`) — Auth-Result-Cache, 60s TTL
  - `kitsos-api-usage-counters` (`4823ab0d3fd6452e8437631a3717f2b5`) — Rate-/Usage-Limits
- **Domain-Konvention:** eine Cloudflare Custom Domain pro Worker
  (`keys.api.kitsos.net`, `verify.api.kitsos.net`, `mail.api.kitsos.net`,
  `hme.api.kitsos.net`), alle öffentlichen API-Endpunkte unter `/v1`
- **Logging:** Axiom (Dataset `kitsos-api-logs`), gewählt statt Betterstack
  wegen Free Tier (500GB/30 Tage vs. 3GB/3 Tage). Instrumentierung via
  `@kitsos/telemetry` (OpenTelemetry, `@microlabs/otel-cf-workers`), jeder
  Worker wrappt seinen Hono-Export mit `withTelemetry()`.
- **Admin/Debug-UIs:** `apidev.kitsos.net` (Cloudflare Pages Projekt
  `kitsos-keys-admin-dev`) — `/` (Keys Admin), `/verify.html`, `/hme.html`.
  Explizit **nicht production-ready**, nur zum Testen.

## Auth-Architektur

- **Clerk** ist der zentrale IdP (`clerk.kitsos.net` API-Domain,
  `accounts.kitsos.net` Login, `myaccount.kitsos.net` Account Management).
  Auth0 ist vollständig abgelöst, nichts läuft mehr darauf.
- **`@kitsos/auth`** (packages/auth) — shared Package, kein eigener Worker:
  - Clerk-Session-JWT-Validierung (`verifyClerkSession`)
  - `kitsos_...` API-Key-Validierung (SHA-256 Hash, 60s KV-Cache)
  - Scope-Check als Intersection von Credential-Scopes ∩ Policy-Scopes
    (gilt für API-Keys und Clerk-Sessions)
  - Resource Grants / ReBAC (`checkResourceGrant`) inkl. Grace-Period und
    Bindung an den konkreten erfolgreichen Verifikationsversuch
  - Rate-Limiting (fixed window, KV) und atomare tägliche Produktlimits in D1,
    mit erhöhbaren Overrides aus `usage_limits`
  - Audit-Log (fire-and-forget, blockiert nie den Request)
  - `authenticate()` als zentraler Einstiegspunkt für App-Worker

## Gebaute Worker

### `keys-api` (keys.api.kitsos.net)
Management-API: Users, Groups, Apps, Policies, API-Keys, Usage-Limits,
Limit-Increase-Requests, Audit-Log.
- `/admin/*` — Clerk-Session + Mitgliedschaft in Admin-Gruppe (`ADMIN_GROUP_ID`
  Secret, aktuell Gruppen-ID `admins`)
- `/me/*` — Self-Service, Scopes beim Key-Erstellen auf eigene Policy begrenzt
- `/me/limits` — effektive Limits, aktuelle Nutzung, Restbudget und hartes
  Systemmaximum
- CORS aktiviert (für die Admin-UI)
- **Bootstrap:** Dion (`user_3FfpiUcINrEWX4jLuK1fM6t8BDb`, dion@kitsos.net) ist
  bereits in der `admins`-Gruppe angelegt

### `verify` (verify.api.kitsos.net)
Resource-Ownership-Verification, Voraussetzung für alle `resource_grants`.
- DNS-TXT (via Cloudflare DoH, 30 Tage Reverify / 7 Tage Grace)
- Magic Link (90 Tage Reverify / 14 Tage Grace) — verschickt über `mail`-Worker
- Magic Link wird ausschließlich an die zu verifizierende E-Mail-Adresse
  verschickt; Token-Hash in D1, 30 Minuten Gültigkeit
- Nur Clerk-Session, kein API-Key-Pfad (bewusst, weil Verifizierung ein
  Browser/Mensch-Vorgang ist)
- `POST /resources` ist jetzt gehärtet: klare Fehlercodes statt roher 500er
  (`missing-fields`, `invalid-method`, `missing-scopes`, `app-not-found`,
  `database-error`)
- **Bug gefixt:** `mail.ts` schickte an den `mail`-Worker ursprünglich falsche
  Felder (`to` als String statt Array, `variables` statt `data`, `from`/
  `subject` fehlten komplett) — jetzt korrekt

### `mail` (mail.api.kitsos.net)
E-Mail-Versand, Brevo als Backend (verify redet NIE direkt mit Brevo, immer
über diesen Worker).
- `POST /send` — manuell oder Template-basiert, `from` muss gegrantete
  `email_address`-Resource sein
- `POST /webhook/:id` — öffentlich, per Secret-Header gated, Dot-Notation
  Payload→Template-Mapping (für z.B. Certimate-Integration gedacht)
- Templates: URL-basiert (kein D1-Storage), 1h KV-Cache
- Default-Limits: 10 Webhooks, 20 Templates und 20 Empfänger pro Tag pro User;
  manuell, Template und Webhook teilen denselben Tageszähler
- Absender-Grant und Template-Besitz werden bei Änderungen und jedem
  Webhook-Aufruf erneut geprüft

### `hide-my-email` (hme.api.kitsos.net)
Random-Alias-Generierung (`house.exclusive.15@hme.kitsos.net`).
- `POST /aliases` — `forwardTo` muss gegrantete `email_address`-Resource sein
- Separater `email()`-Handler forwarded eingehende Mail via Cloudflare Email
  Routing (`message.forward()`), rejected unbekannte/deaktivierte Aliase mit
  Bounce
- **Email Routing ist live konfiguriert:** Catch-all der `kitsos.net`-Zone
  zeigt auf diesen Worker (vorher disabled/drop) — betrifft die GANZE Zone,
  nicht nur `hme.kitsos.net`, weil Cloudflare kein Domain-Suffix-Matching kann

## Limits und Hardening

- Vollständiger Katalog in `LIMITS.md`: harte Größen-/Churn-Grenzen versus
  admin-erhöhbare Produktlimits
- Request-Bodies, URLs, Credentials, Hash-Inputs, Templates, DNS-Antworten,
  ausgehende und eingehende Mails sind größenbegrenzt
- API-Key-, Template-, Webhook-, Alias-, Resource- und Verification-Limits
  werden atomar durchgesetzt; Datenbankhistorien haben Rolling-Retention
- Cloudflare Free unterstützt nur eine Rate-Limit-Regel. Der bereitgestellte
  Token hat Worker Edit/Read und Zone Read, aber kein `Zone WAF Read/Edit`;
  deshalb wurden keine Cloudflare-Regeln gelesen oder geändert. Die
  empfohlene `/v1/`-Regel steht in `LIMITS.md`.

## OpenAPI Specs
`openapi/keys-api.yaml`, `openapi/verify.yaml`, `openapi/mail.yaml` und
`openapi/hide-my-email.yaml`.

## Secrets — Stand pro Worker

| Secret | keys-api | verify | mail | hide-my-email |
|---|---|---|---|---|
| CLERK_SECRET_KEY | ✅ | ✅ | ⛔ (nicht nötig, siehe unten) | ✅ |
| CLERK_PUBLISHABLE_KEY | ✅ | ✅ | ✅ | ✅ |
| AXIOM_TOKEN / AXIOM_DATASET | ✅ | ✅ | ✅ | ✅ |
| ADMIN_GROUP_ID | ✅ | — | — | — |
| MAIL_API_KEY | — | ✅ (Wert unklar, evtl. Platzhalter) | — | — |
| BREVO_API_KEY | — | — | ✅ | — |
| CF_EMAIL_API_TOKEN | — | — | — | ✅ |

`mail` braucht `CLERK_SECRET_KEY` nicht, weil es komplett API-Key-getrieben
läuft (kein Clerk-Session-Pfad, außer eine zukünftige WebUI kommt dazu).

## Bekannte Cloudflare-Tokens (im Chat-Verlauf sichtbar, ggf. rotieren)
- Ein Account-Token für D1/KV/Workers-Deploys wurde mehrfach verwendet
- Ein separater Token nur für Email-Routing-Verwaltung (Adressen + Rules)
- Ein GitHub PAT für Repo-Zugriff
Alle drei sind im Chat-Verlauf sichtbar gewesen — Empfehlung: rotieren, bevor
produktiv genutzt.

## Offen / nächste Schritte

1. **Magic-Link end-to-end fertig verdrahten** (Code ist jetzt korrekt, fehlt
   noch operativ):
   - Template `resource-verification` in `mail` anlegen (`POST /templates`
     mit echter HTML-URL)
   - `kitsos_...` API-Key mit Scope `mail:send` für App `mail` erstellen
     (`keys-api` `/admin/api-keys`)
   - Resource Grant für die Absenderadresse (Default `verify@kitsos.net`,
     überschreibbar via `MAIL_FROM_ADDRESS` Secret in `verify`) — läuft über
     `verify.api.kitsos.net` selbst
   - Den Key als `MAIL_API_KEY` Secret in `verify` setzen
2. **DNS-Manager Worker** (Punkt 11 der ursprünglichen Liste) — noch nicht
   angefangen
3. **Printing Worker** (Punkt 9) — noch nicht angefangen
4. Migrationen 0006/0007 und alle `/v1`-Worker gemeinsam deployen;
   anschließend die Cloudflare-Free-Regel auf `/v1/` setzen (benötigt Zone
   WAF Read/Edit).
5. **Swagger UIs zentral unter `docs.api.kitsos.net`** (Punkt 14) — OpenAPI
   Specs existieren für alle vier aktuellen Worker, UI-Hosting fehlt noch
6. **WebUIs für DNS/Printing/Mail/HME** (Punkte 15-17, 19) — nur die drei
   Dev-Debug-UIs existieren bisher, keine echten Production-UIs
7. Alte, händisch angelegte `hme.kitsos.net`-Weiterleitungsregeln (z.B.
   `test@hme.kitsos.net`) existieren parallel zu den dynamisch über `/aliases`
   erzeugten — nicht bereinigt, könnte verwirren

## Ursprüngliche Todo-Liste — Status

1. ✅ Clerk-Migration (war schon fertig, nur verifiziert)
2. ⬜ Kitsos Logos
3. ⬜ Kitsos Design System
4. ⬜ Design auf Landing anwenden
5. ⬜ DNS Landing neu
6. ⬜ Design auf Clerk Emails
7. ✅ Basic Kitsos API (`@kitsos/auth` + `keys-api`)
8. 🟡 UIs für User/Admin (nur Dev-Version, keine Production-UI)
9. ⬜ API: Printing
10. ✅ API: Ownership Verification (`verify`)
11. ⬜ API: DNS Management
12. ✅ API: Email Sending (`mail`)
13. 🟡 OpenAPI Specs (4 aktuelle Worker; künftige Worker fehlen)
14. ⬜ Zentrale Swagger UIs
15. ⬜ WebUI Printing
16. ⬜ WebUI DNS
17. ⬜ WebUI Email
18. ✅ API: Hide My Email
19. ⬜ WebUI Hide My Email
