const STYLE = String.raw`
:root{color-scheme:light dark;--primary:#0768bb;--primary-hover:#055a9f;--primary-soft:#e7f2fc;--bg:#f7f9fc;--surface:#fff;--raised:#fff;--text:#111827;--muted:#52606d;--border:#dce5ee;--success:#12805c;--warning:#a85e00;--danger:#c52b3a;--focus:#9ed5ff;--shadow:0 8px 24px rgb(15 35 55 / 10%);--control:10px;--card:12px;--font:"Kitsos Default",Arial,Helvetica,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:16px/1.5 var(--font)}
button,input,textarea{font:inherit}
button,a,input,textarea{outline:none}
button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible{box-shadow:0 0 0 3px var(--focus)}
.shell{width:min(760px,calc(100% - 32px));margin:0 auto;padding:32px 0 64px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.brand{display:flex;align-items:center;gap:12px;color:var(--text);text-decoration:none;font-weight:700}
.logo{width:40px;height:40px;object-fit:contain}
.logo-dark{display:none}
.security{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:14px}
.security svg{width:18px;height:18px;stroke:var(--success)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--card);box-shadow:var(--shadow);overflow:hidden}
.hero{padding:28px 28px 24px;border-bottom:1px solid var(--border)}
.eyebrow{margin:0 0 8px;color:var(--primary);font-size:14px;font-weight:700;letter-spacing:.02em}
h1{font-size:28px;line-height:36px;margin:0 0 8px}
h2{font-size:18px;line-height:26px;margin:0}
p{margin:0}.muted{color:var(--muted)}
.client{display:flex;align-items:center;gap:12px;margin-top:20px;padding:12px 14px;background:var(--primary-soft);border-radius:var(--control)}
.client-icon{display:grid;place-items:center;flex:0 0 40px;width:40px;height:40px;border-radius:10px;background:var(--surface);border:1px solid var(--border);font-weight:700;color:var(--primary)}
.client-name{font-weight:700}.client-id{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.body{padding:24px 28px 28px}
.notice{display:flex;gap:10px;padding:12px 14px;border:1px solid var(--border);border-radius:var(--control);background:var(--raised);color:var(--muted);font-size:14px;margin-bottom:20px}
.notice svg{flex:0 0 20px;width:20px;height:20px;stroke:var(--primary)}
.group{margin-top:22px}.group:first-child{margin-top:0}
.group-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.group-name{font-size:16px;font-weight:700}.group-count{font-size:13px;color:var(--muted)}
.scope{display:grid;grid-template-columns:24px 1fr auto;gap:12px;align-items:start;padding:14px 0;border-top:1px solid var(--border);cursor:pointer}
.scope:first-of-type{border-top:0}
.scope input{appearance:none;width:20px;height:20px;margin:2px 0 0;border:1.5px solid var(--border);border-radius:6px;background:var(--surface);cursor:pointer}
.scope input:checked{background:var(--primary);border-color:var(--primary);box-shadow:inset 0 0 0 4px var(--primary)}
.scope input:checked:after{content:"";display:block;width:9px;height:5px;margin:5px 0 0 4px;border-left:2px solid white;border-bottom:2px solid white;transform:rotate(-45deg)}
.scope-title{font-weight:600}.scope-desc{display:block;color:var(--muted);font-size:14px;line-height:20px;margin-top:2px}
.badge{border-radius:999px;padding:3px 8px;font-size:12px;font-weight:700;background:var(--primary-soft);color:var(--primary)}
.badge.write{background:color-mix(in srgb,var(--warning) 14%,transparent);color:var(--warning)}
.badge.send{background:color-mix(in srgb,var(--success) 14%,transparent);color:var(--success)}
.actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:10px;margin-top:26px;padding-top:20px;border-top:1px solid var(--border)}
.button{min-height:44px;padding:10px 16px;border-radius:var(--control);border:1px solid transparent;font-weight:700;cursor:pointer;transition:background 180ms ease-out,border 180ms ease-out}
.button:disabled{opacity:.55;cursor:not-allowed}.primary{background:var(--primary);color:white}.primary:hover:not(:disabled){background:var(--primary-hover)}
.secondary{background:var(--surface);border-color:var(--border);color:var(--text)}.secondary:hover:not(:disabled){background:var(--raised)}
.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 35%,var(--border))}
.status{display:none;margin-bottom:16px;padding:12px 14px;border-radius:var(--control);border:1px solid color-mix(in srgb,var(--danger) 30%,var(--border));color:var(--danger);background:color-mix(in srgb,var(--danger) 8%,var(--surface))}
.status.show{display:block}.loading{padding:44px 28px;text-align:center;color:var(--muted)}
.spinner{width:28px;height:28px;margin:0 auto 12px;border:3px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite}
.hidden{display:none!important}
#sign-in{display:grid;place-items:center;min-height:360px}
.connection{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center;padding:16px 0;border-top:1px solid var(--border)}
.connection:first-child{border-top:0}.connection-title{font-weight:700}.connection-meta{color:var(--muted);font-size:14px;margin-top:2px}
.connection-description{margin-top:8px;color:var(--text);white-space:pre-wrap;overflow-wrap:anywhere}
.connection-buttons{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}
.connection-editor{grid-column:1/-1;padding:16px;border:1px solid var(--border);border-radius:var(--control);background:var(--raised)}
.field-label{display:block;font-weight:700;margin:20px 0 6px}.field-label:first-child{margin-top:0}
.field-help{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:13px;margin-top:5px}
.textarea{display:block;width:100%;min-height:92px;resize:vertical;padding:10px 12px;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:var(--control)}
.editor-scope{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-top:1px solid var(--border)}
.editor-scope:first-of-type{border-top:0}.editor-scope input{margin-top:5px}
.editor-scope span span{display:block;color:var(--muted);font-size:13px}
.editor-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
.empty{text-align:center;padding:36px 12px;color:var(--muted)}
.footer{text-align:center;color:var(--muted);font-size:13px;margin-top:18px}.footer a{color:var(--primary)}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:560px){.shell{width:min(100% - 20px,760px);padding-top:16px}.hero,.body{padding:20px}.security span{display:none}.actions{flex-direction:column-reverse}.button{width:100%}.scope{grid-template-columns:24px 1fr}.badge{grid-column:2;justify-self:start}.connection{grid-template-columns:1fr}.connection .button{width:auto;justify-self:start}.connection-buttons,.editor-actions{justify-content:flex-start}}
@media(prefers-color-scheme:dark){:root{--primary:#03a9f4;--primary-hover:#38bdf8;--primary-soft:#06314b;--bg:#09131d;--surface:#101e2a;--raised:#162838;--text:#f3f7fb;--muted:#a8b8c8;--border:#284052;--success:#38d39f;--warning:#ffbe5c;--danger:#ff7581;--focus:#0e77a7;--shadow:none}.logo-light{display:none}.logo-dark{display:block}.primary{color:#07131d}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
`;

const CLIENT_SCRIPT = `
const page = document.body.dataset.page;
const csrf = document.body.dataset.csrf || "";
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\\\"":"&quot;","'":"&#039;"}[c]));
const CDN_TIMEOUT_MS = 1500;
const CDN_FONT_PATH = "/fonts/kitsos-default/kitsos-default-regular.woff2";
const objectUrls = [];
let loaded = false;
let connectionsState = null;
function cdnHostOrder() {
  const hosts = ["cdn2.kitsos.net", "cdn3.kitsos.net"];
  const random = crypto.getRandomValues(new Uint32Array(1))[0];
  return ["cdn.kitsos.net", ...(random % 2 === 0 ? hosts : hosts.reverse())];
}
async function fetchCdnAsset(path) {
  for (const host of cdnHostOrder()) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CDN_TIMEOUT_MS);
    try {
      const response = await fetch("https://" + host + path, {
        cache: "force-cache",
        mode: "cors",
        signal: controller.signal,
      });
      if (!response.ok) continue;
      return await response.blob();
    } catch {
      // Try the next CDN host.
    } finally {
      clearTimeout(timeout);
    }
  }
  return null;
}
async function loadBrandFont() {
  if (!("FontFace" in window) || !document.fonts) return;
  const blob = await fetchCdnAsset(CDN_FONT_PATH);
  if (!blob) return;
  try {
    const face = new FontFace("Kitsos Default", await blob.arrayBuffer(), {
      style: "normal",
      weight: "400",
    });
    await face.load();
    document.fonts.add(face);
  } catch {
    // Keep the system font stack if the downloaded file is invalid.
  }
}
async function loadVisualAsset(node) {
  const path = node.dataset.cdnPath;
  if (!path) return;
  const blob = await fetchCdnAsset(path);
  if (!blob) return;
  const objectUrl = URL.createObjectURL(blob);
  objectUrls.push(objectUrl);
  if (node instanceof HTMLImageElement) node.src = objectUrl;
  if (node instanceof HTMLLinkElement) node.href = objectUrl;
}
function loadDesignAssets() {
  void loadBrandFont();
  document.querySelectorAll("[data-cdn-path]").forEach((node) => {
    void loadVisualAsset(node);
  });
}
loadDesignAssets();
window.addEventListener("pagehide", () => {
  objectUrls.forEach((url) => URL.revokeObjectURL(url));
});
function showError(message) {
  const node = $("#status");
  node.textContent = message || "Die Anfrage konnte nicht verarbeitet werden.";
  node.classList.add("show");
}
async function api(path, options = {}) {
  const token = await Clerk.session?.getToken();
  if (!token) throw new Error("Bitte melde dich zuerst an.");
  const response = await fetch(path, {
    ...options,
    headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json", ...(options.headers || {})},
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.message || payload.error || "Anfrage fehlgeschlagen.");
  return payload;
}
function showSignedIn() {
  $("#auth-panel")?.classList.add("hidden");
  $("#content-panel")?.classList.remove("hidden");
}
function renderScopes(data) {
  $("#client-name").textContent = data.client.name;
  $("#client-id").textContent = data.client.id;
  $("#client-letter").textContent = data.client.name.slice(0,1).toUpperCase();
  const root = $("#scope-groups");
  const products = new Map();
  for (const scope of data.scopes) {
    if (!products.has(scope.product)) products.set(scope.product, []);
    products.get(scope.product).push(scope);
  }
  root.innerHTML = [...products].map(([product, scopes]) => \`
    <section class="group">
      <div class="group-head"><h2 class="group-name">\${escapeHtml(product)}</h2><span class="group-count">\${scopes.length} Berechtigung\${scopes.length === 1 ? "" : "en"}</span></div>
      \${scopes.map(scope => \`
        <label class="scope">
          <input type="checkbox" name="scope" value="\${escapeHtml(scope.id)}" \${scope.preselected ? "checked" : ""}>
          <span><span class="scope-title">\${escapeHtml(scope.title)}</span><span class="scope-desc">\${escapeHtml(scope.description)}</span></span>
          <span class="badge \${escapeHtml(scope.accessType)}">\${scope.accessType === "read" ? "Lesen" : scope.accessType === "send" ? "Senden" : "Ändern"}</span>
        </label>\`).join("")}
    </section>\`).join("");
  $("#approve").disabled = false;
}
async function loadConsent() {
  if (loaded) return;
  loaded = true;
  showSignedIn();
  try {
    renderScopes(await api("/consent/context"));
  } catch (error) {
    loaded = false;
    showError(error.message);
  }
}
async function approve() {
  const button = $("#approve");
  button.disabled = true;
  $("#deny").disabled = true;
  try {
    const scopes = [...document.querySelectorAll('input[name="scope"]:checked')].map(input => input.value);
    const description = $("#consent-description")?.value || "";
    const result = await api("/consent/approve", {
      method: "POST",
      body: JSON.stringify({csrf, scopes, description}),
    });
    window.location.assign(result.redirectTo);
  } catch (error) {
    showError(error.message);
    button.disabled = false;
    $("#deny").disabled = false;
  }
}
async function deny() {
  $("#deny").disabled = true;
  try {
    const result = await api("/consent/deny", {
      method: "POST",
      body: JSON.stringify({csrf}),
    });
    window.location.assign(result.redirectTo);
  } catch (error) {
    showError(error.message);
    $("#deny").disabled = false;
  }
}
function renderConnections(data) {
  connectionsState = data;
  const root = $("#connections");
  const limit = $("#connection-limit");
  if (limit && data.limits) {
    limit.textContent = data.connections.length + " von " + data.limits.connectedApps + " Verbindungen";
  }
  if (!data.connections.length) {
    root.innerHTML = '<div class="empty">Aktuell ist keine App mit deinem Kitsos-Konto verbunden.</div>';
    return;
  }
  root.innerHTML = data.connections.map(item => \`
    <article class="connection">
      <div>
        <div class="connection-title">\${escapeHtml(item.clientName || item.clientId)}</div>
        <div class="connection-meta">\${item.scopeCount} Berechtigungen · verbunden am \${new Date(item.createdAt * 1000).toLocaleDateString("de-DE")}</div>
        \${item.description ? \`<p class="connection-description">\${escapeHtml(item.description)}</p>\` : ""}
      </div>
      <div class="connection-buttons">
        <button class="button secondary" type="button" data-edit="\${escapeHtml(item.id)}">Bearbeiten</button>
        <button class="button secondary danger" type="button" data-revoke="\${escapeHtml(item.id)}">Zugriff entfernen</button>
      </div>
      <div class="connection-editor hidden" data-editor="\${escapeHtml(item.id)}">
        <label class="field-label" for="description-\${escapeHtml(item.id)}">Eigene Beschreibung</label>
        <textarea id="description-\${escapeHtml(item.id)}" class="textarea" maxlength="500" data-description placeholder="Wofür nutzt du diese Verbindung?">\${escapeHtml(item.description || "")}</textarea>
        <div class="field-help"><span>Nur für dich sichtbar</span><span data-description-count>\${[...(item.description || "")].length}/500</span></div>
        <span class="field-label">Berechtigungen</span>
        <div>
          \${item.availableScopes.map(scope => \`
            <label class="editor-scope">
              <input type="checkbox" data-connection-scope value="\${escapeHtml(scope.id)}" \${item.scopes.includes(scope.id) ? "checked" : ""}>
              <span><strong>\${escapeHtml(scope.title)}</strong><span>\${escapeHtml(scope.description)}</span></span>
            </label>\`).join("")}
        </div>
        <div class="editor-actions">
          <button class="button secondary" type="button" data-cancel-edit>Abbrechen</button>
          <button class="button primary" type="button" data-save="\${escapeHtml(item.id)}">Änderungen speichern</button>
        </div>
      </div>
    </article>\`).join("");
  root.querySelectorAll("[data-edit]").forEach(button => button.addEventListener("click", () => {
    root.querySelector('[data-editor="' + CSS.escape(button.dataset.edit) + '"]')?.classList.remove("hidden");
  }));
  root.querySelectorAll("[data-cancel-edit]").forEach(button => button.addEventListener("click", () => {
    button.closest(".connection-editor").classList.add("hidden");
  }));
  root.querySelectorAll("[data-description]").forEach(textarea => textarea.addEventListener("input", () => {
    textarea.closest(".connection-editor").querySelector("[data-description-count]").textContent = [...textarea.value].length + "/500";
  }));
  root.querySelectorAll("[data-save]").forEach(button => button.addEventListener("click", async () => {
    const editor = button.closest(".connection-editor");
    const scopes = [...editor.querySelectorAll("[data-connection-scope]:checked")].map(input => input.value);
    if (!scopes.length) {
      showError("Wähle mindestens eine Berechtigung aus.");
      return;
    }
    button.disabled = true;
    try {
      const result = await api("/connections/update", {
        method:"POST",
        body:JSON.stringify({
          grantId:button.dataset.save,
          description:editor.querySelector("[data-description]").value,
          scopes,
        }),
      });
      const item = connectionsState.connections.find(connection => connection.id === button.dataset.save);
      item.description = result.description || "";
      item.scopes = result.scopes;
      item.scopeCount = result.scopeCount;
      renderConnections(connectionsState);
    } catch (error) {
      showError(error.message);
      button.disabled = false;
    }
  }));
  root.querySelectorAll("[data-revoke]").forEach(button => button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await api("/connections/revoke", {method:"POST", body:JSON.stringify({grantId:button.dataset.revoke})});
      connectionsState.connections = connectionsState.connections.filter(item => item.id !== button.dataset.revoke);
      renderConnections(connectionsState);
    } catch (error) {
      showError(error.message);
      button.disabled = false;
    }
  }));
}
async function loadConnections() {
  if (loaded) return;
  loaded = true;
  showSignedIn();
  try {
    renderConnections(await api("/connections/context"));
  } catch (error) {
    loaded = false;
    showError(error.message);
  }
}
window.addEventListener("load", async () => {
  try {
    await Clerk.load({ui:{ClerkUI:window.__internal_ClerkUICtor}});
    const render = () => {
      if (Clerk.isSignedIn) {
        page === "consent" ? loadConsent() : loadConnections();
      } else {
        loaded = false;
        $("#content-panel")?.classList.add("hidden");
        $("#auth-panel")?.classList.remove("hidden");
        const node = $("#sign-in");
        if (node && !node.dataset.mounted) {
          node.dataset.mounted = "true";
          Clerk.mountSignIn(node, {routing:"hash"});
        }
      }
    };
    Clerk.addListener(render);
    render();
  } catch (error) {
    showError("Clerk konnte nicht geladen werden. Bitte lade die Seite neu.");
  }
  $("#approve")?.addEventListener("click", approve);
  $("#deny")?.addEventListener("click", deny);
});
`;

function safeJson(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function clerkFrontendDomain(publishableKey: string): string {
  try {
    const encoded = publishableKey.split("_")[2] ?? "";
    return atob(encoded).replace(/\$$/, "");
  } catch {
    return "clerk.kitsos.net";
  }
}

function shell(options: {
  title: string;
  page: "consent" | "connections";
  csrf?: string;
  publishableKey: string;
  nonce: string;
  content: string;
}): string {
  const clerkDomain = clerkFrontendDomain(options.publishableKey);
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>${options.title}</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E" data-cdn-path="/logos/fav/favicon.svg">
  <style nonce="${options.nonce}">${STYLE}</style>
  <script defer crossorigin="anonymous" src="https://${clerkDomain}/npm/@clerk/ui@1/dist/ui.browser.js"></script>
  <script defer crossorigin="anonymous" data-clerk-publishable-key="${options.publishableKey}" src="https://${clerkDomain}/npm/@clerk/clerk-js@6/dist/clerk.browser.js"></script>
</head>
<body data-page="${options.page}" data-csrf=${safeJson(options.csrf ?? "")}>
  <main class="shell">
    <header class="topbar">
      <a class="brand" href="https://kitsos.net">
        <picture>
          <img class="logo logo-light" src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" data-cdn-path="/logos/k.png" alt="Kitsos">
          <img class="logo logo-dark" src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" data-cdn-path="/logos/k-dark.png" alt="Kitsos">
        </picture>
        <span>Kitsos</span>
      </a>
      <div class="security">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
        <span>Sichere Verbindung</span>
      </div>
    </header>
    <div id="status" class="status" role="alert"></div>
    ${options.content}
    <p class="footer">Du kannst den Zugriff später unter <a href="/connections">Verbundene Apps</a> widerrufen.</p>
  </main>
  <script nonce="${options.nonce}">${CLIENT_SCRIPT}</script>
</body>
</html>`;
}

const signInPanel = `
<section id="auth-panel" class="card">
  <div class="hero"><p class="eyebrow">Kitsos-Anmeldung</p><h1>Mit Kitsos anmelden</h1><p class="muted">Melde dich an, um die Verbindung sicher zu autorisieren.</p></div>
  <div id="sign-in"></div>
</section>`;

export function consentPage(publishableKey: string, nonce: string, csrf: string): string {
  return shell({
    title: "App autorisieren · Kitsos",
    page: "consent",
    csrf,
    publishableKey,
    nonce,
    content: `${signInPanel}
<section id="content-panel" class="card hidden">
  <div class="hero">
    <p class="eyebrow">App autorisieren</p>
    <h1>Zugriff auf Kitsos erlauben?</h1>
    <p class="muted">Wähle genau aus, was diese App in deinem Namen tun darf.</p>
    <div class="client">
      <span id="client-letter" class="client-icon" aria-hidden="true">A</span>
      <span><span id="client-name" class="client-name">App</span><span id="client-id" class="client-id"></span></span>
    </div>
  </div>
  <div class="body">
    <div class="notice">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>
      <span>Leserechte sind vorausgewählt. Rechte zum Ändern oder Senden musst du bewusst aktivieren. Verwalten umfasst jeweils auch Lesen.</span>
    </div>
    <div id="scope-groups"><div class="loading"><div class="spinner"></div>Berechtigungen werden geladen …</div></div>
    <label class="field-label" for="consent-description">Eigene Beschreibung <span class="muted">(optional)</span></label>
    <textarea id="consent-description" class="textarea" maxlength="500" placeholder="Wofür möchtest du diese Verbindung verwenden?"></textarea>
    <div class="field-help"><span>Nur in deinem Kitsos-Konto sichtbar</span><span>Maximal 500 Zeichen</span></div>
    <div class="actions">
      <button id="deny" class="button secondary" type="button">Abbrechen</button>
      <button id="approve" class="button primary" type="button" disabled>Auswahl erlauben</button>
    </div>
  </div>
</section>`,
  });
}

export function connectionsPage(publishableKey: string, nonce: string): string {
  return shell({
    title: "Verbundene Apps · Kitsos",
    page: "connections",
    publishableKey,
    nonce,
    content: `${signInPanel}
<section id="content-panel" class="card hidden">
  <div class="hero"><p class="eyebrow">Sicherheit</p><h1>Verbundene Apps</h1><p class="muted">Passe Beschreibungen und Berechtigungen an oder widerrufe den Zugriff vollständig.</p><p id="connection-limit" class="connection-meta"></p></div>
  <div class="body"><div id="connections"><div class="loading"><div class="spinner"></div>Verbindungen werden geladen …</div></div></div>
</section>`,
  });
}

export function securityHeaders(nonce: string, publishableKey: string): Headers {
  const clerkDomain = clerkFrontendDomain(publishableKey);
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": [
      "default-src 'none'",
      `script-src 'nonce-${nonce}' https://${clerkDomain}`,
      `style-src 'nonce-${nonce}' 'unsafe-inline'`,
      `connect-src 'self' https://cdn.kitsos.net https://cdn2.kitsos.net https://cdn3.kitsos.net https://${clerkDomain} https://api.clerk.com`,
      `img-src 'self' data: blob: https://cdn.kitsos.net https://cdn2.kitsos.net https://cdn3.kitsos.net https://${clerkDomain}`,
      `font-src https://cdn.kitsos.net https://cdn2.kitsos.net https://cdn3.kitsos.net https://${clerkDomain}`,
      `frame-src https://${clerkDomain}`,
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  });
}
