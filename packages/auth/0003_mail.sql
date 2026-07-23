CREATE TABLE mail_templates (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  url TEXT NOT NULL,             -- HTML fetched from here at send time, cached 1h in KV
  variables TEXT NOT NULL,       -- JSON array of expected variable names
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE mail_webhooks (
  id TEXT PRIMARY KEY,           -- also the URL slug: /webhook/{id}
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  template_id TEXT NOT NULL REFERENCES mail_templates(id),
  from_address TEXT NOT NULL,
  to_addresses TEXT NOT NULL,    -- JSON array
  mapping TEXT NOT NULL,         -- JSON: {templateVar: "dot.path.in.payload"}
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE mail_user_limits (
  user_id TEXT PRIMARY KEY,
  max_webhooks INTEGER NOT NULL DEFAULT 10,
  max_emails_per_day INTEGER NOT NULL DEFAULT 20
);

CREATE INDEX idx_mail_templates_user ON mail_templates(user_id);
CREATE INDEX idx_mail_webhooks_user ON mail_webhooks(user_id);
