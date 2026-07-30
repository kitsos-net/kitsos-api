-- Multi-app API keys and the shared scope metadata used by the MCP consent UI.

ALTER TABLE api_key_apps ADD COLUMN scopes TEXT NOT NULL DEFAULT '[]';

-- Every current key is a single-app key. Preserve it as the first canonical
-- api_key_apps grant before switching application code to the join table.
INSERT OR IGNORE INTO api_key_apps (api_key_id, app_id, scopes)
SELECT id, app_id, scopes
FROM api_keys;

-- Older installations may already contain api_key_apps rows. Limit their
-- scopes to scopes that actually belong to the associated app.
UPDATE api_key_apps
SET scopes = COALESCE((
  SELECT json_group_array(j.value)
  FROM api_keys k, json_each(k.scopes) j
  JOIN app_scopes s
    ON s.app_id = api_key_apps.app_id
   AND s.scope = j.value
  WHERE k.id = api_key_apps.api_key_id
), '[]');

ALTER TABLE app_scopes ADD COLUMN display_name TEXT;
ALTER TABLE app_scopes ADD COLUMN access_type TEXT NOT NULL DEFAULT 'write';
ALTER TABLE app_scopes ADD COLUMN mcp_exposable INTEGER NOT NULL DEFAULT 0;

-- Make the product scope catalog reproducible. Some of these rows used to be
-- provisioned manually through keys-api.
INSERT OR IGNORE INTO app_scopes (app_id, scope, description) VALUES
  ('mail', 'mail:send', 'Send email from a verified sender address'),
  ('mail', 'mail:manage', 'Create, update and delete mail templates and webhooks'),
  ('hide-my-email', 'hme:manage', 'Create, update and delete forwarding aliases'),
  ('hide-my-email', 'hme:receive', 'Use a verified address as an alias destination');

INSERT OR IGNORE INTO app_scopes (app_id, scope, description) VALUES
  ('mail', 'mail:read', 'Read mail templates and webhooks'),
  ('hide-my-email', 'hme:read', 'Read forwarding aliases'),
  ('verify', 'verify:read', 'Read resource verifications'),
  ('verify', 'verify:manage', 'Start and complete resource verifications'),
  ('keys-api', 'account:read', 'Read the current account, limits and limit requests'),
  ('keys-api', 'account:limits:request', 'Request a product limit increase');

UPDATE app_scopes
SET
  display_name = CASE scope
    WHEN 'mail:read' THEN 'Mail data read'
    WHEN 'mail:send' THEN 'Send email'
    WHEN 'mail:manage' THEN 'Manage mail'
    WHEN 'hme:read' THEN 'Aliases read'
    WHEN 'hme:manage' THEN 'Manage aliases'
    WHEN 'verify:read' THEN 'Verifications read'
    WHEN 'verify:manage' THEN 'Manage verifications'
    WHEN 'account:read' THEN 'Account data read'
    WHEN 'account:limits:request' THEN 'Request limit increases'
    WHEN 'utility:crypt' THEN 'Cryptographic utilities'
    WHEN 'utility:time' THEN 'Time utilities'
    WHEN 'utility:geo' THEN 'Connection geolocation'
    WHEN 'utility:dns' THEN 'DNS lookups'
    ELSE COALESCE(display_name, scope)
  END,
  access_type = CASE
    WHEN scope IN (
      'mail:read',
      'hme:read',
      'verify:read',
      'account:read',
      'utility:crypt',
      'utility:time',
      'utility:geo',
      'utility:dns'
    ) THEN 'read'
    WHEN scope IN ('mail:send') THEN 'send'
    ELSE 'write'
  END,
  mcp_exposable = CASE
    WHEN scope IN (
      'mail:read',
      'mail:send',
      'mail:manage',
      'hme:read',
      'hme:manage',
      'verify:read',
      'verify:manage',
      'account:read',
      'account:limits:request',
      'utility:crypt',
      'utility:time',
      'utility:geo',
      'utility:dns'
    ) THEN 1
    ELSE 0
  END;

-- Keep authentication provenance queryable without weakening the existing
-- api_key_id foreign-key relationship.
ALTER TABLE audit_log ADD COLUMN auth_method TEXT;
ALTER TABLE audit_log ADD COLUMN credential_id TEXT;
ALTER TABLE audit_log ADD COLUMN client_id TEXT;

CREATE INDEX IF NOT EXISTS idx_api_key_apps_app
  ON api_key_apps(app_id, api_key_id);
