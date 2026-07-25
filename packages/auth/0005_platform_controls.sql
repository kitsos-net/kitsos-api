-- Platform-wide keys and centrally enforced controls.

-- A key can be enabled for more than one Kitsos API. Existing single-app keys
-- are backfilled below and continue to work unchanged.
CREATE TABLE api_key_apps (
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  app_id TEXT NOT NULL REFERENCES apps(id),
  PRIMARY KEY (api_key_id, app_id)
);
INSERT OR IGNORE INTO api_key_apps (api_key_id, app_id)
SELECT id, app_id FROM api_keys;
CREATE INDEX idx_api_key_apps_app ON api_key_apps(app_id);

-- Optional allow-list for resources managed through a key. If a key has at
-- least one grant for a resource type, access to that type is restricted to
-- the granted resource IDs (for example individual mail template IDs).
CREATE TABLE api_key_resource_grants (
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (api_key_id, resource_type, resource_id)
);

-- Defaults apply to every user; user rows in usage_limits override them.
CREATE TABLE usage_limit_defaults (
  app_id TEXT NOT NULL REFERENCES apps(id),
  limit_type TEXT NOT NULL,
  limit_value INTEGER NOT NULL,
  PRIMARY KEY (app_id, limit_type)
);

-- Conservative initial platform defaults. They are configurable through the
-- keys API and only take effect once the respective app exists.
INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value)
SELECT 'mail', 'emails_per_day', 20 WHERE EXISTS (SELECT 1 FROM apps WHERE id = 'mail');
INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value)
SELECT 'mail', 'webhooks', 10 WHERE EXISTS (SELECT 1 FROM apps WHERE id = 'mail');
INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value)
SELECT 'hide-my-email', 'aliases', 25 WHERE EXISTS (SELECT 1 FROM apps WHERE id = 'hide-my-email');
INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value)
SELECT 'verify', 'verified_resources', 20 WHERE EXISTS (SELECT 1 FROM apps WHERE id = 'verify');
