-- Kitsos API Platform — initial schema
-- User IDs are Clerk user IDs (not Auth0 sub)

-- ============ Users & Groups ============
CREATE TABLE users (
  id TEXT PRIMARY KEY,             -- Clerk user_id
  email TEXT NOT NULL,
  display_name TEXT,
  status TEXT NOT NULL DEFAULT 'active',  -- active | deactivated | pending_deletion | deleted
  last_active_at INTEGER,
  deletion_scheduled_at INTEGER,
  deletion_reason TEXT,            -- inactivity | user_request | admin
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE user_ip_allowlist (
  user_id TEXT NOT NULL REFERENCES users(id),
  cidr TEXT NOT NULL,
  PRIMARY KEY (user_id, cidr)
);

-- ============ Apps & Scopes ============
CREATE TABLE apps (
  id TEXT PRIMARY KEY,             -- z.B. "dns-manager"
  name TEXT NOT NULL,
  description TEXT,
  environment TEXT NOT NULL DEFAULT 'production',  -- production | staging | dev
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE app_scopes (
  app_id TEXT NOT NULL REFERENCES apps(id),
  scope TEXT NOT NULL,             -- z.B. "dns:record:write"
  description TEXT,
  PRIMARY KEY (app_id, scope)
);

-- ============ API Keys ============
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  app_id TEXT NOT NULL REFERENCES apps(id),
  name TEXT,
  status TEXT NOT NULL DEFAULT 'active',   -- active | revoked | expired
  scopes TEXT NOT NULL,             -- JSON array, subset of app_scopes
  expires_at INTEGER,
  auto_roll_at INTEGER,
  last_used_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ============ Policies ============
CREATE TABLE policies (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES apps(id),
  subject_type TEXT NOT NULL,       -- user | group
  subject_id TEXT NOT NULL,
  scopes TEXT NOT NULL,             -- JSON array
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ============ Resources / ReBAC ============
CREATE TABLE resources (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES apps(id),
  resource_type TEXT NOT NULL,      -- zone | email_address | ...
  value TEXT NOT NULL,              -- z.B. "domain.de" oder "name@email.de"
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE resource_verifications (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES resources(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  method TEXT NOT NULL,             -- dns_txt | magic_link
  verified_at INTEGER,
  reverify_due_at INTEGER,
  grace_expires_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE resource_grants (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES resources(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  scopes TEXT NOT NULL,             -- JSON array
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ============ Rate Limits ============
CREATE TABLE rate_limit_rules (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES apps(id),
  scope TEXT,
  window_seconds INTEGER NOT NULL,
  max_requests INTEGER NOT NULL
);

-- ============ Usage Limits + Increase Requests ============
CREATE TABLE usage_limits (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  app_id TEXT NOT NULL REFERENCES apps(id),
  limit_type TEXT NOT NULL,         -- z.B. "emails_per_day"
  limit_value INTEGER NOT NULL,
  is_override INTEGER NOT NULL DEFAULT 0,  -- boolean 0/1
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE limit_increase_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  app_id TEXT NOT NULL REFERENCES apps(id),
  limit_type TEXT NOT NULL,
  requested_value INTEGER NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied
  reviewed_by TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  reviewed_at INTEGER
);

-- ============ Audit Log ============
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  app_id TEXT,
  api_key_id TEXT,
  action TEXT NOT NULL,
  resource_id TEXT,
  result TEXT NOT NULL,             -- allowed | denied
  reason TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ============ Indexes ============
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_app ON api_keys(app_id);
CREATE INDEX idx_policies_subject ON policies(subject_type, subject_id);
CREATE INDEX idx_resources_app_value ON resources(app_id, value);
CREATE INDEX idx_resource_grants_user ON resource_grants(user_id);
CREATE INDEX idx_resource_verif_resource ON resource_verifications(resource_id);
CREATE INDEX idx_usage_limits_user_app ON usage_limits(user_id, app_id);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
