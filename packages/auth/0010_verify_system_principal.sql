-- Dedicated service principal for Verify -> Mail. This is intentionally a D1
-- principal rather than a human Clerk account: it cannot sign in and receives
-- only the mail:send scope needed by the Verify worker.
INSERT OR IGNORE INTO users (id, email, display_name, status)
VALUES (
  'system:verify-mailer',
  'verify@kitsos.net',
  'Kitsos Verify Mailer',
  'active'
);

INSERT OR IGNORE INTO policies
  (id, app_id, subject_type, subject_id, scopes)
VALUES (
  'policy:system:verify-mailer:mail-send',
  'mail',
  'user',
  'system:verify-mailer',
  '["mail:send"]'
);

INSERT OR IGNORE INTO resources
  (id, app_id, resource_type, value)
VALUES (
  'resource:system:verify-mailer:sender',
  'mail',
  'email_address',
  'verify@kitsos.net'
);

INSERT OR IGNORE INTO resource_verifications
  (id, resource_id, user_id, method, verified_at)
VALUES (
  'verification:system:verify-mailer:sender',
  'resource:system:verify-mailer:sender',
  'system:verify-mailer',
  'system_bootstrap',
  unixepoch()
);

INSERT INTO resource_grants
  (id, resource_id, user_id, scopes, verification_id)
VALUES (
  'grant:system:verify-mailer:sender',
  'resource:system:verify-mailer:sender',
  'system:verify-mailer',
  '["mail:send"]',
  'verification:system:verify-mailer:sender'
)
ON CONFLICT(resource_id, user_id) DO UPDATE SET
  scopes = excluded.scopes,
  verification_id = excluded.verification_id;

INSERT INTO mail_templates
  (id, user_id, name, url, variables)
VALUES (
  'resource-verification',
  'system:verify-mailer',
  'Resource verification',
  'https://cdn.kitsos.net/api/mail/templates/verify-email-dev.html',
  '["resource","confirm_url","magicLink"]'
)
ON CONFLICT(id) DO UPDATE SET
  user_id = excluded.user_id,
  name = excluded.name,
  url = excluded.url,
  variables = excluded.variables;

-- This internal sender remains bounded by the normal mail hard maximum while
-- not sharing the human account's Free Tier quota.
INSERT INTO usage_limits
  (id, user_id, app_id, limit_type, limit_value, is_override)
VALUES (
  'limit:system:verify-mailer:emails-per-day',
  'system:verify-mailer',
  'mail',
  'emails_per_day',
  10000,
  1
)
ON CONFLICT(user_id, app_id, limit_type, is_override) DO UPDATE SET
  limit_value = excluded.limit_value;
