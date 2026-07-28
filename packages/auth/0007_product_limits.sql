-- Unified, atomic daily counters and indexes for user-adjustable product
-- limits. Defaults live in code; usage_limits stores per-user overrides.

INSERT OR IGNORE INTO apps (id, name, description, environment)
VALUES
  ('keys-api', 'Keys API', 'API key and access management', 'production'),
  ('verify', 'Verify', 'Resource ownership verification', 'production'),
  ('mail', 'Mail', 'Email delivery and templates', 'production'),
  ('hide-my-email', 'Hide My Email', 'Email forwarding aliases', 'production');

ALTER TABLE api_keys ADD COLUMN description TEXT;

CREATE TABLE daily_usage_counters (
  user_id TEXT NOT NULL REFERENCES users(id),
  app_id TEXT NOT NULL REFERENCES apps(id),
  limit_type TEXT NOT NULL,
  day_bucket INTEGER NOT NULL CHECK (day_bucket >= 0),
  count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
  PRIMARY KEY (user_id, app_id, limit_type, day_bucket)
);

INSERT OR IGNORE INTO daily_usage_counters
  (user_id, app_id, limit_type, day_bucket, count)
SELECT user_id, 'mail', 'emails_per_day', day_bucket, count
FROM mail_daily_usage;

INSERT INTO usage_limits
  (id, user_id, app_id, limit_type, limit_value, is_override)
SELECT
  lower(hex(randomblob(16))),
  user_id,
  'mail',
  'mail_webhooks',
  max_webhooks,
  1
FROM mail_user_limits
WHERE true
ON CONFLICT(user_id, app_id, limit_type, is_override)
DO UPDATE SET limit_value = excluded.limit_value;

INSERT INTO usage_limits
  (id, user_id, app_id, limit_type, limit_value, is_override)
SELECT
  lower(hex(randomblob(16))),
  user_id,
  'mail',
  'emails_per_day',
  max_emails_per_day,
  1
FROM mail_user_limits
WHERE true
ON CONFLICT(user_id, app_id, limit_type, is_override)
DO UPDATE SET limit_value = excluded.limit_value;

DELETE FROM api_keys WHERE status = 'revoked';
DELETE FROM resource_verifications
WHERE verified_at IS NULL
  AND token_expires_at IS NOT NULL
  AND token_expires_at < unixepoch();

CREATE INDEX idx_api_keys_user_status
  ON api_keys(user_id, status);
CREATE INDEX idx_api_keys_expires
  ON api_keys(expires_at)
  WHERE expires_at IS NOT NULL;
CREATE INDEX idx_verifications_user_created
  ON resource_verifications(user_id, created_at);
CREATE INDEX idx_verifications_pending_expiry
  ON resource_verifications(token_expires_at)
  WHERE verified_at IS NULL AND token_expires_at IS NOT NULL;
CREATE INDEX idx_audit_log_user_created
  ON audit_log(user_id, created_at DESC, id);

-- Normalize legacy pending requests before enforcing the new invariants.
UPDATE limit_increase_requests
SET status = 'denied', reviewed_at = unixepoch()
WHERE id IN (
  SELECT id
  FROM (
    SELECT
      id,
      ROW_NUMBER() OVER (
        PARTITION BY user_id, app_id, limit_type
        ORDER BY created_at DESC, id DESC
      ) AS type_rank
    FROM limit_increase_requests
    WHERE status = 'pending'
  )
  WHERE type_rank > 1
);

UPDATE limit_increase_requests
SET status = 'denied', reviewed_at = unixepoch()
WHERE id IN (
  SELECT id
  FROM (
    SELECT
      id,
      ROW_NUMBER() OVER (
        PARTITION BY user_id
        ORDER BY created_at DESC, id DESC
      ) AS pending_rank
    FROM limit_increase_requests
    WHERE status = 'pending'
  )
  WHERE pending_rank > 5
);

CREATE UNIQUE INDEX idx_limit_requests_one_pending
  ON limit_increase_requests(user_id, app_id, limit_type)
  WHERE status = 'pending';

-- Keep abuse-resistant rolling histories. These triggers bound storage even
-- when a valid account continuously creates allowed traffic over many years.
CREATE TRIGGER trim_daily_usage_counters_after_insert
AFTER INSERT ON daily_usage_counters
BEGIN
  DELETE FROM daily_usage_counters
  WHERE user_id = NEW.user_id
    AND day_bucket <= NEW.day_bucket - 31;
END;

CREATE TRIGGER trim_audit_log_after_insert
AFTER INSERT ON audit_log
BEGIN
  DELETE FROM audit_log
  WHERE id IN (
    SELECT id
    FROM audit_log
    WHERE user_id IS NEW.user_id
    ORDER BY created_at DESC, id DESC
    LIMIT -1 OFFSET 10000
  );
END;

CREATE TRIGGER trim_limit_requests_after_insert
AFTER INSERT ON limit_increase_requests
BEGIN
  DELETE FROM limit_increase_requests
  WHERE id IN (
    SELECT id
    FROM limit_increase_requests
    WHERE user_id = NEW.user_id
      AND status != 'pending'
    ORDER BY created_at DESC, id DESC
    LIMIT -1 OFFSET 1000
  );
END;

CREATE TRIGGER trim_verifications_after_insert
AFTER INSERT ON resource_verifications
BEGIN
  DELETE FROM resource_verifications
  WHERE id IN (
    SELECT rv.id
    FROM resource_verifications rv
    LEFT JOIN resource_grants rg ON rg.verification_id = rv.id
    WHERE rv.user_id = NEW.user_id
      AND rg.id IS NULL
    ORDER BY rv.created_at DESC, rv.id DESC
    LIMIT -1 OFFSET 1000
  );
END;

CREATE TRIGGER delete_orphan_resource_after_verification
AFTER DELETE ON resource_verifications
BEGIN
  DELETE FROM resources
  WHERE id = OLD.resource_id
    AND NOT EXISTS (
      SELECT 1 FROM resource_verifications WHERE resource_id = OLD.resource_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM resource_grants WHERE resource_id = OLD.resource_id
    );
END;

DELETE FROM resources
WHERE NOT EXISTS (
  SELECT 1 FROM resource_verifications WHERE resource_id = resources.id
)
  AND NOT EXISTS (
    SELECT 1 FROM resource_grants WHERE resource_id = resources.id
  );
