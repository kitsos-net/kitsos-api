-- Bind every resource grant to the verification that authorized it, expire
-- verification attempts, and make mail usage accounting atomic.

ALTER TABLE resource_verifications ADD COLUMN token_hash TEXT;
ALTER TABLE resource_verifications ADD COLUMN token_expires_at INTEGER;
ALTER TABLE resource_grants ADD COLUMN verification_id TEXT REFERENCES resource_verifications(id);

-- Existing plaintext tokens cannot be migrated safely. Remove all of them;
-- users with a pending attempt can start a fresh one.
UPDATE resource_verifications
SET token = NULL;
DROP INDEX IF EXISTS idx_resource_verif_token;

-- Preserve existing verified grants by attaching the newest successful
-- verification for the same resource and user.
UPDATE resource_grants
SET verification_id = (
  SELECT rv.id
  FROM resource_verifications rv
  WHERE rv.resource_id = resource_grants.resource_id
    AND rv.user_id = resource_grants.user_id
    AND rv.verified_at IS NOT NULL
  ORDER BY rv.verified_at DESC
  LIMIT 1
)
WHERE verification_id IS NULL;

-- Keep one effective grant per user/resource. New verifications replace its
-- scopes and verification reference atomically.
DELETE FROM resource_grants
WHERE rowid NOT IN (
  SELECT MAX(rowid)
  FROM resource_grants
  GROUP BY resource_id, user_id
);

CREATE UNIQUE INDEX idx_resource_grants_resource_user
  ON resource_grants(resource_id, user_id);
CREATE INDEX idx_resource_verif_token_hash
  ON resource_verifications(token_hash);
CREATE UNIQUE INDEX idx_resources_app_type_value
  ON resources(app_id, resource_type, value);

CREATE TABLE mail_daily_usage (
  user_id TEXT NOT NULL,
  day_bucket INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day_bucket)
);

-- Usage-limit lookup must be deterministic. Retain the newest row for each
-- base/override slot, then enforce that invariant.
DELETE FROM usage_limits
WHERE rowid NOT IN (
  SELECT MAX(rowid)
  FROM usage_limits
  GROUP BY user_id, app_id, limit_type, is_override
);

CREATE UNIQUE INDEX idx_usage_limits_effective
  ON usage_limits(user_id, app_id, limit_type, is_override);
