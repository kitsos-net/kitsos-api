-- Collapse historical duplicate resources, verification attempts and grants,
-- then make the one-resource/one-owner model enforceable by SQLite.

UPDATE resource_verifications
SET resource_id = (
  SELECT canonical.id
  FROM resources AS duplicate
  JOIN resources AS canonical
    ON canonical.resource_type = duplicate.resource_type
   AND canonical.value = duplicate.value
  WHERE duplicate.id = resource_verifications.resource_id
  ORDER BY canonical.created_at ASC, canonical.id ASC
  LIMIT 1
)
WHERE resource_id IN (
  SELECT id FROM resources
);

UPDATE resource_grants
SET resource_id = (
  SELECT canonical.id
  FROM resources AS duplicate
  JOIN resources AS canonical
    ON canonical.resource_type = duplicate.resource_type
   AND canonical.value = duplicate.value
  WHERE duplicate.id = resource_grants.resource_id
  ORDER BY canonical.created_at ASC, canonical.id ASC
  LIMIT 1
)
WHERE resource_id IN (
  SELECT id FROM resources
);

DELETE FROM resources
WHERE id NOT IN (
  SELECT canonical_id FROM (
    SELECT id AS canonical_id,
           ROW_NUMBER() OVER (
             PARTITION BY resource_type, value
             ORDER BY created_at ASC, id ASC
           ) AS position
    FROM resources
  )
  WHERE position = 1
);

-- Retain the newest successful verification (or newest pending attempt when
-- none succeeded) for each resource owner.
DELETE FROM resource_verifications
WHERE id NOT IN (
  SELECT id FROM (
    SELECT id,
           ROW_NUMBER() OVER (
             PARTITION BY resource_id, user_id
             ORDER BY (verified_at IS NOT NULL) DESC, verified_at DESC, created_at DESC, id DESC
           ) AS position
    FROM resource_verifications
  )
  WHERE position = 1
);

-- Preserve the union of every historically granted scope before collapsing
-- duplicate grant rows.
UPDATE resource_grants AS target
SET scopes = (
  SELECT json_group_array(scope)
  FROM (
    SELECT DISTINCT json_each.value AS scope
    FROM resource_grants AS source, json_each(source.scopes)
    WHERE source.resource_id = target.resource_id
      AND source.user_id = target.user_id
    ORDER BY scope
  )
);

DELETE FROM resource_grants
WHERE id NOT IN (
  SELECT id FROM (
    SELECT id,
           ROW_NUMBER() OVER (
             PARTITION BY resource_id, user_id
             ORDER BY created_at DESC, id DESC
           ) AS position
    FROM resource_grants
  )
  WHERE position = 1
);

DROP INDEX IF EXISTS idx_resources_type_value;
CREATE UNIQUE INDEX idx_resources_type_value_unique
  ON resources(resource_type, value);
CREATE UNIQUE INDEX idx_resource_verifications_resource_user_unique
  ON resource_verifications(resource_id, user_id);
CREATE UNIQUE INDEX idx_resource_grants_resource_user_unique
  ON resource_grants(resource_id, user_id);

-- Users start with 15 magic-link emails per UTC day. A reviewed entry in
-- usage_limits overrides this default, which is the existing increase-request
-- workflow used across the platform.
INSERT OR IGNORE INTO usage_limit_defaults (app_id, limit_type, limit_value)
SELECT 'verify', 'verification_emails_per_day', 15
WHERE EXISTS (SELECT 1 FROM apps WHERE id = 'verify');
