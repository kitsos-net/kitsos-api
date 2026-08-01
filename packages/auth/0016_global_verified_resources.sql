-- A resource verification proves ownership once for the whole platform.
-- Canonicalize legacy per-app resources, retain the verification/grant chosen
-- for each owner, and keep app_id only as a compatibility storage column owned
-- by the Verify service.

DROP TRIGGER prevent_deleting_resource_grant_in_use;
DROP TRIGGER delete_orphan_resource_after_verification;

CREATE TABLE resource_global_merge (
  old_id TEXT PRIMARY KEY,
  canonical_id TEXT NOT NULL
);

INSERT INTO resource_global_merge (old_id, canonical_id)
SELECT
  id,
  FIRST_VALUE(id) OVER (
    PARTITION BY resource_type, value
    ORDER BY created_at, id
  )
FROM resources;

-- A user needs one ownership grant per global resource. Prefer the grant
-- backed by the newest successful verification when legacy app copies collide.
DELETE FROM resource_grants
WHERE id IN (
  SELECT id
  FROM (
    SELECT
      rg.id,
      ROW_NUMBER() OVER (
        PARTITION BY merge.canonical_id, rg.user_id
        ORDER BY
          rv.verified_at IS NOT NULL DESC,
          rv.verified_at DESC,
          rg.created_at DESC,
          rg.id DESC
      ) AS duplicate_rank
    FROM resource_grants rg
    JOIN resource_global_merge merge ON merge.old_id = rg.resource_id
    LEFT JOIN resource_verifications rv ON rv.id = rg.verification_id
  )
  WHERE duplicate_rank > 1
);

DELETE FROM api_key_resource_grants
WHERE rowid IN (
  SELECT rowid
  FROM (
    SELECT
      legacy.rowid,
      ROW_NUMBER() OVER (
        PARTITION BY legacy.api_key_id, legacy.resource_type, merge.canonical_id
        ORDER BY legacy.rowid DESC
      ) AS duplicate_rank
    FROM api_key_resource_grants legacy
    JOIN resource_global_merge merge ON merge.old_id = legacy.resource_id
  )
  WHERE duplicate_rank > 1
);

UPDATE resource_verifications
SET resource_id = (
  SELECT canonical_id
  FROM resource_global_merge
  WHERE old_id = resource_verifications.resource_id
);

UPDATE resource_grants
SET resource_id = (
  SELECT canonical_id
  FROM resource_global_merge
  WHERE old_id = resource_grants.resource_id
);

UPDATE api_key_resource_grants
SET resource_id = (
  SELECT canonical_id
  FROM resource_global_merge
  WHERE old_id = api_key_resource_grants.resource_id
);

UPDATE audit_log
SET resource_id = (
  SELECT canonical_id
  FROM resource_global_merge
  WHERE old_id = audit_log.resource_id
)
WHERE resource_id IN (SELECT old_id FROM resource_global_merge);

DELETE FROM resources
WHERE id IN (
  SELECT old_id
  FROM resource_global_merge
  WHERE old_id != canonical_id
);

DROP INDEX idx_resources_app_type_value;
UPDATE resources SET app_id = 'verify';
CREATE UNIQUE INDEX idx_resources_type_value
  ON resources(resource_type, value);

DROP TABLE resource_global_merge;

-- Product objects depend on global ownership, regardless of which app created
-- a legacy resource row.
CREATE TRIGGER prevent_deleting_resource_grant_in_use
BEFORE DELETE ON resource_grants
WHEN EXISTS (
  SELECT 1
  FROM resources r
  WHERE r.id = OLD.resource_id
    AND r.resource_type = 'email_address'
    AND (
      EXISTS (
        SELECT 1
        FROM mail_webhooks w
        WHERE w.user_id = OLD.user_id
          AND lower(w.from_address) = lower(r.value)
      )
      OR EXISTS (
        SELECT 1
        FROM hme_aliases a
        WHERE a.user_id = OLD.user_id
          AND lower(a.forward_to) = lower(r.value)
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'resource-in-use');
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
    )
    AND NOT EXISTS (
      SELECT 1 FROM api_key_resource_grants WHERE resource_id = OLD.resource_id
    );
END;
