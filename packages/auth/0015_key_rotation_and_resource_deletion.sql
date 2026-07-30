-- Keep verified resources from being removed while a product object owned by
-- the same user still relies on the grant. The self-service and admin APIs
-- surface this invariant as HTTP 409. The trigger closes the check/delete race
-- for every current and future caller.
CREATE TRIGGER prevent_deleting_resource_grant_in_use
BEFORE DELETE ON resource_grants
WHEN EXISTS (
  SELECT 1
  FROM resources r
  WHERE r.id = OLD.resource_id
    AND (
      (
        r.app_id = 'mail'
        AND r.resource_type = 'email_address'
        AND EXISTS (
          SELECT 1
          FROM mail_webhooks w
          WHERE w.user_id = OLD.user_id
            AND lower(w.from_address) = lower(r.value)
        )
      )
      OR (
        r.app_id = 'hide-my-email'
        AND r.resource_type = 'email_address'
        AND EXISTS (
          SELECT 1
          FROM hme_aliases a
          WHERE a.user_id = OLD.user_id
            AND lower(a.forward_to) = lower(r.value)
        )
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'resource-in-use');
END;

DROP TRIGGER delete_orphan_resource_after_verification;
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
