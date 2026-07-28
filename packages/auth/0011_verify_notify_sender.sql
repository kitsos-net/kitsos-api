-- Move the Verify system sender onto the dedicated notification subdomain.
-- The resource id and verification/grant references remain stable.
UPDATE users
SET email = 'verify@notify.kitsos.net'
WHERE id = 'system:verify-mailer'
  AND email = 'verify@kitsos.net';

UPDATE resources
SET value = 'verify@notify.kitsos.net'
WHERE id = 'resource:system:verify-mailer:sender'
  AND app_id = 'mail'
  AND resource_type = 'email_address'
  AND value = 'verify@kitsos.net';
