-- The CDN redirects the legacy .html path. Mail template fetches deliberately
-- reject redirects, so keep the system template on its canonical URL.
UPDATE mail_templates
SET url = 'https://cdn.kitsos.net/api/mail/templates/verify-email-dev'
WHERE id = 'resource-verification'
  AND user_id = 'system:verify-mailer'
  AND url = 'https://cdn.kitsos.net/api/mail/templates/verify-email-dev.html';
