-- Adds fields needed to track a verification attempt before it's confirmed:
-- the token to check for (DNS TXT value / magic-link token) and the scopes
-- that will be granted once verification succeeds.

ALTER TABLE resource_verifications ADD COLUMN token TEXT;
ALTER TABLE resource_verifications ADD COLUMN pending_scopes TEXT;

CREATE INDEX idx_resource_verif_token ON resource_verifications(token);
