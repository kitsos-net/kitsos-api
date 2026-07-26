-- Dedicated machine-to-machine app for Grafana and other analytics readers.
-- Policies and API keys are deliberately not created here: grant this scope
-- only to the service account that Grafana uses.
INSERT OR IGNORE INTO apps (id, name, description, environment)
VALUES ('analytics', 'Analytics', 'Read-only aggregated platform analytics', 'production');

INSERT OR IGNORE INTO app_scopes (app_id, scope, description)
VALUES ('analytics', 'analytics:read', 'Read aggregated platform analytics');
