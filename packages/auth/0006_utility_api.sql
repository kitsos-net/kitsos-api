-- Kitsos Utility API: cryptographic hashes, time, geo and DNS lookups.
INSERT OR IGNORE INTO apps (id, name, description, environment)
VALUES ('utility', 'Kitsos Utility API', 'Public utility endpoints with elevated API-key limits', 'production');

INSERT OR IGNORE INTO app_scopes (app_id, scope, description) VALUES
  ('utility', 'utility:crypt', 'Cryptographic hash endpoint'),
  ('utility', 'utility:time', 'Time and timezone endpoint'),
  ('utility', 'utility:geo', 'Edge geolocation endpoint'),
  ('utility', 'utility:dns', 'DNS lookup endpoint');

INSERT OR IGNORE INTO rate_limit_rules (id, app_id, scope, window_seconds, max_requests)
VALUES ('rl_utility_default', 'utility', NULL, 60, 120);
