#!/bin/sh
set -eu

test_db="$(mktemp /tmp/kitsos-security.XXXXXX)"
trap 'rm -f "$test_db"' EXIT

for migration in packages/auth/00*.sql; do
  sqlite3 "$test_db" ".read $migration"
done

sqlite3 "$test_db" "
  PRAGMA foreign_keys = ON;
  INSERT INTO users (id, email)
  VALUES ('owner', 'owner@example.com'), ('other', 'other@example.com');

  INSERT INTO api_keys
    (id, key_hash, user_id, app_id, name, description, status, scopes,
     expires_at, auto_roll_at)
  VALUES
    ('old', 'old-hash', 'owner', 'mail', 'Production', 'metadata',
     'active', '[\"mail:send\"]', unixepoch() + 3600, unixepoch() + 1800);
  INSERT INTO api_key_apps (api_key_id, app_id, scopes)
  VALUES
    ('old', 'mail', '[\"mail:send\"]'),
    ('old', 'hide-my-email', '[\"hme:read\"]');

  BEGIN IMMEDIATE;
  INSERT INTO api_keys
    (id, key_hash, user_id, app_id, name, description, status, scopes,
     expires_at, auto_roll_at)
  SELECT
    'new', 'new-hash', user_id, app_id, name, description, 'active', scopes,
    expires_at, auto_roll_at
  FROM api_keys
  WHERE id = 'old' AND status = 'active';
  INSERT INTO api_key_apps (api_key_id, app_id, scopes)
  SELECT 'new', app_id, scopes
  FROM api_key_apps
  WHERE api_key_id = 'old';
  UPDATE api_keys
  SET status = 'revoked'
  WHERE id = 'old' AND status = 'active'
    AND EXISTS (SELECT 1 FROM api_keys WHERE id = 'new');
  COMMIT;

  CREATE TEMP TABLE assertions (ok INTEGER NOT NULL CHECK (ok = 1));
  INSERT INTO assertions
  SELECT COUNT(*) = 1
  FROM api_keys
  WHERE id = 'new' AND user_id = 'owner' AND name = 'Production'
    AND description = 'metadata' AND status = 'active'
    AND expires_at IS NOT NULL AND auto_roll_at IS NOT NULL;
  INSERT INTO assertions
  SELECT COUNT(*) = 2 FROM api_key_apps WHERE api_key_id = 'new';
  INSERT INTO assertions
  SELECT COUNT(*) = 0
  FROM (
    SELECT 'second-new'
    FROM api_keys
    WHERE id = 'old' AND status = 'active'
  );

  INSERT INTO resources (id, app_id, resource_type, value)
  VALUES ('shared', 'mail', 'email_address', 'sender@example.com');
  INSERT INTO resource_verifications
    (id, resource_id, user_id, method, verified_at)
  VALUES
    ('verification-owner', 'shared', 'owner', 'magic_link', unixepoch()),
    ('verification-other', 'shared', 'other', 'magic_link', unixepoch());
  INSERT INTO resource_grants
    (id, resource_id, user_id, scopes, verification_id)
  VALUES
    ('grant-owner', 'shared', 'owner', '[\"mail:send\"]', 'verification-owner'),
    ('grant-other', 'shared', 'other', '[\"mail:send\"]', 'verification-other');
  INSERT INTO mail_templates (id, user_id, name, url, variables)
  VALUES ('template', 'owner', 'Template', 'https://example.com/template', '[]');
  INSERT INTO mail_webhooks
    (id, user_id, name, secret_hash, template_id, from_address, to_addresses, mapping)
  VALUES
    ('webhook', 'owner', 'Webhook', 'hash', 'template',
     'sender@example.com', '[]', '{}');
"

if sqlite3 "$test_db" \
  "PRAGMA foreign_keys = ON; DELETE FROM resource_grants WHERE id = 'grant-owner';" \
  2>&1 | grep -q "resource-in-use"; then
  :
else
  echo "expected resource-in-use conflict" >&2
  exit 1
fi

sqlite3 "$test_db" "
  PRAGMA foreign_keys = ON;
  DELETE FROM mail_webhooks WHERE id = 'webhook';
  DELETE FROM resource_grants
  WHERE resource_id = 'shared' AND user_id = 'owner';
  DELETE FROM resource_verifications
  WHERE resource_id = 'shared' AND user_id = 'owner';
  DELETE FROM resources
  WHERE id = 'shared'
    AND NOT EXISTS (
      SELECT 1 FROM resource_verifications WHERE resource_id = 'shared'
    )
    AND NOT EXISTS (
      SELECT 1 FROM resource_grants WHERE resource_id = 'shared'
    );
  CREATE TEMP TABLE final_assertions (ok INTEGER NOT NULL CHECK (ok = 1));
  INSERT INTO final_assertions
  SELECT COUNT(*) = 1 FROM resources WHERE id = 'shared';
  INSERT INTO final_assertions
  SELECT COUNT(*) = 1
  FROM resource_grants
  WHERE resource_id = 'shared' AND user_id = 'other';
"

echo "security invariants passed"

global_db="$(mktemp /tmp/kitsos-global-resources.XXXXXX)"
trap 'rm -f "$test_db" "$global_db"' EXIT

for migration in packages/auth/000[1-9]_*.sql packages/auth/001[0-5]_*.sql; do
  sqlite3 "$global_db" ".read $migration"
done

sqlite3 "$global_db" "
  PRAGMA foreign_keys = ON;
  INSERT INTO users (id, email) VALUES ('global-owner', 'global@example.com');
  INSERT INTO resources (id, app_id, resource_type, value) VALUES
    ('mail-copy', 'mail', 'email_address', 'global@example.com'),
    ('hme-copy', 'hide-my-email', 'email_address', 'global@example.com');
  INSERT INTO resource_verifications
    (id, resource_id, user_id, method, verified_at)
  VALUES
    ('mail-verification', 'mail-copy', 'global-owner', 'magic_link', 100),
    ('hme-verification', 'hme-copy', 'global-owner', 'magic_link', 200);
  INSERT INTO resource_grants
    (id, resource_id, user_id, scopes, verification_id)
  VALUES
    ('mail-grant', 'mail-copy', 'global-owner', '[\"mail:send\"]', 'mail-verification'),
    ('hme-grant', 'hme-copy', 'global-owner', '[\"hme:receive\"]', 'hme-verification');
  CREATE INDEX idx_resources_type_value ON resources(resource_type, value);
"

sqlite3 "$global_db" \
  -cmd "PRAGMA foreign_keys = ON" \
  ".read packages/auth/0016_global_verified_resources.sql"

sqlite3 "$global_db" ".read packages/auth/0017_verify_template_canonical_url.sql"

sqlite3 "$global_db" "
  PRAGMA foreign_keys = ON;
  CREATE TEMP TABLE global_assertions (ok INTEGER NOT NULL CHECK (ok = 1));
  INSERT INTO global_assertions
  SELECT COUNT(*) = 1
  FROM resources
  WHERE resource_type = 'email_address'
    AND value = 'global@example.com'
    AND app_id = 'verify';
  INSERT INTO global_assertions
  SELECT COUNT(*) = 1
  FROM resource_grants rg
  JOIN resources r ON r.id = rg.resource_id
  WHERE rg.user_id = 'global-owner'
    AND r.resource_type = 'email_address'
    AND r.value = 'global@example.com';
  INSERT INTO global_assertions
  SELECT COUNT(*) = 2
  FROM resource_verifications rv
  JOIN resources r ON r.id = rv.resource_id
  WHERE rv.user_id = 'global-owner'
    AND r.resource_type = 'email_address'
    AND r.value = 'global@example.com';
  INSERT INTO global_assertions
  SELECT COUNT(*) = 1
  FROM mail_templates
  WHERE id = 'resource-verification'
    AND url = 'https://cdn.kitsos.net/api/mail/templates/verify-email-dev';
"

echo "global resource migration passed"

grep -q 'redirect: "manual"' apps/mail/src/template.ts
if grep -Eq '^[[:space:]]*redirect: "error"' apps/mail/src/template.ts; then
  echo "workerd-incompatible redirect mode returned" >&2
  exit 1
fi

test "$(grep -c 'callUpstream(context, "kitsos_' apps/mcp/src/tools.ts)" -eq 28
grep -q 'requestSpan?.addEvent("mcp.tool.call"' apps/mcp/src/index.ts
grep -q '"db.statement"' packages/telemetry/src/index.ts
grep -q '"db.cf.kv.key"' packages/telemetry/src/index.ts
grep -q 'recordAuthDecision' packages/auth/src/index.ts
grep -q 'recordResourceDecision' packages/auth/src/checks.ts
grep -q 'recordUsageDecision' packages/auth/src/checks.ts

echo "telemetry invariants passed"
