-- Utility originally used one umbrella policy scope. Replace that legacy
-- value with the concrete scopes enforced by the v1 Utility endpoints.
-- Existing concrete scopes do not need to be preserved separately because
-- utility:manage granted the complete Utility API before the split.
UPDATE policies
SET scopes = '[
  "utility:crypt",
  "utility:time",
  "utility:geo",
  "utility:dns"
]'
WHERE app_id = 'utility'
  AND EXISTS (
    SELECT 1
    FROM json_each(policies.scopes)
    WHERE value = 'utility:manage'
  );
