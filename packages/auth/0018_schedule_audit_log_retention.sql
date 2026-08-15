-- Audit retention used to run after every insert. The OFFSET scan grew with
-- each user's history and made a write account for thousands of rows read.
-- The keys-api scheduled handler now performs the same bounded cleanup once
-- per day instead.
DROP TRIGGER IF EXISTS trim_audit_log_after_insert;
