-- Resource ownership is platform-wide. app_id remains legacy provenance,
-- while lookups use resource_type + value across every Kitsos API.
CREATE INDEX IF NOT EXISTS idx_resources_type_value ON resources(resource_type, value);
