-- User-managed metadata and live scope restrictions for MCP OAuth grants.
-- The OAuth provider remains the source of truth for grants and tokens; this
-- table stores only Kitsos-owned settings that must take effect immediately.

CREATE TABLE mcp_connections (
  delegation_id TEXT PRIMARY KEY
    CHECK (length(delegation_id) BETWEEN 1 AND 128),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
    CHECK (length(user_id) BETWEEN 1 AND 256),
  client_id TEXT NOT NULL
    CHECK (length(client_id) BETWEEN 1 AND 256),
  client_name TEXT
    CHECK (client_name IS NULL OR length(client_name) <= 100),
  description TEXT
    CHECK (description IS NULL OR length(description) <= 500),
  granted_scopes TEXT NOT NULL
    CHECK (json_valid(granted_scopes) AND length(granted_scopes) <= 4096),
  configured_scopes TEXT NOT NULL
    CHECK (json_valid(configured_scopes) AND length(configured_scopes) <= 4096),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_mcp_connections_user_created
  ON mcp_connections(user_id, created_at DESC);

CREATE INDEX idx_mcp_connections_client
  ON mcp_connections(client_id);
