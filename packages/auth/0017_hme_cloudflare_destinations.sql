-- Cloudflare Email Routing destination addresses are account-global, while
-- Kitsos resource grants stay user-specific.  This table stores only the
-- Cloudflare identifier and confirmation state; the destination email itself
-- remains canonical in resources.value.
CREATE TABLE hme_cloudflare_destinations (
  resource_id TEXT PRIMARY KEY REFERENCES resources(id),
  destination_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'verified')),
  verified_at INTEGER,
  last_checked_at INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_hme_cloudflare_destinations_status
  ON hme_cloudflare_destinations(status, last_checked_at);
