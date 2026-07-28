-- Atomic fixed-window request counters. Cloudflare KV's free-tier write
-- allowance is too small for a write on every API request, so request rate
-- limits use D1 while KV remains available for low-write authentication cache.
CREATE TABLE request_rate_counters (
  bucket_key TEXT NOT NULL CHECK (length(bucket_key) BETWEEN 1 AND 512),
  window_start INTEGER NOT NULL CHECK (window_start >= 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > window_start),
  count INTEGER NOT NULL CHECK (count >= 1),
  PRIMARY KEY (bucket_key, window_start)
);

CREATE INDEX idx_request_rate_counters_expiry
  ON request_rate_counters(expires_at);
