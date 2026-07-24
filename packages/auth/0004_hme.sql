CREATE TABLE hme_aliases (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  alias TEXT NOT NULL UNIQUE,      -- local part, e.g. "house.exclusive.15"
  domain TEXT NOT NULL DEFAULT 'hme.kitsos.net',
  forward_to TEXT NOT NULL,        -- must be a verified email_address resource grant
  label TEXT,                      -- user's own note, e.g. "signed up for X"
  status TEXT NOT NULL DEFAULT 'active',  -- active | disabled
  emails_forwarded INTEGER NOT NULL DEFAULT 0,
  last_forwarded_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_hme_aliases_user ON hme_aliases(user_id);
CREATE INDEX idx_hme_aliases_alias ON hme_aliases(alias);
