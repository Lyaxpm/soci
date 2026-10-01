CREATE TABLE IF NOT EXISTS donations (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL DEFAULT 'sociabuzz',
  username TEXT NOT NULL,
  amount INTEGER NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'IDR',
  created_at INTEGER NOT NULL,
  created_at_iso TEXT NOT NULL,
  raw_hash TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'queued',
  lease_token TEXT,
  lease_until INTEGER,
  leased_by TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  done_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_donations_queue
  ON donations(state, lease_until, attempts, created_at);

CREATE INDEX IF NOT EXISTS idx_donations_created
  ON donations(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_donations_username
  ON donations(username);
