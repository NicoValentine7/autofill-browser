CREATE TABLE IF NOT EXISTS event_logs (
  id TEXT PRIMARY KEY NOT NULL,
  timestamp TEXT NOT NULL,
  type TEXT NOT NULL,
  hostname TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  field_signature TEXT,
  profile_key TEXT,
  previous_value TEXT,
  next_value TEXT,
  source TEXT NOT NULL,
  run_id TEXT,
  detail TEXT,
  received_at TEXT NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS event_logs_received_at_idx ON event_logs (received_at DESC);
CREATE INDEX IF NOT EXISTS event_logs_timestamp_idx ON event_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS event_logs_type_idx ON event_logs (type);
CREATE INDEX IF NOT EXISTS event_logs_hostname_idx ON event_logs (hostname);
