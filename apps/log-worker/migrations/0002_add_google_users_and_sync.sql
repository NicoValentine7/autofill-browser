ALTER TABLE event_logs ADD COLUMN user_id TEXT;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,
  google_sub TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  name TEXT,
  picture TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sync_snapshots (
  user_id TEXT PRIMARY KEY NOT NULL,
  schema_version INTEGER NOT NULL,
  profile_json TEXT NOT NULL,
  settings_json TEXT NOT NULL,
  domain_policies_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS event_logs_user_id_idx ON event_logs (user_id);
CREATE INDEX IF NOT EXISTS users_google_sub_idx ON users (google_sub);
