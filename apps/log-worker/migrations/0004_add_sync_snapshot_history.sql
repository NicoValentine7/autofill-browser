CREATE TABLE IF NOT EXISTS user_sync_snapshot_history (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  profile_json TEXT NOT NULL,
  settings_json TEXT NOT NULL,
  domain_policies_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  device_id TEXT,
  changed_fields_json TEXT NOT NULL,
  encryption_version INTEGER NOT NULL DEFAULT 1,
  raw_json TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'save',
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS user_sync_snapshot_history_user_revision_idx ON user_sync_snapshot_history (user_id, revision DESC);
CREATE INDEX IF NOT EXISTS user_sync_snapshot_history_created_idx ON user_sync_snapshot_history (created_at DESC);
