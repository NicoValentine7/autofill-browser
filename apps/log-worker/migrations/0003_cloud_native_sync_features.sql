ALTER TABLE user_sync_snapshots ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_sync_snapshots ADD COLUMN device_id TEXT;
ALTER TABLE user_sync_snapshots ADD COLUMN changed_fields_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE user_sync_snapshots ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS remote_rules (
  key TEXT PRIMARY KEY NOT NULL,
  schema_version INTEGER NOT NULL,
  blocked_identity_tokens_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_analysis_reports (
  id TEXT PRIMARY KEY NOT NULL,
  scope_user_id TEXT,
  window_started_at TEXT NOT NULL,
  window_ended_at TEXT NOT NULL,
  total_events INTEGER NOT NULL,
  field_filled_count INTEGER NOT NULL,
  correction_count INTEGER NOT NULL,
  risky_event_count INTEGER NOT NULL,
  top_hostnames_json TEXT NOT NULL,
  top_profile_keys_json TEXT NOT NULL,
  notes_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS log_analysis_reports_scope_created_idx ON log_analysis_reports (scope_user_id, created_at DESC);
