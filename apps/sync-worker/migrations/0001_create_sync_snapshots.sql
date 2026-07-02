-- Zero-knowledge sync snapshots (ADR 0002/0003, Agent Home U7).
-- The server stores only client-side AES-GCM ciphertext envelopes plus
-- non-secret metadata. No plaintext vault/dossier/charter content, no
-- Vault Key, and no Recovery Phrase ever reach this table.
CREATE TABLE IF NOT EXISTS sync_snapshots (
  account_id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL,
  key_id TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  recovery_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
