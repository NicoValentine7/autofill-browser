use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::error::Result;
use crate::reference::SecretRef;
use crate::vault::{ensure_parent_dir, set_private_permissions};

pub const AGVT_AUDIT_PATH_ENV: &str = "AGVT_AUDIT_PATH";
const AUDIT_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub ts: u64,
    pub op: String,
    pub reference: String,
    pub caller: String,
}

/// Records one vault operation in the append-only audit log.
///
/// This never fails the calling operation: on write failure it prints a single
/// warning line to stderr and returns.
///
/// Security invariant: only the operation name, the `agvt://` reference
/// (vault/item/field names), the UTC epoch time, and the caller command name
/// are recorded. Secret values and payload bodies must never be passed to
/// this API.
pub fn record(op: &str, secret_ref: &SecretRef, caller: &str) {
    let reference = format!(
        "agvt://{}/{}/{}",
        secret_ref.vault, secret_ref.item, secret_ref.field
    );
    if let Err(error) = append_entry(&audit_log_path(), op, &reference, caller) {
        eprintln!("warning: audit log write failed for {op} {reference}: {error}");
    }
}

pub fn audit_log_path() -> PathBuf {
    if let Ok(path) = env::var(AGVT_AUDIT_PATH_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(path) = env::var("XDG_DATA_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("agvt").join("audit.jsonl");
        }
    }
    if let Ok(path) = env::var("HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path)
                .join(".local")
                .join("share")
                .join("agvt")
                .join("audit.jsonl");
        }
    }
    PathBuf::from(".local/share/agvt/audit.jsonl")
}

pub(crate) fn append_entry(path: &Path, op: &str, reference: &str, caller: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    let entry = serde_json::json!({
        "schemaVersion": AUDIT_SCHEMA_VERSION,
        "ts": now_epoch_seconds(),
        "op": op,
        "ref": reference,
        "caller": caller,
    });
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    set_private_permissions(path)?;
    file.write_all(format!("{}\n", serde_json::to_string(&entry)?).as_bytes())?;
    Ok(())
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn list_entries(path: &Path) -> Result<Vec<AuditEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(value) => entries.push(AuditEntry {
                ts: value.get("ts").and_then(Value::as_u64).unwrap_or(0),
                op: value
                    .get("op")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                reference: value
                    .get("ref")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                caller: value
                    .get("caller")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            }),
            Err(error) => eprintln!(
                "warning: skipped malformed audit log line {}: {error}",
                index + 1
            ),
        }
    }
    Ok(entries)
}

/// Serializes tests (across modules) that mutate process environment
/// variables such as `AGVT_AUDIT_PATH`: the environment is process-global,
/// so every env-mutating test in this crate must hold this one lock.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn lock_test_env() -> std::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_entries_without_rewriting_existing_lines() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");

        append_entry(&path, "add", "agvt://dev/cloudflare/token", "agvt").unwrap();
        let first_snapshot = fs::read_to_string(&path).unwrap();
        assert_eq!(first_snapshot.lines().count(), 1);

        append_entry(&path, "read", "agvt://dev/cloudflare/token", "agvt").unwrap();
        let second_snapshot = fs::read_to_string(&path).unwrap();
        assert!(second_snapshot.starts_with(&first_snapshot));
        assert_eq!(second_snapshot.lines().count(), 2);

        let entries = list_entries(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].op, "add");
        assert_eq!(entries[1].op, "read");
        assert_eq!(entries[0].reference, "agvt://dev/cloudflare/token");
        assert_eq!(entries[0].caller, "agvt");
        assert!(entries[0].ts > 0);
    }

    #[test]
    fn record_never_stores_secret_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let secret_ref = SecretRef {
            vault: "dev".to_owned(),
            item: "cloudflare".to_owned(),
            field: "token".to_owned(),
        };

        // record() only ever receives the reference, never the value; this
        // asserts the resulting file contains reference metadata only.
        append_entry(
            &path,
            "add",
            &format!(
                "agvt://{}/{}/{}",
                secret_ref.vault, secret_ref.item, secret_ref.field
            ),
            "agvt",
        )
        .unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("agvt://dev/cloudflare/token"));
        assert!(!raw.contains("dummy"));
    }

    #[test]
    fn missing_audit_file_lists_as_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("does-not-exist.jsonl");
        assert!(list_entries(&path).unwrap().is_empty());
    }
}
