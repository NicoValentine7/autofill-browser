//! Zero-knowledge sync (`agvt sync init|push|pull`) — ADR 0002/0003 implementation.
//!
//! The client bundles the global vault, dossier, and charter files into one
//! snapshot, encrypts it with a random 32-byte Vault Key (AES-256-GCM), and
//! uploads only ciphertext plus a Vault Recovery Package: the Vault Key
//! wrapped with a high-entropy client-generated Recovery Phrase using
//! PBKDF2-SHA256 (600k iterations) and AES-GCM, with the package metadata
//! (schema, algorithm, KDF params, salt, IV, keyId, syncId, createdAt)
//! authenticated as AAD. The server can authenticate and move the package but
//! never receives the Recovery Phrase, the Vault Key, or any plaintext
//! (ADR 0002 zero-knowledge boundary, ADR 0003 passphrase wrapping).
//!
//! Security invariants:
//! - The Recovery Phrase is printed exactly once, at `sync init`, and is
//!   never logged, audited, or sent anywhere.
//! - `pull` is three-staged: back up existing files, download and verify the
//!   decrypted content into temp files, then atomically rename. A failure at
//!   any stage before the renames leaves every existing file untouched.
//! - schemaVersion mismatches are explicit errors, never silent overwrites.

use std::env;
use std::fs;
use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::aead::{Aad, Nonce};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::audit;
use crate::charter::{self, CharterFile};
use crate::dossier;
use crate::error::{AgvtError, Result};
use crate::reference::{parse_secret_ref, SecretRef};
use crate::vault::{
    acquire_vault_write_lock, derive_key, ensure_parent_dir, import_aead_key, now_stamp,
    random_bytes, random_hex, require_passphrase_for_path, set_private_permissions, validate_kdf,
    Kdf, DEFAULT_KDF_ITERATIONS, KDF_NAME,
};
use crate::{path_for_secret_ref, read_stdin, GlobalOptions};

pub const AGVT_SYNC_URL_ENV: &str = "AGVT_SYNC_URL";
pub const AGVT_SYNC_PATH_ENV: &str = "AGVT_SYNC_PATH";
pub const AGVT_SYNC_TOKEN_ENV: &str = "AGVT_SYNC_TOKEN";
pub const AGVT_SYNC_TOKEN_REF_ENV: &str = "AGVT_SYNC_TOKEN_REF";
const AGVT_CURL_PATH_ENV: &str = "AGVT_CURL_PATH";

const DEFAULT_SYNC_TOKEN_REF: &str = "agvt://global/cloudflare/token";
const SYNC_SCHEMA_VERSION: u8 = 1;
const WRAP_ALGORITHM: &str = "PBKDF2-SHA256/AES-GCM";
const SNAPSHOT_ALGORITHM: &str = "AES-GCM";
/// Domain-separated fixed salt for deriving the account id from the Recovery
/// Phrase. One-way (PBKDF2, high-entropy input), so the server-visible id
/// never reveals the phrase, while a user restoring on a new machine only
/// needs the phrase itself.
const SYNC_ID_SALT: &str = "agvt-sync-account-id:v1";
const PHRASE_PREFIX: &str = "agvt1";
const PHRASE_RANDOM_BYTES: usize = 20; // 160 bits of entropy.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

const SNAPSHOT_FILE_LABELS: [&str; 3] = ["vault", "dossier", "charter"];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RecoveryPackage {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "syncId")]
    pub sync_id: String,
    pub algorithm: String,
    pub kdf: Kdf,
    pub iv: String,
    pub ciphertext: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LocalKeyWrap {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    algorithm: String,
    kdf: Kdf,
    iv: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SnapshotEnvelope {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub algorithm: String,
    pub iv: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SyncStateFile {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    #[serde(rename = "syncId")]
    sync_id: String,
    #[serde(rename = "keyId")]
    key_id: String,
    /// Vault Key wrapped with a key derived from the vault passphrase, so
    /// day-to-day pushes never need the Recovery Phrase. Absent when the
    /// passphrase was unavailable during a phrase-based pull.
    #[serde(rename = "localKey", skip_serializing_if = "Option::is_none")]
    local_key: Option<LocalKeyWrap>,
    recovery: RecoveryPackage,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

pub(crate) fn handle_sync(options: &GlobalOptions) -> Result<()> {
    match options.args.first().map(String::as_str) {
        Some("init") => handle_sync_init(options),
        Some("push") => handle_sync_push(options),
        Some("pull") => handle_sync_pull(options, &options.args[1..]),
        _ => Err(AgvtError::new("sync requires init, push, or pull.")),
    }
}

// ---------------------------------------------------------------------------
// Paths and environment
// ---------------------------------------------------------------------------

pub(crate) fn sync_state_path() -> PathBuf {
    if let Ok(path) = env::var(AGVT_SYNC_PATH_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(path) = env::var("XDG_DATA_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("agvt").join("sync.json");
        }
    }
    if let Ok(path) = env::var("HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path)
                .join(".local")
                .join("share")
                .join("agvt")
                .join("sync.json");
        }
    }
    PathBuf::from(".local/share/agvt/sync.json")
}

fn resolve_sync_url() -> Result<String> {
    let value = env::var(AGVT_SYNC_URL_ENV).unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AgvtError::new(format!(
            "{AGVT_SYNC_URL_ENV} must be set to the sync worker endpoint. \
             There is no default: the production URL is never hardcoded."
        )));
    }
    Ok(trimmed.trim_end_matches('/').to_owned())
}

/// Resolves the bearer token for the sync worker without ever printing it.
///
/// Order: `AGVT_SYNC_TOKEN` (needed for cold-start pulls where no vault
/// exists yet), then a vault reference (`AGVT_SYNC_TOKEN_REF`, default
/// `agvt://global/cloudflare/token`).
fn resolve_sync_token(options: &GlobalOptions) -> Result<String> {
    if let Ok(value) = env::var(AGVT_SYNC_TOKEN_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    let reference_text =
        env::var(AGVT_SYNC_TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_SYNC_TOKEN_REF.to_owned());
    let secret_ref = parse_secret_ref(reference_text.trim(), &options.default_vault)?;
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;
    let token = crate::vault::read_secret_field(vault_path, &passphrase, &secret_ref)?;
    if token.trim().is_empty() {
        return Err(AgvtError::new(format!(
            "sync token reference {reference_text} resolved to an empty value. \
             Set {AGVT_SYNC_TOKEN_ENV} or store a token at the reference."
        )));
    }
    Ok(token.trim().to_owned())
}

// ---------------------------------------------------------------------------
// Recovery Phrase, sync id, and key wrapping (ADR 0003)
// ---------------------------------------------------------------------------

fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }
    output
}

/// Generates a high-entropy Recovery Phrase: 160 random bits rendered as
/// base32 in dash-separated groups, e.g. `agvt1-c3n4-...`. Generated on the
/// client, shown once, never sent to the server, never logged (ADR 0003).
fn generate_recovery_phrase() -> Result<String> {
    let encoded = base32_encode(&random_bytes(PHRASE_RANDOM_BYTES)?);
    let groups: Vec<String> = encoded
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    Ok(format!("{PHRASE_PREFIX}-{}", groups.join("-")))
}

fn validate_recovery_phrase(value: &str) -> Result<String> {
    let trimmed = value.trim().to_owned();
    if !trimmed.starts_with(PHRASE_PREFIX) || trimmed.len() < 24 {
        return Err(AgvtError::new(
            "the Recovery Phrase does not look like an agvt sync phrase.",
        ));
    }
    Ok(trimmed)
}

/// Derives the server-visible account id from the Recovery Phrase with a
/// domain-separated fixed salt. One-way; a user restoring on a new machine
/// needs to remember only the phrase.
fn derive_sync_id(phrase: &str) -> Result<String> {
    let iterations = NonZeroU32::new(DEFAULT_KDF_ITERATIONS)
        .ok_or_else(|| AgvtError::new("invalid KDF iterations."))?;
    let mut output = [0_u8; 16];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        SYNC_ID_SALT.as_bytes(),
        phrase.as_bytes(),
        &mut output,
    );
    Ok(output.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization should not fail")
}

fn kdf_json(kdf: &Kdf) -> String {
    format!(
        "{{\"name\":{},\"iterations\":{},\"salt\":{}}}",
        json_string(&kdf.name),
        kdf.iterations,
        json_string(&kdf.salt)
    )
}

/// AAD for the Vault Recovery Package. Authenticates schema, algorithm, KDF
/// params, salt, IV, keyId, syncId, and createdAt, so restore rejects
/// tampered metadata (ADR 0003).
fn recovery_package_aad(
    kdf: &Kdf,
    iv: &str,
    key_id: &str,
    sync_id: &str,
    created_at: &str,
) -> Vec<u8> {
    format!(
        "[\"sync-recovery\",{SYNC_SCHEMA_VERSION},\"{WRAP_ALGORITHM}\",{},{},{},{},{}]",
        kdf_json(kdf),
        json_string(iv),
        json_string(key_id),
        json_string(sync_id),
        json_string(created_at)
    )
    .into_bytes()
}

fn local_key_aad(kdf: &Kdf, iv: &str, key_id: &str, sync_id: &str) -> Vec<u8> {
    format!(
        "[\"sync-local-key\",{SYNC_SCHEMA_VERSION},\"{WRAP_ALGORITHM}\",{},{},{},{}]",
        kdf_json(kdf),
        json_string(iv),
        json_string(key_id),
        json_string(sync_id)
    )
    .into_bytes()
}

fn snapshot_aad(iv: &str, key_id: &str, sync_id: &str, created_at: &str) -> Vec<u8> {
    format!(
        "[\"sync-snapshot\",{SYNC_SCHEMA_VERSION},\"{SNAPSHOT_ALGORITHM}\",{},{},{},{}]",
        json_string(iv),
        json_string(key_id),
        json_string(sync_id),
        json_string(created_at)
    )
    .into_bytes()
}

fn seal_bytes(plaintext: &[u8], key_bytes: &[u8; 32], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = import_aead_key(key_bytes)?;
    let nonce = Nonce::try_assume_unique_for_key(iv)
        .map_err(|_| AgvtError::new("invalid AES-GCM nonce."))?;
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| AgvtError::new("AES-GCM encryption failed."))?;
    Ok(in_out)
}

fn open_bytes(ciphertext: &[u8], key_bytes: &[u8; 32], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = import_aead_key(key_bytes)?;
    let nonce = Nonce::try_assume_unique_for_key(iv)
        .map_err(|_| AgvtError::new("invalid AES-GCM nonce."))?;
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| {
            AgvtError::new("sync data could not be decrypted (wrong key, phrase, or tampering).")
        })?;
    Ok(plaintext.to_vec())
}

fn new_wrap_kdf() -> Result<Kdf> {
    Ok(Kdf {
        name: KDF_NAME.to_owned(),
        iterations: DEFAULT_KDF_ITERATIONS,
        salt: BASE64.encode(random_bytes(16)?),
    })
}

/// The wrapped plaintext carries its own keyId so restore can require the
/// unwrapped Vault Key keyId to match the package keyId (ADR 0003).
fn wrapped_key_plaintext(vault_key: &[u8; 32], key_id: &str) -> String {
    format!(
        "{{\"schemaVersion\":{SYNC_SCHEMA_VERSION},\"keyId\":{},\"key\":{}}}",
        json_string(key_id),
        json_string(&BASE64.encode(vault_key))
    )
}

fn parse_wrapped_key(plaintext: &[u8], expected_key_id: &str) -> Result<[u8; 32]> {
    let parsed: Value = serde_json::from_slice(plaintext)
        .map_err(|_| AgvtError::new("unwrapped sync key payload is not valid JSON."))?;
    if parsed.get("schemaVersion").and_then(Value::as_u64) != Some(u64::from(SYNC_SCHEMA_VERSION)) {
        return Err(AgvtError::new("unsupported sync key payload schema."));
    }
    if parsed.get("keyId").and_then(Value::as_str) != Some(expected_key_id) {
        return Err(AgvtError::new(
            "unwrapped Vault Key keyId does not match the package keyId.",
        ));
    }
    let key_b64 = parsed
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| AgvtError::new("sync key payload is missing the key."))?;
    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|_| AgvtError::new("sync key payload is not valid base64."))?;
    key_bytes
        .try_into()
        .map_err(|_| AgvtError::new("sync key payload has the wrong key length."))
}

fn wrap_vault_key_with_phrase(
    vault_key: &[u8; 32],
    phrase: &str,
    key_id: &str,
    sync_id: &str,
    created_at: &str,
) -> Result<RecoveryPackage> {
    let kdf = new_wrap_kdf()?;
    let wrap_key = derive_key(phrase, &kdf)?;
    let iv_bytes = random_bytes(12)?;
    let iv = BASE64.encode(&iv_bytes);
    let aad = recovery_package_aad(&kdf, &iv, key_id, sync_id, created_at);
    let ciphertext = seal_bytes(
        wrapped_key_plaintext(vault_key, key_id).as_bytes(),
        &wrap_key,
        &iv_bytes,
        &aad,
    )?;
    Ok(RecoveryPackage {
        schema_version: SYNC_SCHEMA_VERSION,
        key_id: key_id.to_owned(),
        sync_id: sync_id.to_owned(),
        algorithm: WRAP_ALGORITHM.to_owned(),
        kdf,
        iv,
        ciphertext: BASE64.encode(ciphertext),
        created_at: created_at.to_owned(),
    })
}

fn validate_recovery_package(package: &RecoveryPackage) -> Result<()> {
    if package.schema_version != SYNC_SCHEMA_VERSION {
        return Err(AgvtError::new(format!(
            "sync recovery package schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}).",
            package.schema_version
        )));
    }
    if package.algorithm != WRAP_ALGORITHM {
        return Err(AgvtError::new(
            "unsupported sync recovery package algorithm.",
        ));
    }
    validate_kdf(&package.kdf)
}

fn unwrap_vault_key_from_recovery(package: &RecoveryPackage, phrase: &str) -> Result<[u8; 32]> {
    validate_recovery_package(package)?;
    let wrap_key = derive_key(phrase, &package.kdf)?;
    let iv_bytes = BASE64
        .decode(&package.iv)
        .map_err(|_| AgvtError::new("invalid recovery package IV."))?;
    let ciphertext = BASE64
        .decode(&package.ciphertext)
        .map_err(|_| AgvtError::new("invalid recovery package ciphertext."))?;
    let aad = recovery_package_aad(
        &package.kdf,
        &package.iv,
        &package.key_id,
        &package.sync_id,
        &package.created_at,
    );
    let plaintext = open_bytes(&ciphertext, &wrap_key, &iv_bytes, &aad).map_err(|_| {
        AgvtError::new(
            "the Recovery Phrase did not unlock this snapshot (wrong phrase or tampered package).",
        )
    })?;
    parse_wrapped_key(&plaintext, &package.key_id)
}

fn wrap_vault_key_with_passphrase(
    vault_key: &[u8; 32],
    passphrase: &str,
    key_id: &str,
    sync_id: &str,
) -> Result<LocalKeyWrap> {
    let kdf = new_wrap_kdf()?;
    let wrap_key = derive_key(passphrase, &kdf)?;
    let iv_bytes = random_bytes(12)?;
    let iv = BASE64.encode(&iv_bytes);
    let aad = local_key_aad(&kdf, &iv, key_id, sync_id);
    let ciphertext = seal_bytes(
        wrapped_key_plaintext(vault_key, key_id).as_bytes(),
        &wrap_key,
        &iv_bytes,
        &aad,
    )?;
    Ok(LocalKeyWrap {
        schema_version: SYNC_SCHEMA_VERSION,
        algorithm: WRAP_ALGORITHM.to_owned(),
        kdf,
        iv,
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn unwrap_vault_key_from_local(state: &SyncStateFile, passphrase: &str) -> Result<[u8; 32]> {
    let Some(local) = &state.local_key else {
        return Err(AgvtError::new(
            "sync state has no local key wrap. Re-link this machine with \
             `agvt sync pull --recovery-phrase-stdin` while the vault passphrase is available.",
        ));
    };
    if local.schema_version != SYNC_SCHEMA_VERSION || local.algorithm != WRAP_ALGORITHM {
        return Err(AgvtError::new("unsupported sync local key wrap."));
    }
    validate_kdf(&local.kdf)?;
    let wrap_key = derive_key(passphrase, &local.kdf)?;
    let iv_bytes = BASE64
        .decode(&local.iv)
        .map_err(|_| AgvtError::new("invalid sync local key IV."))?;
    let ciphertext = BASE64
        .decode(&local.ciphertext)
        .map_err(|_| AgvtError::new("invalid sync local key ciphertext."))?;
    let aad = local_key_aad(&local.kdf, &local.iv, &state.key_id, &state.sync_id);
    let plaintext = open_bytes(&ciphertext, &wrap_key, &iv_bytes, &aad).map_err(|_| {
        AgvtError::new(
            "the vault passphrase did not unlock the sync key (was the passphrase changed?). \
             Re-link with `agvt sync pull --recovery-phrase-stdin`.",
        )
    })?;
    parse_wrapped_key(&plaintext, &state.key_id)
}

// ---------------------------------------------------------------------------
// Sync state file
// ---------------------------------------------------------------------------

fn load_sync_state(path: &Path) -> Result<Option<SyncStateFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let state: SyncStateFile = serde_json::from_str(&raw)
        .map_err(|error| AgvtError::new(format!("sync state file is unreadable: {error}")))?;
    if state.schema_version != SYNC_SCHEMA_VERSION {
        return Err(AgvtError::new(format!(
            "sync state schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}).",
            state.schema_version
        )));
    }
    Ok(Some(state))
}

fn save_sync_state(path: &Path, state: &SyncStateFile) -> Result<()> {
    ensure_parent_dir(path)?;
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(
        &temporary_path,
        format!("{}\n", serde_json::to_string_pretty(state)?),
    )?;
    set_private_permissions(&temporary_path)?;
    fs::rename(&temporary_path, path)?;
    set_private_permissions(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshot content
// ---------------------------------------------------------------------------

fn snapshot_targets(options: &GlobalOptions) -> Vec<(String, PathBuf)> {
    vec![
        ("vault".to_owned(), options.global_vault_path.clone()),
        ("dossier".to_owned(), dossier::dossier_path()),
        ("charter".to_owned(), charter::charter_path()),
    ]
}

/// Builds the plaintext snapshot JSON from the local files. File contents are
/// carried as base64 so the snapshot is byte-exact on restore.
fn build_snapshot_plaintext(
    targets: &[(String, PathBuf)],
    created_at: &str,
) -> Result<(String, Vec<String>)> {
    let mut files = Map::new();
    let mut included = Vec::new();
    for (label, path) in targets {
        if path.exists() {
            let bytes = fs::read(path)?;
            let mut entry = Map::new();
            entry.insert("encoding".to_owned(), Value::String("base64".to_owned()));
            entry.insert("content".to_owned(), Value::String(BASE64.encode(&bytes)));
            files.insert(label.clone(), Value::Object(entry));
            included.push(label.clone());
        } else {
            files.insert(label.clone(), Value::Null);
        }
    }
    if included.is_empty() {
        return Err(AgvtError::new(
            "nothing to push: no vault, dossier, or charter file exists locally.",
        ));
    }
    let mut root = Map::new();
    root.insert(
        "schemaVersion".to_owned(),
        Value::Number(serde_json::Number::from(SYNC_SCHEMA_VERSION)),
    );
    root.insert("createdAt".to_owned(), Value::String(created_at.to_owned()));
    root.insert("files".to_owned(), Value::Object(files));
    Ok((serde_json::to_string(&Value::Object(root))?, included))
}

fn encrypt_snapshot(
    plaintext: &str,
    vault_key: &[u8; 32],
    key_id: &str,
    sync_id: &str,
    created_at: &str,
) -> Result<SnapshotEnvelope> {
    let iv_bytes = random_bytes(12)?;
    let iv = BASE64.encode(&iv_bytes);
    let aad = snapshot_aad(&iv, key_id, sync_id, created_at);
    let ciphertext = seal_bytes(plaintext.as_bytes(), vault_key, &iv_bytes, &aad)?;
    Ok(SnapshotEnvelope {
        schema_version: SYNC_SCHEMA_VERSION,
        algorithm: SNAPSHOT_ALGORITHM.to_owned(),
        iv,
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_snapshot(
    envelope: &SnapshotEnvelope,
    vault_key: &[u8; 32],
    key_id: &str,
    sync_id: &str,
    created_at: &str,
) -> Result<String> {
    if envelope.schema_version != SYNC_SCHEMA_VERSION {
        return Err(AgvtError::new(format!(
            "sync snapshot schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}). \
             Refusing to overwrite local files; upgrade agvt instead.",
            envelope.schema_version
        )));
    }
    if envelope.algorithm != SNAPSHOT_ALGORITHM {
        return Err(AgvtError::new("unsupported sync snapshot algorithm."));
    }
    let iv_bytes = BASE64
        .decode(&envelope.iv)
        .map_err(|_| AgvtError::new("invalid sync snapshot IV."))?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| AgvtError::new("invalid sync snapshot ciphertext."))?;
    let aad = snapshot_aad(&envelope.iv, key_id, sync_id, created_at);
    let plaintext = open_bytes(&ciphertext, vault_key, &iv_bytes, &aad)?;
    String::from_utf8(plaintext)
        .map_err(|_| AgvtError::new("decrypted sync snapshot is not valid UTF-8."))
}

fn build_push_body(
    state: &SyncStateFile,
    envelope: &SnapshotEnvelope,
    created_at: &str,
) -> Result<Value> {
    Ok(serde_json::json!({
        "schemaVersion": SYNC_SCHEMA_VERSION,
        "syncId": state.sync_id,
        "keyId": state.key_id,
        "createdAt": created_at,
        "snapshot": serde_json::to_value(envelope)?,
        "recovery": serde_json::to_value(&state.recovery)?,
    }))
}

/// Verifies restored bytes parse as the expected file type before any local
/// file is replaced. This is the "verify" half of the three-stage pull.
fn validate_restored_content(label: &str, bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AgvtError::new(format!("restored {label} file is not valid UTF-8.")))?;
    match label {
        "vault" => {
            serde_json::from_str::<crate::vault::VaultFile>(text).map_err(|error| {
                AgvtError::new(format!("restored vault file is invalid: {error}"))
            })?;
        }
        "dossier" => {
            serde_json::from_str::<dossier::DossierFile>(text).map_err(|error| {
                AgvtError::new(format!("restored dossier file is invalid: {error}"))
            })?;
        }
        "charter" => {
            serde_json::from_str::<CharterFile>(text).map_err(|error| {
                AgvtError::new(format!("restored charter file is invalid: {error}"))
            })?;
        }
        _ => {
            return Err(AgvtError::new(format!(
                "unknown snapshot file label: {label}"
            )))
        }
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|file_name| format!("{}.bak", file_name.to_string_lossy()))
        .unwrap_or_else(|| "sync-restore.bak".to_owned());
    path.with_file_name(name)
}

fn temp_restore_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|file_name| {
            format!(
                "{}.sync-tmp-{}",
                file_name.to_string_lossy(),
                std::process::id()
            )
        })
        .unwrap_or_else(|| format!("sync-restore.tmp-{}", std::process::id()));
    path.with_file_name(name)
}

/// Applies a decrypted snapshot with the mandatory three-stage safety design:
/// 1. back up every existing target to `<name>.bak`,
/// 2. write and verify all restored content in temp files,
/// 3. atomically rename the temp files into place, only after every file
///    verified. A failure in stage 1-2 leaves all existing files untouched.
fn apply_snapshot(plaintext: &str, targets: &[(String, PathBuf)]) -> Result<Vec<String>> {
    let parsed: Value = serde_json::from_str(plaintext)
        .map_err(|_| AgvtError::new("sync snapshot payload is not valid JSON."))?;
    let schema = parsed.get("schemaVersion").and_then(Value::as_u64);
    if schema != Some(u64::from(SYNC_SCHEMA_VERSION)) {
        return Err(AgvtError::new(format!(
            "sync snapshot payload schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}). \
             Refusing to overwrite local files; upgrade agvt instead.",
            schema.map(|value| value.to_string()).unwrap_or_else(|| "<missing>".to_owned())
        )));
    }
    let files = parsed
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| AgvtError::new("sync snapshot payload is missing files."))?;
    for label in files.keys() {
        if !SNAPSHOT_FILE_LABELS.contains(&label.as_str()) {
            return Err(AgvtError::new(format!(
                "sync snapshot contains an unknown file label: {label}. \
                 A newer agvt may be required; refusing to restore."
            )));
        }
    }

    // Stage 0: decode and validate everything in memory first.
    let mut staged: Vec<(String, PathBuf, Vec<u8>)> = Vec::new();
    for (label, path) in targets {
        let Some(entry) = files.get(label) else {
            continue;
        };
        if entry.is_null() {
            continue;
        }
        let content = entry
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AgvtError::new(format!("snapshot file {label} is missing its content."))
            })?;
        if entry.get("encoding").and_then(Value::as_str) != Some("base64") {
            return Err(AgvtError::new(format!(
                "snapshot file {label} uses an unsupported encoding."
            )));
        }
        let bytes = BASE64
            .decode(content)
            .map_err(|_| AgvtError::new(format!("snapshot file {label} is not valid base64.")))?;
        validate_restored_content(label, &bytes)?;
        staged.push((label.clone(), path.clone(), bytes));
    }
    if staged.is_empty() {
        return Err(AgvtError::new(
            "sync snapshot contains no files to restore.",
        ));
    }

    // Stage 1: back up existing files.
    for (_, path, _) in &staged {
        if path.exists() {
            let backup = backup_path(path);
            fs::copy(path, &backup)?;
            set_private_permissions(&backup)?;
        }
    }

    // Stage 2: write temp files; clean them up on any failure.
    let mut temps: Vec<(PathBuf, PathBuf)> = Vec::new();
    let write_result = (|| -> Result<()> {
        for (_, path, bytes) in &staged {
            ensure_parent_dir(path)?;
            let temp = temp_restore_path(path);
            fs::write(&temp, bytes)?;
            set_private_permissions(&temp)?;
            temps.push((temp, path.clone()));
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        for (temp, _) in &temps {
            let _ = fs::remove_file(temp);
        }
        return Err(error);
    }

    // Stage 3: atomic renames, only after every file was written and verified.
    for (temp, path) in &temps {
        fs::rename(temp, path)?;
        set_private_permissions(path)?;
    }
    Ok(staged.into_iter().map(|(label, _, _)| label).collect())
}

// ---------------------------------------------------------------------------
// HTTP transport (curl subprocess, same discipline as cloudflare.rs: the
// bearer token goes through a stdin-fed config, never through argv)
// ---------------------------------------------------------------------------

fn curl_path() -> String {
    env::var(AGVT_CURL_PATH_ENV).unwrap_or_else(|_| "curl".to_owned())
}

fn curl_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn temp_file_path(tag: &str) -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!(
        "agvt-sync-{tag}-{}-{timestamp}",
        std::process::id()
    ))
}

fn http_json(method: &str, url: &str, bearer: &str, body: Option<&Value>) -> Result<(u16, Value)> {
    let response_path = temp_file_path("response");
    let mut body_path: Option<PathBuf> = None;
    let mut config = format!(
        "silent\nshow-error\nrequest = \"{}\"\nurl = \"{}\"\nheader = \"Authorization: Bearer {}\"\noutput = \"{}\"\nwrite-out = \"%{{http_code}}\"\n",
        curl_escape(method),
        curl_escape(url),
        curl_escape(bearer),
        curl_escape(&response_path.display().to_string())
    );
    if let Some(body) = body {
        let path = temp_file_path("body");
        fs::write(&path, serde_json::to_vec(body)?)?;
        set_private_permissions(&path)?;
        config.push_str(&format!(
            "header = \"Content-Type: application/json\"\ndata-binary = \"@{}\"\n",
            curl_escape(&path.display().to_string())
        ));
        body_path = Some(path);
    }

    let mut child = Command::new(curl_path())
        .args(["-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(config.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if let Some(path) = &body_path {
        let _ = fs::remove_file(path);
    }
    let response_raw = fs::read(&response_path).unwrap_or_default();
    let _ = fs::remove_file(&response_path);

    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(AgvtError::new(if message.is_empty() {
            "sync worker request failed.".to_owned()
        } else {
            format!("sync worker request failed: {message}")
        }));
    }
    let status: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| AgvtError::new("sync worker response status was unreadable."))?;
    let value = if response_raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&response_raw)
            .map_err(|_| AgvtError::new("sync worker response was not valid JSON."))?
    };
    Ok((status, value))
}

fn server_error_message(status: u16, body: &Value) -> String {
    let detail = body
        .get("error")
        .and_then(Value::as_str)
        .map(|message| format!(": {message}"))
        .unwrap_or_default();
    format!("sync worker returned HTTP {status}{detail}")
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn sync_audit_ref(sync_id: &str) -> SecretRef {
    SecretRef {
        vault: "sync".to_owned(),
        item: sync_id.to_owned(),
        field: "snapshot".to_owned(),
    }
}

fn handle_sync_init(options: &GlobalOptions) -> Result<()> {
    let state_path = sync_state_path();
    if state_path.exists() {
        return Err(AgvtError::new(format!(
            "sync is already initialized: {}. Remove the file first to rotate the sync key \
             (this abandons snapshots pushed under the old key).",
            state_path.display()
        )));
    }
    let passphrase = require_passphrase_for_path(&options.global_vault_path)?;
    let phrase = generate_recovery_phrase()?;
    let sync_id = derive_sync_id(&phrase)?;
    let key_id = format!("sync-key-{}", random_hex(8)?);
    let vault_key_bytes = random_bytes(32)?;
    let vault_key: [u8; 32] = vault_key_bytes
        .try_into()
        .map_err(|_| AgvtError::new("secure random generator failed."))?;
    let created_at = now_stamp();
    let recovery = wrap_vault_key_with_phrase(&vault_key, &phrase, &key_id, &sync_id, &created_at)?;
    let local_key = wrap_vault_key_with_passphrase(&vault_key, &passphrase, &key_id, &sync_id)?;
    let state = SyncStateFile {
        schema_version: SYNC_SCHEMA_VERSION,
        sync_id: sync_id.clone(),
        key_id,
        local_key: Some(local_key),
        recovery,
        created_at: created_at.clone(),
        updated_at: created_at,
    };
    save_sync_state(&state_path, &state)?;
    audit::record("sync-init", &sync_audit_ref(&sync_id), "agvt");

    // The one and only time the Recovery Phrase is ever shown (ADR 0003).
    println!("Recovery Phrase (shown once — write it down now, it is never shown again):");
    println!();
    println!("  {phrase}");
    println!();
    println!("Anyone with this phrase can decrypt your synced snapshot; agvt never");
    println!("stores it, never sends it to the server, and cannot recover it for you.");
    println!("sync id: {sync_id}");
    println!("saved {}", state_path.display());
    Ok(())
}

fn handle_sync_push(options: &GlobalOptions) -> Result<()> {
    let state_path = sync_state_path();
    let state = load_sync_state(&state_path)?
        .ok_or_else(|| AgvtError::new("sync is not initialized. Run `agvt sync init` first."))?;
    let url = resolve_sync_url()?;
    let passphrase = require_passphrase_for_path(&options.global_vault_path)?;
    let vault_key = unwrap_vault_key_from_local(&state, &passphrase)?;
    let created_at = now_stamp();
    let targets = snapshot_targets(options);
    let (plaintext, included) = build_snapshot_plaintext(&targets, &created_at)?;
    let envelope = encrypt_snapshot(
        &plaintext,
        &vault_key,
        &state.key_id,
        &state.sync_id,
        &created_at,
    )?;
    let body = build_push_body(&state, &envelope, &created_at)?;
    let token = resolve_sync_token(options)?;
    let (status, response) = http_json(
        "PUT",
        &format!("{url}/v1/snapshots/{}", state.sync_id),
        &token,
        Some(&body),
    )?;
    if !(200..300).contains(&status) {
        return Err(AgvtError::new(server_error_message(status, &response)));
    }
    audit::record("sync-push", &sync_audit_ref(&state.sync_id), "agvt");
    println!(
        "pushed encrypted snapshot ({}) for sync id {}",
        included.join(", "),
        state.sync_id
    );
    Ok(())
}

fn handle_sync_pull(options: &GlobalOptions, args: &[String]) -> Result<()> {
    let mut use_phrase = false;
    for argument in args {
        match argument.as_str() {
            "--recovery-phrase-stdin" => use_phrase = true,
            other => {
                return Err(AgvtError::new(format!(
                    "unknown sync pull option: {other}. Supported: --recovery-phrase-stdin."
                )))
            }
        }
    }
    let url = resolve_sync_url()?;
    let state_path = sync_state_path();
    let existing_state = load_sync_state(&state_path)?;

    let phrase = if use_phrase {
        Some(validate_recovery_phrase(&read_stdin()?)?)
    } else {
        None
    };
    let sync_id = match (&phrase, &existing_state) {
        (Some(phrase), _) => derive_sync_id(phrase)?,
        (None, Some(state)) => state.sync_id.clone(),
        (None, None) => {
            return Err(AgvtError::new(
                "sync is not initialized on this machine. Pipe your Recovery Phrase to \
                 `agvt sync pull --recovery-phrase-stdin` to restore.",
            ))
        }
    };

    let token = resolve_sync_token(options)?;
    let (status, response) = http_json(
        "GET",
        &format!("{url}/v1/snapshots/{sync_id}"),
        &token,
        None,
    )?;
    if status == 404 {
        return Err(AgvtError::new(
            "no snapshot exists on the server for this sync id.",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(AgvtError::new(server_error_message(status, &response)));
    }

    let remote_schema = response.get("schemaVersion").and_then(Value::as_u64);
    if remote_schema != Some(u64::from(SYNC_SCHEMA_VERSION)) {
        return Err(AgvtError::new(format!(
            "server snapshot schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}). \
             Refusing to overwrite local files; upgrade agvt instead.",
            remote_schema.map(|value| value.to_string()).unwrap_or_else(|| "<missing>".to_owned())
        )));
    }
    let envelope: SnapshotEnvelope = serde_json::from_value(
        response
            .get("snapshot")
            .cloned()
            .ok_or_else(|| AgvtError::new("server response is missing the snapshot."))?,
    )
    .map_err(|_| AgvtError::new("server snapshot envelope is malformed."))?;
    let recovery: RecoveryPackage = serde_json::from_value(
        response
            .get("recovery")
            .cloned()
            .ok_or_else(|| AgvtError::new("server response is missing the recovery package."))?,
    )
    .map_err(|_| AgvtError::new("server recovery package is malformed."))?;
    let remote_key_id = response
        .get("keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| AgvtError::new("server response is missing keyId."))?
        .to_owned();
    let remote_created_at = response
        .get("createdAt")
        .and_then(Value::as_str)
        .ok_or_else(|| AgvtError::new("server response is missing createdAt."))?
        .to_owned();

    if recovery.sync_id != sync_id {
        return Err(AgvtError::new(
            "server recovery package does not belong to this sync id.",
        ));
    }

    let vault_key = match &phrase {
        Some(phrase) => unwrap_vault_key_from_recovery(&recovery, phrase)?,
        None => {
            let state = existing_state
                .as_ref()
                .expect("state presence was checked when resolving the sync id");
            if state.key_id != remote_key_id {
                return Err(AgvtError::new(
                    "the server snapshot was encrypted under a different key than this machine's \
                     sync state (was sync re-initialized elsewhere?). Pull with \
                     --recovery-phrase-stdin to relink.",
                ));
            }
            let passphrase = require_passphrase_for_path(&options.global_vault_path)?;
            unwrap_vault_key_from_local(state, &passphrase)?
        }
    };

    let plaintext = decrypt_snapshot(
        &envelope,
        &vault_key,
        &remote_key_id,
        &sync_id,
        &remote_created_at,
    )?;

    let targets = snapshot_targets(options);
    // Hold the vault write lock across the restore so a concurrent `agvt add`
    // cannot interleave with the rename stage.
    let _lock = acquire_vault_write_lock(&options.global_vault_path)?;
    let restored = apply_snapshot(&plaintext, &targets)?;

    // Persist / refresh the sync state so future pushes work from this machine.
    if phrase.is_some() {
        let now = now_stamp();
        let local_key = match require_passphrase_for_path(&options.global_vault_path) {
            Ok(passphrase) => Some(wrap_vault_key_with_passphrase(
                &vault_key,
                &passphrase,
                &remote_key_id,
                &sync_id,
            )?),
            Err(_) => {
                eprintln!(
                    "warning: vault passphrase unavailable; sync state was saved without a local \
                     key wrap. `agvt sync push` will ask you to relink once the passphrase is set."
                );
                None
            }
        };
        let state = SyncStateFile {
            schema_version: SYNC_SCHEMA_VERSION,
            sync_id: sync_id.clone(),
            key_id: remote_key_id,
            local_key,
            recovery,
            created_at: existing_state
                .as_ref()
                .map(|state| state.created_at.clone())
                .unwrap_or_else(|| now.clone()),
            updated_at: now,
        };
        save_sync_state(&state_path, &state)?;
    }

    audit::record("sync-pull", &sync_audit_ref(&sync_id), "agvt");
    println!(
        "restored {} from the encrypted snapshot (existing files were backed up as *.bak)",
        restored.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap as TestBTreeMap;

    use super::*;
    use crate::reference::item_target_to_ref;
    use crate::vault::{upsert_secret, UpsertSecretInput};

    const PASSPHRASE: &str = "test-passphrase-with-enough-length";
    const SECRET_MARKER: &str = "super-secret-token-plaintext-marker";
    const DOSSIER_MARKER: &str = "acme-corp-dossier-body-marker";

    struct Fixture {
        _directory: tempfile::TempDir,
        targets: Vec<(String, PathBuf)>,
    }

    fn make_fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("agent-vault.json");
        let secret_ref = item_target_to_ref("agvt://global/example/token", "dev", "token").unwrap();
        let mut fields = TestBTreeMap::new();
        fields.insert("token".to_owned(), SECRET_MARKER.to_owned());
        upsert_secret(
            &vault_path,
            PASSPHRASE,
            UpsertSecretInput {
                secret_ref,
                kind: "api-token".to_owned(),
                label: Some("Example".to_owned()),
                fields,
            },
        )
        .unwrap();
        let dossier_path = directory.path().join("dossier.json");
        fs::write(
            &dossier_path,
            format!(
                "{{\"schemaVersion\":1,\"entries\":{{\"note\":{{\"id\":\"note\",\"topic\":\"{DOSSIER_MARKER}\",\"tags\":[],\"tier\":\"open\",\"body\":\"{DOSSIER_MARKER}\",\"createdAt\":\"0\",\"updatedAt\":\"0\"}}}},\"createdAt\":\"0\",\"updatedAt\":\"0\"}}\n"
            ),
        )
        .unwrap();
        let charter_path = directory.path().join("charter.json");
        fs::write(
            &charter_path,
            "{\"schemaVersion\":1,\"rules\":[{\"capability\":\"commit\",\"scope\":\"*\",\"autonomy\":\"confirm\"}]}\n",
        )
        .unwrap();
        Fixture {
            targets: vec![
                ("vault".to_owned(), vault_path),
                ("dossier".to_owned(), dossier_path),
                ("charter".to_owned(), charter_path),
            ],
            _directory: directory,
        }
    }

    fn make_state(phrase: &str) -> (SyncStateFile, [u8; 32]) {
        let sync_id = derive_sync_id(phrase).unwrap();
        let key_id = format!("sync-key-{}", random_hex(8).unwrap());
        let vault_key: [u8; 32] = random_bytes(32).unwrap().try_into().unwrap();
        let created_at = now_stamp();
        let recovery =
            wrap_vault_key_with_phrase(&vault_key, phrase, &key_id, &sync_id, &created_at).unwrap();
        let local_key =
            wrap_vault_key_with_passphrase(&vault_key, PASSPHRASE, &key_id, &sync_id).unwrap();
        (
            SyncStateFile {
                schema_version: SYNC_SCHEMA_VERSION,
                sync_id,
                key_id,
                local_key: Some(local_key),
                recovery,
                created_at: created_at.clone(),
                updated_at: created_at,
            },
            vault_key,
        )
    }

    fn push_body_for_fixture(
        fixture: &Fixture,
        state: &SyncStateFile,
        vault_key: &[u8; 32],
    ) -> Value {
        let created_at = now_stamp();
        let (plaintext, included) =
            build_snapshot_plaintext(&fixture.targets, &created_at).unwrap();
        assert_eq!(included, vec!["vault", "dossier", "charter"]);
        let envelope = encrypt_snapshot(
            &plaintext,
            vault_key,
            &state.key_id,
            &state.sync_id,
            &created_at,
        )
        .unwrap();
        build_push_body(state, &envelope, &created_at).unwrap()
    }

    /// Simulates the pull decrypt+apply pipeline against a previously pushed
    /// body, exactly as the HTTP handler does after the GET.
    fn pull_from_body(
        body: &Value,
        phrase: &str,
        targets: &[(String, PathBuf)],
    ) -> Result<Vec<String>> {
        let schema = body.get("schemaVersion").and_then(Value::as_u64);
        if schema != Some(u64::from(SYNC_SCHEMA_VERSION)) {
            return Err(AgvtError::new(format!(
                "server snapshot schemaVersion {} is not supported by this agvt (expected {SYNC_SCHEMA_VERSION}).",
                schema.map(|value| value.to_string()).unwrap_or_else(|| "<missing>".to_owned())
            )));
        }
        let envelope: SnapshotEnvelope =
            serde_json::from_value(body.get("snapshot").cloned().unwrap()).unwrap();
        let recovery: RecoveryPackage =
            serde_json::from_value(body.get("recovery").cloned().unwrap()).unwrap();
        let vault_key = unwrap_vault_key_from_recovery(&recovery, phrase)?;
        let plaintext = decrypt_snapshot(
            &envelope,
            &vault_key,
            body.get("keyId").and_then(Value::as_str).unwrap(),
            body.get("syncId").and_then(Value::as_str).unwrap(),
            body.get("createdAt").and_then(Value::as_str).unwrap(),
        )?;
        apply_snapshot(&plaintext, targets)
    }

    #[test]
    fn push_pull_roundtrip_restores_identical_bytes_in_empty_environment() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let body = push_body_for_fixture(&fixture, &state, &vault_key);

        // Fresh, empty "machine": none of the three files exist yet.
        let restore_directory = tempfile::tempdir().unwrap();
        let restore_targets: Vec<(String, PathBuf)> = fixture
            .targets
            .iter()
            .map(|(label, path)| {
                (
                    label.clone(),
                    restore_directory.path().join(path.file_name().unwrap()),
                )
            })
            .collect();
        let restored = pull_from_body(&body, &phrase, &restore_targets).unwrap();
        assert_eq!(restored, vec!["vault", "dossier", "charter"]);
        for ((_, original), (_, restored_path)) in fixture.targets.iter().zip(&restore_targets) {
            assert_eq!(
                fs::read(original).unwrap(),
                fs::read(restored_path).unwrap(),
                "restored bytes must match the pushed bytes exactly"
            );
        }
        // The restored vault decrypts with the original vault passphrase.
        let secret_ref = item_target_to_ref("agvt://global/example/token", "dev", "token").unwrap();
        assert_eq!(
            crate::vault::read_secret_field(&restore_targets[0].1, PASSPHRASE, &secret_ref)
                .unwrap(),
            SECRET_MARKER
        );
    }

    #[test]
    fn pull_is_impossible_without_or_with_wrong_recovery_phrase() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let body = push_body_for_fixture(&fixture, &state, &vault_key);

        let restore_directory = tempfile::tempdir().unwrap();
        let targets = vec![(
            "vault".to_owned(),
            restore_directory.path().join("agent-vault.json"),
        )];

        // Wrong phrase: unwrap fails, nothing is written.
        let wrong_phrase = generate_recovery_phrase().unwrap();
        assert!(pull_from_body(&body, &wrong_phrase, &targets).is_err());
        assert!(!targets[0].1.exists());

        // No phrase at all: a random key cannot open the snapshot either.
        let envelope: SnapshotEnvelope =
            serde_json::from_value(body.get("snapshot").cloned().unwrap()).unwrap();
        let random_key: [u8; 32] = random_bytes(32).unwrap().try_into().unwrap();
        assert!(decrypt_snapshot(
            &envelope,
            &random_key,
            body.get("keyId").and_then(Value::as_str).unwrap(),
            body.get("syncId").and_then(Value::as_str).unwrap(),
            body.get("createdAt").and_then(Value::as_str).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn failed_pull_leaves_existing_files_intact() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let mut body = push_body_for_fixture(&fixture, &state, &vault_key);

        // The pull target already has all three files with known content.
        let existing = make_fixture();
        let before: Vec<Vec<u8>> = existing
            .targets
            .iter()
            .map(|(_, path)| fs::read(path).unwrap())
            .collect();

        // Tamper the ciphertext so decryption fails mid-pull.
        let ciphertext = body["snapshot"]["ciphertext"].as_str().unwrap().to_owned();
        let mut corrupted = BASE64.decode(&ciphertext).unwrap();
        corrupted[0] ^= 0xff;
        body["snapshot"]["ciphertext"] = Value::String(BASE64.encode(&corrupted));

        assert!(pull_from_body(&body, &phrase, &existing.targets).is_err());
        for ((_, path), original) in existing.targets.iter().zip(&before) {
            assert_eq!(
                &fs::read(path).unwrap(),
                original,
                "a failed pull must leave existing files byte-identical"
            );
            assert!(
                !temp_restore_path(path).exists(),
                "failed pulls must not leave temp files behind"
            );
        }
    }

    #[test]
    fn corrupt_staged_content_never_replaces_existing_files() {
        // Failure after decryption (invalid restored content) must also leave
        // the existing files untouched — this exercises the verify stage.
        let phrase = generate_recovery_phrase().unwrap();
        let (state, vault_key) = make_state(&phrase);
        let created_at = now_stamp();
        let bogus = format!(
            "{{\"schemaVersion\":1,\"createdAt\":\"{created_at}\",\"files\":{{\"charter\":{{\"encoding\":\"base64\",\"content\":\"{}\"}}}}}}",
            BASE64.encode(b"this is not a charter json")
        );
        let envelope = encrypt_snapshot(
            &bogus,
            &vault_key,
            &state.key_id,
            &state.sync_id,
            &created_at,
        )
        .unwrap();
        let plaintext = decrypt_snapshot(
            &envelope,
            &vault_key,
            &state.key_id,
            &state.sync_id,
            &created_at,
        )
        .unwrap();

        let directory = tempfile::tempdir().unwrap();
        let charter_path = directory.path().join("charter.json");
        fs::write(&charter_path, "{\"schemaVersion\":1,\"rules\":[]}\n").unwrap();
        let before = fs::read(&charter_path).unwrap();
        let targets = vec![("charter".to_owned(), charter_path.clone())];
        assert!(apply_snapshot(&plaintext, &targets).is_err());
        assert_eq!(fs::read(&charter_path).unwrap(), before);
        assert!(
            !backup_path(&charter_path).exists()
                || fs::read(backup_path(&charter_path)).unwrap() == before
        );
    }

    #[test]
    fn successful_pull_backs_up_existing_files() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let body = push_body_for_fixture(&fixture, &state, &vault_key);

        let existing = make_fixture();
        let before: Vec<Vec<u8>> = existing
            .targets
            .iter()
            .map(|(_, path)| fs::read(path).unwrap())
            .collect();
        pull_from_body(&body, &phrase, &existing.targets).unwrap();
        for ((_, path), original) in existing.targets.iter().zip(&before) {
            assert_eq!(
                &fs::read(backup_path(path)).unwrap(),
                original,
                "the pre-pull content must survive as a .bak file"
            );
        }
    }

    #[test]
    fn schema_version_mismatch_is_an_explicit_error() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let mut body = push_body_for_fixture(&fixture, &state, &vault_key);
        body["schemaVersion"] = Value::Number(serde_json::Number::from(99));

        let restore_directory = tempfile::tempdir().unwrap();
        let targets = vec![(
            "vault".to_owned(),
            restore_directory.path().join("agent-vault.json"),
        )];
        let error = pull_from_body(&body, &phrase, &targets).unwrap_err();
        assert!(error.to_string().contains("schemaVersion 99"));
        assert!(!targets[0].1.exists());

        // The inner payload schema is also enforced.
        let error =
            apply_snapshot("{\"schemaVersion\":99,\"files\":{}}", &fixture.targets).unwrap_err();
        assert!(error.to_string().contains("schemaVersion 99"));
    }

    #[test]
    fn push_body_contains_no_plaintext_secret_phrase_or_file_content() {
        let phrase = generate_recovery_phrase().unwrap();
        let fixture = make_fixture();
        let (state, vault_key) = make_state(&phrase);
        let body = push_body_for_fixture(&fixture, &state, &vault_key);
        let serialized = serde_json::to_string(&body).unwrap();

        // This is exactly what crosses the wire and lands in D1: no secret
        // values, no dossier text, no Recovery Phrase, no Vault Key.
        assert!(!serialized.contains(SECRET_MARKER));
        assert!(!serialized.contains(DOSSIER_MARKER));
        assert!(!serialized.contains(&phrase));
        assert!(!serialized.contains(&BASE64.encode(vault_key)));
        // Not even the vault's own internal structure leaks.
        assert!(!serialized.contains("keyCheck"));
        assert!(!serialized.contains("\"items\""));
    }

    #[test]
    fn recovery_package_rejects_tampered_metadata() {
        let phrase = generate_recovery_phrase().unwrap();
        let (state, _vault_key) = make_state(&phrase);
        let mut tampered = state.recovery.clone();
        tampered.created_at = "9999999999".to_owned();
        assert!(unwrap_vault_key_from_recovery(&tampered, &phrase).is_err());

        let mut tampered_key_id = state.recovery.clone();
        tampered_key_id.key_id = "sync-key-attacker".to_owned();
        assert!(unwrap_vault_key_from_recovery(&tampered_key_id, &phrase).is_err());
    }

    #[test]
    fn sync_id_derivation_is_deterministic_and_one_way_shaped() {
        let phrase = generate_recovery_phrase().unwrap();
        let first = derive_sync_id(&phrase).unwrap();
        let second = derive_sync_id(&phrase).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
        let other = derive_sync_id(&generate_recovery_phrase().unwrap()).unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn local_key_wrap_requires_the_vault_passphrase() {
        let phrase = generate_recovery_phrase().unwrap();
        let (state, vault_key) = make_state(&phrase);
        assert_eq!(
            unwrap_vault_key_from_local(&state, PASSPHRASE).unwrap(),
            vault_key
        );
        assert!(
            unwrap_vault_key_from_local(&state, "wrong-passphrase-with-enough-length").is_err()
        );
    }

    #[test]
    fn recovery_phrase_has_expected_shape() {
        let phrase = generate_recovery_phrase().unwrap();
        assert!(phrase.starts_with("agvt1-"));
        // 160 bits -> 32 base32 characters, plus prefix and dashes.
        let body: String = phrase
            .trim_start_matches("agvt1-")
            .chars()
            .filter(|character| *character != '-')
            .collect();
        assert_eq!(body.len(), 32);
        assert!(validate_recovery_phrase(&phrase).is_ok());
        assert!(validate_recovery_phrase("hunter2").is_err());
    }
}
