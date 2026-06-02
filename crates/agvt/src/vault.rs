use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroU32;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{AgvtError, Result};
use crate::keychain;
use crate::reference::SecretRef;

pub const DEFAULT_AGENT_VAULT_PATH: &str = ".local/agent-vault.json";
pub const AGVT_PASSPHRASE_ENV: &str = "AGVT_PASSPHRASE";
pub const LEGACY_PASSPHRASE_ENV: &str = "AUTOFILL_AGENT_VAULT_PASSPHRASE";
pub const AGVT_PATH_ENV: &str = "AGVT_PATH";
pub const LEGACY_PATH_ENV: &str = "AUTOFILL_AGENT_VAULT_PATH";

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_KDF_ITERATIONS: u32 = 600_000;
const MIN_KDF_ITERATIONS: u32 = 250_000;
const MAX_KDF_ITERATIONS: u32 = 5_000_000;
const KEY_CHECK_VALUE: &str = "agent-vault-key-check:v1";
const ALGORITHM: &str = "PBKDF2-SHA256/AES-GCM";
const KDF_NAME: &str = "PBKDF2-SHA256";
const MAX_SECRET_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kdf {
    pub name: String,
    pub iterations: u32,
    pub salt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedValue {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub algorithm: String,
    pub iv: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultItem {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub kind: String,
    pub label: String,
    #[serde(rename = "encryptedValue")]
    pub encrypted_value: EncryptedValue,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultFile {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub algorithm: String,
    #[serde(rename = "vaultId")]
    pub vault_id: String,
    pub kdf: Kdf,
    #[serde(rename = "keyCheck")]
    pub key_check: EncryptedValue,
    pub items: BTreeMap<String, VaultItem>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct UpsertTokenInput {
    pub secret_ref: SecretRef,
    pub token: String,
    pub label: Option<String>,
    pub service_url: Option<String>,
    pub account_name: Option<String>,
    pub account_id: Option<String>,
    pub token_id: Option<String>,
    pub expires_on: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpsertSecretInput {
    pub secret_ref: SecretRef,
    pub kind: String,
    pub label: Option<String>,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedItem {
    pub vault: String,
    pub item: String,
    pub kind: String,
    pub label: String,
    pub updated_at: String,
}

fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0_u8; length];
    rng.fill(&mut bytes)
        .map_err(|_| AgvtError::new("secure random generator failed."))?;
    Ok(bytes)
}

fn random_hex(length: usize) -> Result<String> {
    Ok(random_bytes(length)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn now_stamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization should not fail")
}

pub fn validate_item_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "api-token" | "login" | "totp" | "ssh-key" | "custom" | "secret" => Ok(normalized),
        _ => Err(AgvtError::new(
            "kind must be one of api-token, login, totp, ssh-key, custom, or secret.",
        )),
    }
}

pub fn canonical_payload_field(value: &str) -> Result<String> {
    let trimmed = value.trim();
    Ok(match trimmed {
        "service-url" => "serviceUrl".to_owned(),
        "account" | "account-name" => "accountName".to_owned(),
        "account-id" => "accountId".to_owned(),
        "token-id" => "tokenId".to_owned(),
        "expires-on" => "expiresOn".to_owned(),
        "private-key" => "privateKey".to_owned(),
        "public-key" => "publicKey".to_owned(),
        "totp-secret" => "secret".to_owned(),
        "token" | "serviceUrl" | "accountName" | "accountId" | "tokenId" | "expiresOn"
        | "notes" | "secret" | "password" | "username" | "url" | "issuer" | "privateKey"
        | "publicKey" | "passphrase" | "period" | "digits" => trimmed.to_owned(),
        _ => {
            return Err(AgvtError::new(
                "field must be a supported Agent Vault field name.",
            ))
        }
    })
}

fn build_secret_payload(kind: &str, fields: &BTreeMap<String, String>) -> Result<String> {
    let normalized_kind = validate_item_kind(kind)?;
    let mut payload = Map::new();
    payload.insert(
        "schemaVersion".to_owned(),
        Value::Number(serde_json::Number::from(SCHEMA_VERSION)),
    );
    payload.insert("kind".to_owned(), Value::String(normalized_kind));
    for (field, value) in fields {
        let canonical_field = canonical_payload_field(field)?;
        let trimmed_value = value.trim();
        if !trimmed_value.is_empty() {
            payload.insert(canonical_field, Value::String(trimmed_value.to_owned()));
        }
    }
    Ok(serde_json::to_string(&Value::Object(payload))?)
}

fn parse_secret_payload(plaintext: &str) -> Result<(String, BTreeMap<String, String>)> {
    let parsed: Value = serde_json::from_str(plaintext)?;
    let object = parsed
        .as_object()
        .ok_or_else(|| AgvtError::new("Vault item payload is not an object."))?;
    if object.get("schemaVersion").and_then(Value::as_u64) != Some(u64::from(SCHEMA_VERSION)) {
        return Err(AgvtError::new("unsupported Vault item payload schema."));
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AgvtError::new("Vault item payload is missing kind."))?;
    let normalized_kind = validate_item_kind(kind)?;
    let mut fields = BTreeMap::new();
    for (field, value) in object {
        if field == "schemaVersion" || field == "kind" {
            continue;
        }
        if let Some(string_value) = value.as_str() {
            fields.insert(canonical_payload_field(field)?, string_value.to_owned());
        }
    }
    Ok((normalized_kind, fields))
}

fn build_key_check_aad(vault: &VaultFile) -> Vec<u8> {
    format!(
        "[\"key-check\",{},\"{}\",{},{{\"name\":{},\"iterations\":{},\"salt\":{}}}]",
        vault.schema_version,
        vault.algorithm,
        json_string(&vault.vault_id),
        json_string(&vault.kdf.name),
        vault.kdf.iterations,
        json_string(&vault.kdf.salt)
    )
    .into_bytes()
}

fn build_item_aad(vault: &VaultFile, storage_name: &str, kind: &str) -> Vec<u8> {
    format!(
        "[\"item\",{},\"{}\",{},{},{}]",
        vault.schema_version,
        vault.algorithm,
        json_string(&vault.vault_id),
        json_string(storage_name),
        json_string(kind)
    )
    .into_bytes()
}

fn validate_vault(vault: &VaultFile) -> Result<()> {
    if vault.schema_version != SCHEMA_VERSION || vault.algorithm != ALGORITHM {
        return Err(AgvtError::new("unsupported Agent Vault file schema."));
    }
    if vault.kdf.name != KDF_NAME
        || vault.kdf.iterations < MIN_KDF_ITERATIONS
        || vault.kdf.iterations > MAX_KDF_ITERATIONS
        || BASE64
            .decode(&vault.kdf.salt)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
            != 16
    {
        return Err(AgvtError::new("unsupported Agent Vault KDF settings."));
    }
    validate_encrypted_value(&vault.key_check)?;
    for item in vault.items.values() {
        validate_encrypted_value(&item.encrypted_value)?;
    }
    Ok(())
}

fn validate_encrypted_value(value: &EncryptedValue) -> Result<()> {
    let iv_length = BASE64
        .decode(&value.iv)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    let ciphertext_length = BASE64
        .decode(&value.ciphertext)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    if value.schema_version != SCHEMA_VERSION
        || value.algorithm != "AES-GCM"
        || iv_length != 12
        || ciphertext_length < 16
    {
        return Err(AgvtError::new(
            "invalid encrypted value in Agent Vault file.",
        ));
    }
    Ok(())
}

fn derive_key(passphrase: &str, vault: &VaultFile) -> Result<[u8; 32]> {
    let iterations = NonZeroU32::new(vault.kdf.iterations)
        .ok_or_else(|| AgvtError::new("invalid KDF iterations."))?;
    let salt = BASE64
        .decode(&vault.kdf.salt)
        .map_err(|_| AgvtError::new("invalid KDF salt."))?;
    let mut key = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        passphrase.as_bytes(),
        &mut key,
    );
    Ok(key)
}

fn import_aead_key(key_bytes: &[u8; 32]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| AgvtError::new("AES-GCM key import failed."))?;
    Ok(LessSafeKey::new(unbound))
}

fn encrypt_text(plaintext: &str, key: &LessSafeKey, aad: &[u8]) -> Result<EncryptedValue> {
    let iv = random_bytes(12)?;
    let nonce = Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| AgvtError::new("invalid AES-GCM nonce."))?;
    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| AgvtError::new("AES-GCM encryption failed."))?;
    Ok(EncryptedValue {
        schema_version: SCHEMA_VERSION,
        algorithm: "AES-GCM".to_owned(),
        iv: BASE64.encode(iv),
        ciphertext: BASE64.encode(in_out),
    })
}

fn decrypt_text(value: &EncryptedValue, key: &LessSafeKey, aad: &[u8]) -> Result<String> {
    let iv = BASE64
        .decode(&value.iv)
        .map_err(|_| AgvtError::new("invalid AES-GCM IV."))?;
    let nonce = Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| AgvtError::new("invalid AES-GCM nonce."))?;
    let mut in_out = BASE64
        .decode(&value.ciphertext)
        .map_err(|_| AgvtError::new("invalid AES-GCM ciphertext."))?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| AgvtError::new("Agent Vault passphrase did not unlock this vault."))?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| AgvtError::new("decrypted value is not valid UTF-8."))
}

fn create_vault(passphrase: &str) -> Result<VaultFile> {
    let salt = random_bytes(16)?;
    let created_at = now_stamp();
    let mut vault = VaultFile {
        schema_version: SCHEMA_VERSION,
        algorithm: ALGORITHM.to_owned(),
        vault_id: format!("vault-{}", random_hex(16)?),
        kdf: Kdf {
            name: KDF_NAME.to_owned(),
            iterations: DEFAULT_KDF_ITERATIONS,
            salt: BASE64.encode(salt),
        },
        key_check: EncryptedValue {
            schema_version: SCHEMA_VERSION,
            algorithm: "AES-GCM".to_owned(),
            iv: BASE64.encode([0_u8; 12]),
            ciphertext: BASE64.encode([0_u8; 16]),
        },
        items: BTreeMap::new(),
        created_at: created_at.clone(),
        updated_at: created_at,
    };
    let key_bytes = derive_key(passphrase, &vault)?;
    let key = import_aead_key(&key_bytes)?;
    let key_check_plaintext = format!("{KEY_CHECK_VALUE}:{}", vault.vault_id);
    vault.key_check = encrypt_text(&key_check_plaintext, &key, &build_key_check_aad(&vault))?;
    Ok(vault)
}

pub fn validate_passphrase_value(value: &str, source: &str) -> Result<String> {
    let trimmed = value.trim().to_owned();
    if trimmed.len() < 24 {
        return Err(AgvtError::new(format!(
            "{source} must be at least 24 characters."
        )));
    }
    Ok(trimmed)
}

pub fn require_passphrase_for_path(path: &Path) -> Result<String> {
    let value = std::env::var(AGVT_PASSPHRASE_ENV)
        .or_else(|_| std::env::var(LEGACY_PASSPHRASE_ENV))
        .unwrap_or_default();
    if !value.trim().is_empty() {
        return validate_passphrase_value(&value, AGVT_PASSPHRASE_ENV);
    }

    if let Some(passphrase) = keychain::read_passphrase(path)? {
        return validate_passphrase_value(&passphrase, "macOS Keychain passphrase");
    }

    Err(AgvtError::new(format!(
        "{AGVT_PASSPHRASE_ENV} must be set, or store it with `agvt keychain set`."
    )))
}

pub fn default_vault_path() -> String {
    std::env::var(AGVT_PATH_ENV)
        .or_else(|_| std::env::var(LEGACY_PATH_ENV))
        .unwrap_or_else(|_| DEFAULT_AGENT_VAULT_PATH.to_owned())
}

pub fn load_vault(path: &Path) -> Result<Option<VaultFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let vault: VaultFile = serde_json::from_str(&raw)?;
    validate_vault(&vault)?;
    Ok(Some(vault))
}

pub fn save_vault(path: &Path, vault: &VaultFile) -> Result<()> {
    validate_vault(vault)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(
        &temporary_path,
        format!("{}\n", serde_json::to_string_pretty(vault)?),
    )?;
    set_private_permissions(&temporary_path)?;
    fs::rename(&temporary_path, path)?;
    set_private_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn unlock_vault(vault: &VaultFile, passphrase: &str) -> Result<LessSafeKey> {
    let key_bytes = derive_key(passphrase, vault)?;
    let key = import_aead_key(&key_bytes)?;
    let key_check = decrypt_text(&vault.key_check, &key, &build_key_check_aad(vault))?;
    if key_check != format!("{KEY_CHECK_VALUE}:{}", vault.vault_id) {
        return Err(AgvtError::new(
            "Agent Vault passphrase did not unlock this vault.",
        ));
    }
    Ok(key)
}

pub fn upsert_api_token(path: &Path, passphrase: &str, input: UpsertTokenInput) -> Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert("token".to_owned(), input.token);
    if let Some(service_url) = input.service_url {
        fields.insert("serviceUrl".to_owned(), service_url);
    }
    if let Some(account_name) = input.account_name {
        fields.insert("accountName".to_owned(), account_name);
    }
    if let Some(account_id) = input.account_id {
        fields.insert("accountId".to_owned(), account_id);
    }
    if let Some(token_id) = input.token_id {
        fields.insert("tokenId".to_owned(), token_id);
    }
    if let Some(expires_on) = input.expires_on {
        fields.insert("expiresOn".to_owned(), expires_on);
    }
    if let Some(notes) = input.notes {
        fields.insert("notes".to_owned(), notes);
    }

    upsert_secret(
        path,
        passphrase,
        UpsertSecretInput {
            secret_ref: input.secret_ref,
            kind: "api-token".to_owned(),
            label: input.label,
            fields,
        },
    )
}

pub fn upsert_secret(path: &Path, passphrase: &str, input: UpsertSecretInput) -> Result<()> {
    let mut vault = match load_vault(path)? {
        Some(vault) => vault,
        None => create_vault(passphrase)?,
    };
    let key = unlock_vault(&vault, passphrase)?;
    let kind = validate_item_kind(&input.kind)?;
    let storage_name = input.secret_ref.storage_name();
    let existing = vault.items.get(&storage_name);
    let timestamp = now_stamp();

    let mut fields = BTreeMap::new();
    for (field, value) in input.fields {
        let canonical_field = canonical_payload_field(&field)?;
        let trimmed_value = value.trim().to_owned();
        if trimmed_value.len() > MAX_SECRET_BYTES {
            return Err(AgvtError::new("Vault field value is too large."));
        }
        if !trimmed_value.is_empty() {
            fields.insert(canonical_field, trimmed_value);
        }
    }
    let required_field = match kind.as_str() {
        "api-token" => "token",
        "login" => "password",
        "totp" => "secret",
        "ssh-key" => "privateKey",
        "custom" | "secret" => "secret",
        _ => "secret",
    };
    if !fields.contains_key(required_field) {
        return Err(AgvtError::new(format!(
            "{kind} item requires encrypted field `{required_field}`."
        )));
    }
    let payload = build_secret_payload(&kind, &fields)?;
    let encrypted_value = encrypt_text(
        &payload,
        &key,
        &build_item_aad(&vault, &storage_name, &kind),
    )?;
    let item = VaultItem {
        schema_version: SCHEMA_VERSION,
        kind,
        label: input
            .label
            .filter(|value| !value.trim().is_empty())
            .or_else(|| existing.map(|item| item.label.clone()))
            .unwrap_or_else(|| input.secret_ref.item.clone()),
        encrypted_value,
        created_at: existing
            .map(|item| item.created_at.clone())
            .unwrap_or_else(|| timestamp.clone()),
        updated_at: timestamp.clone(),
    };
    vault.items.insert(storage_name, item);
    vault.updated_at = timestamp;
    save_vault(path, &vault)
}

pub fn read_secret_payload(
    path: &Path,
    passphrase: &str,
    secret_ref: &SecretRef,
) -> Result<(String, BTreeMap<String, String>)> {
    let vault =
        load_vault(path)?.ok_or_else(|| AgvtError::new("Agent Vault file does not exist."))?;
    let key = unlock_vault(&vault, passphrase)?;
    let storage_name = secret_ref.storage_name();
    let item = vault
        .items
        .get(&storage_name)
        .ok_or_else(|| AgvtError::new(format!("Vault item not found: {storage_name}")))?;
    let plaintext = decrypt_text(
        &item.encrypted_value,
        &key,
        &build_item_aad(&vault, &storage_name, &item.kind),
    )?;
    parse_secret_payload(&plaintext)
}

pub fn read_secret_field(path: &Path, passphrase: &str, secret_ref: &SecretRef) -> Result<String> {
    let (_kind, fields) = read_secret_payload(path, passphrase, secret_ref)?;
    let field = canonical_payload_field(&secret_ref.field)?;
    Ok(fields.get(&field).cloned().unwrap_or_default())
}

pub fn delete_item(path: &Path, passphrase: &str, secret_ref: &SecretRef) -> Result<()> {
    let mut vault =
        load_vault(path)?.ok_or_else(|| AgvtError::new("Agent Vault file does not exist."))?;
    unlock_vault(&vault, passphrase)?;
    vault.items.remove(&secret_ref.storage_name());
    vault.updated_at = now_stamp();
    save_vault(path, &vault)
}

pub fn list_items(path: &Path) -> Result<Vec<ListedItem>> {
    let Some(vault) = load_vault(path)? else {
        return Ok(Vec::new());
    };
    Ok(vault
        .items
        .iter()
        .map(|(storage_name, item)| {
            let (vault_name, item_name) = storage_name
                .split_once(':')
                .map(|(vault_name, item_name)| (vault_name.to_owned(), item_name.to_owned()))
                .unwrap_or_else(|| ("dev".to_owned(), storage_name.clone()));
            ListedItem {
                vault: vault_name,
                item: item_name,
                kind: item.kind.clone(),
                label: item.label.clone(),
                updated_at: item.updated_at.clone(),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::reference::item_target_to_ref;

    #[test]
    fn stores_values_encrypted_and_reads_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-vault.json");
        let passphrase = "test-passphrase-with-enough-length";
        let secret_ref = item_target_to_ref("agvt://dev/cloudflare/token", "dev", "token").unwrap();

        upsert_api_token(
            &path,
            passphrase,
            UpsertTokenInput {
                secret_ref: secret_ref.clone(),
                token: "dummy-token".to_owned(),
                label: Some("Cloudflare".to_owned()),
                service_url: Some("https://api.cloudflare.com/client/v4".to_owned()),
                account_name: None,
                account_id: Some("account-123".to_owned()),
                token_id: Some("token-123".to_owned()),
                expires_on: Some("2026-12-31T00:00:00Z".to_owned()),
                notes: Some("test note".to_owned()),
            },
        )
        .unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("dummy-token"));
        assert!(!raw.contains("api.cloudflare.com"));
        assert_eq!(
            read_secret_field(&path, passphrase, &secret_ref).unwrap(),
            "dummy-token"
        );
        assert_eq!(
            read_secret_field(
                &path,
                passphrase,
                &item_target_to_ref("agvt://cloudflare/service-url", "dev", "token").unwrap()
            )
            .unwrap(),
            "https://api.cloudflare.com/client/v4"
        );
        assert_eq!(
            read_secret_field(
                &path,
                passphrase,
                &item_target_to_ref("agvt://cloudflare/account-id", "dev", "token").unwrap()
            )
            .unwrap(),
            "account-123"
        );
    }

    #[test]
    fn rejects_wrong_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let path = PathBuf::from(directory.path()).join("agent-vault.json");
        let secret_ref = item_target_to_ref("cloudflare", "dev", "token").unwrap();
        upsert_api_token(
            &path,
            "test-passphrase-with-enough-length",
            UpsertTokenInput {
                secret_ref: secret_ref.clone(),
                token: "dummy-token".to_owned(),
                label: None,
                service_url: None,
                account_name: None,
                account_id: None,
                token_id: None,
                expires_on: None,
                notes: None,
            },
        )
        .unwrap();

        assert!(
            read_secret_field(&path, "wrong-passphrase-with-enough-length", &secret_ref).is_err()
        );
    }
}
