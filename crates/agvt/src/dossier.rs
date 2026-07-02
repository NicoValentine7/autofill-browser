use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::aead::LessSafeKey;
use serde::{Deserialize, Serialize};

use crate::audit;
use crate::error::{AgvtError, Result};
use crate::reference::{validate_name, SecretRef};
use crate::vault::{
    acquire_vault_write_lock, decrypt_text, derive_key, encrypt_text, ensure_parent_dir,
    import_aead_key, now_stamp, random_bytes, random_hex, require_passphrase_for_path,
    set_private_permissions, validate_encrypted_value, validate_kdf, EncryptedValue, Kdf,
    DEFAULT_KDF_ITERATIONS, KDF_NAME,
};
use crate::{read_stdin, take_value, GlobalOptions};

pub const AGVT_DOSSIER_PATH_ENV: &str = "AGVT_DOSSIER_PATH";
const DOSSIER_SCHEMA_VERSION: u8 = 1;
const KEY_CHECK_VALUE: &str = "agvt-dossier-key-check:v1";
const MAX_BODY_BYTES: usize = 256 * 1024;
const DOSSIER_REF_VAULT: &str = "dossier";
const DOSSIER_REF_FIELD: &str = "body";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Tier {
    Open,
    Standard,
    Locked,
}

impl Tier {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "standard" => Ok(Self::Standard),
            "locked" => Ok(Self::Locked),
            _ => Err(AgvtError::new(
                "tier must be one of open, standard, or locked.",
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Standard => "standard",
            Self::Locked => "locked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DossierEntry {
    pub id: String,
    pub topic: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub tier: Tier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(rename = "encryptedBody", skip_serializing_if = "Option::is_none")]
    pub encrypted_body: Option<EncryptedValue>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DossierFile {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<Kdf>,
    #[serde(rename = "keyCheck", skip_serializing_if = "Option::is_none")]
    key_check: Option<EncryptedValue>,
    entries: BTreeMap<String, DossierEntry>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct AddEntryInput {
    pub id: Option<String>,
    pub topic: String,
    pub body: String,
    pub tags: Vec<String>,
    pub tier: Tier,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EditEntryInput {
    pub topic: Option<String>,
    pub body: Option<String>,
    pub tags: Option<Vec<String>>,
    pub tier: Option<Tier>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntrySummary {
    pub id: String,
    pub tier: Tier,
    pub topic: String,
    pub tags: Vec<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ShownEntry {
    pub id: String,
    pub topic: String,
    pub tags: Vec<String>,
    pub tier: Tier,
    pub updated_at: String,
    /// Plaintext body for open/standard entries; always `None` for locked
    /// entries — CLI display flows never decrypt locked bodies (ADR 0014).
    pub body: Option<String>,
    /// `agvt://dossier/<id>/body` reference, present only for locked entries.
    pub body_ref: Option<String>,
}

pub(crate) fn dossier_path() -> PathBuf {
    if let Ok(path) = env::var(AGVT_DOSSIER_PATH_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(path) = env::var("XDG_DATA_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("agvt").join("dossier.json");
        }
    }
    if let Ok(path) = env::var("HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path)
                .join(".local")
                .join("share")
                .join("agvt")
                .join("dossier.json");
        }
    }
    PathBuf::from(".local/share/agvt/dossier.json")
}

pub(crate) fn dossier_body_ref(id: &str) -> SecretRef {
    SecretRef {
        vault: DOSSIER_REF_VAULT.to_owned(),
        item: id.to_owned(),
        field: DOSSIER_REF_FIELD.to_owned(),
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization should not fail")
}

fn key_check_aad(kdf: &Kdf) -> Vec<u8> {
    format!(
        "[\"dossier-key-check\",{},{{\"name\":{},\"iterations\":{},\"salt\":{}}}]",
        DOSSIER_SCHEMA_VERSION,
        json_string(&kdf.name),
        kdf.iterations,
        json_string(&kdf.salt)
    )
    .into_bytes()
}

fn entry_aad(id: &str) -> Vec<u8> {
    format!(
        "[\"dossier-entry\",{},{}]",
        DOSSIER_SCHEMA_VERSION,
        json_string(id)
    )
    .into_bytes()
}

fn new_dossier_file() -> DossierFile {
    let created_at = now_stamp();
    DossierFile {
        schema_version: DOSSIER_SCHEMA_VERSION,
        kdf: None,
        key_check: None,
        entries: BTreeMap::new(),
        created_at: created_at.clone(),
        updated_at: created_at,
    }
}

fn validate_dossier(file: &DossierFile) -> Result<()> {
    if file.schema_version != DOSSIER_SCHEMA_VERSION {
        return Err(AgvtError::new("unsupported dossier file schema."));
    }
    match (&file.kdf, &file.key_check) {
        (Some(kdf), Some(key_check)) => {
            validate_kdf(kdf)?;
            validate_encrypted_value(key_check)?;
        }
        (None, None) => {}
        _ => {
            return Err(AgvtError::new(
                "dossier crypto envelope is incomplete: kdf and keyCheck must both be present.",
            ))
        }
    }
    for (id, entry) in &file.entries {
        if id != &entry.id {
            return Err(AgvtError::new("dossier entry id mismatch."));
        }
        match entry.tier {
            Tier::Locked => {
                let Some(encrypted_body) = &entry.encrypted_body else {
                    return Err(AgvtError::new(
                        "locked dossier entry is missing its encrypted body.",
                    ));
                };
                validate_encrypted_value(encrypted_body)?;
                if entry.body.is_some() {
                    return Err(AgvtError::new(
                        "locked dossier entry must not carry a plaintext body.",
                    ));
                }
                if file.kdf.is_none() {
                    return Err(AgvtError::new(
                        "dossier has locked entries but no crypto envelope.",
                    ));
                }
            }
            Tier::Open | Tier::Standard => {
                if entry.body.is_none() || entry.encrypted_body.is_some() {
                    return Err(AgvtError::new(
                        "open/standard dossier entry must carry a plaintext body only.",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn load_dossier(path: &Path) -> Result<Option<DossierFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let file: DossierFile = serde_json::from_str(&raw)?;
    validate_dossier(&file)?;
    Ok(Some(file))
}

fn save_dossier(path: &Path, file: &DossierFile) -> Result<()> {
    validate_dossier(file)?;
    ensure_parent_dir(path)?;
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(
        &temporary_path,
        format!("{}\n", serde_json::to_string_pretty(file)?),
    )?;
    set_private_permissions(&temporary_path)?;
    fs::rename(&temporary_path, path)?;
    set_private_permissions(path)?;
    Ok(())
}

fn unlock_dossier_key(file: &DossierFile, passphrase: &str) -> Result<LessSafeKey> {
    let (Some(kdf), Some(key_check)) = (&file.kdf, &file.key_check) else {
        return Err(AgvtError::new("dossier has no crypto envelope yet."));
    };
    let key = import_aead_key(&derive_key(passphrase, kdf)?)?;
    let plaintext = decrypt_text(key_check, &key, &key_check_aad(kdf))?;
    if plaintext != KEY_CHECK_VALUE {
        return Err(AgvtError::new("passphrase did not unlock this dossier."));
    }
    Ok(key)
}

fn ensure_dossier_key(file: &mut DossierFile, passphrase: &str) -> Result<LessSafeKey> {
    if file.kdf.is_some() {
        return unlock_dossier_key(file, passphrase);
    }
    let kdf = Kdf {
        name: KDF_NAME.to_owned(),
        iterations: DEFAULT_KDF_ITERATIONS,
        salt: BASE64.encode(random_bytes(16)?),
    };
    let key = import_aead_key(&derive_key(passphrase, &kdf)?)?;
    file.key_check = Some(encrypt_text(KEY_CHECK_VALUE, &key, &key_check_aad(&kdf))?);
    file.kdf = Some(kdf);
    Ok(key)
}

fn validate_body(body: &str) -> Result<()> {
    if body.trim().is_empty() {
        return Err(AgvtError::new("dossier body must not be empty."));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(AgvtError::new("dossier body is too large."));
    }
    Ok(())
}

fn require_locked_passphrase(passphrase: Option<&str>) -> Result<&str> {
    passphrase.ok_or_else(|| AgvtError::new("locked dossier entries require the vault passphrase."))
}

pub(crate) fn add_entry(
    path: &Path,
    input: AddEntryInput,
    passphrase: Option<&str>,
) -> Result<String> {
    validate_body(&input.body)?;
    let topic = input.topic.trim().to_owned();
    if topic.is_empty() {
        return Err(AgvtError::new("dossier topic must not be empty."));
    }
    let _lock = acquire_vault_write_lock(path)?;
    let mut file = load_dossier(path)?.unwrap_or_else(new_dossier_file);
    let id = match input.id {
        Some(id) => {
            let id = validate_name(&id, "dossier id")?;
            if file.entries.contains_key(&id) {
                return Err(AgvtError::new(format!(
                    "dossier entry already exists: {id}. Use `agvt dossier edit`."
                )));
            }
            id
        }
        None => loop {
            let candidate = format!("d-{}", random_hex(4)?);
            if !file.entries.contains_key(&candidate) {
                break candidate;
            }
        },
    };

    let timestamp = now_stamp();
    let (body, encrypted_body) = match input.tier {
        Tier::Locked => {
            let key = ensure_dossier_key(&mut file, require_locked_passphrase(passphrase)?)?;
            (
                None,
                Some(encrypt_text(&input.body, &key, &entry_aad(&id))?),
            )
        }
        Tier::Open | Tier::Standard => (Some(input.body), None),
    };
    file.entries.insert(
        id.clone(),
        DossierEntry {
            id: id.clone(),
            topic,
            tags: normalize_tags(input.tags),
            tier: input.tier,
            body,
            encrypted_body,
            created_at: timestamp.clone(),
            updated_at: timestamp.clone(),
        },
    );
    file.updated_at = timestamp;
    save_dossier(path, &file)?;
    Ok(id)
}

pub(crate) fn edit_entry(
    path: &Path,
    id: &str,
    input: EditEntryInput,
    passphrase: Option<&str>,
) -> Result<()> {
    if let Some(body) = &input.body {
        validate_body(body)?;
    }
    let _lock = acquire_vault_write_lock(path)?;
    let mut file =
        load_dossier(path)?.ok_or_else(|| AgvtError::new("dossier file does not exist."))?;
    let entry = file
        .entries
        .get(id)
        .cloned()
        .ok_or_else(|| AgvtError::new(format!("dossier entry not found: {id}")))?;

    let target_tier = input.tier.unwrap_or(entry.tier);
    if entry.tier == Tier::Locked && target_tier != Tier::Locked && input.body.is_none() {
        return Err(AgvtError::new(
            "changing a locked entry to open/standard requires a new --body or --body-stdin; locked bodies are never decrypted for display or downgrade.",
        ));
    }

    let (body, encrypted_body) = match target_tier {
        Tier::Locked => {
            if let Some(new_body) = &input.body {
                let key = ensure_dossier_key(&mut file, require_locked_passphrase(passphrase)?)?;
                (None, Some(encrypt_text(new_body, &key, &entry_aad(id))?))
            } else if entry.tier == Tier::Locked {
                (None, entry.encrypted_body.clone())
            } else {
                let existing_body = entry
                    .body
                    .clone()
                    .ok_or_else(|| AgvtError::new("dossier entry has no body to encrypt."))?;
                let key = ensure_dossier_key(&mut file, require_locked_passphrase(passphrase)?)?;
                (
                    None,
                    Some(encrypt_text(&existing_body, &key, &entry_aad(id))?),
                )
            }
        }
        Tier::Open | Tier::Standard => (input.body.clone().or(entry.body.clone()), None),
    };

    let timestamp = now_stamp();
    let topic = match input.topic {
        Some(topic) if !topic.trim().is_empty() => topic.trim().to_owned(),
        Some(_) => return Err(AgvtError::new("dossier topic must not be empty.")),
        None => entry.topic.clone(),
    };
    file.entries.insert(
        id.to_owned(),
        DossierEntry {
            id: id.to_owned(),
            topic,
            tags: input.tags.map(normalize_tags).unwrap_or(entry.tags),
            tier: target_tier,
            body,
            encrypted_body,
            created_at: entry.created_at,
            updated_at: timestamp.clone(),
        },
    );
    file.updated_at = timestamp;
    save_dossier(path, &file)
}

pub(crate) fn remove_entry(path: &Path, id: &str) -> Result<()> {
    let _lock = acquire_vault_write_lock(path)?;
    let mut file =
        load_dossier(path)?.ok_or_else(|| AgvtError::new("dossier file does not exist."))?;
    if file.entries.remove(id).is_none() {
        return Err(AgvtError::new(format!("dossier entry not found: {id}")));
    }
    file.updated_at = now_stamp();
    save_dossier(path, &file)
}

fn summarize(entry: &DossierEntry) -> EntrySummary {
    EntrySummary {
        id: entry.id.clone(),
        tier: entry.tier,
        topic: entry.topic.clone(),
        tags: entry.tags.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

pub(crate) fn list_summaries(path: &Path, tier: Option<Tier>) -> Result<Vec<EntrySummary>> {
    let Some(file) = load_dossier(path)? else {
        return Ok(Vec::new());
    };
    Ok(file
        .entries
        .values()
        .filter(|entry| tier.is_none_or(|tier| entry.tier == tier))
        .map(summarize)
        .collect())
}

/// Searches topics, tags, and plaintext bodies (case-insensitive substring).
/// Locked bodies are never decrypted for search; locked entries match on
/// topic and tags only.
pub(crate) fn search_entries(
    path: &Path,
    query: &str,
    tier: Option<Tier>,
) -> Result<Vec<EntrySummary>> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Err(AgvtError::new("search requires a non-empty query."));
    }
    let Some(file) = load_dossier(path)? else {
        return Ok(Vec::new());
    };
    Ok(file
        .entries
        .values()
        .filter(|entry| tier.is_none_or(|tier| entry.tier == tier))
        .filter(|entry| {
            entry.topic.to_lowercase().contains(&needle)
                || entry
                    .tags
                    .iter()
                    .any(|tag| tag.to_lowercase().contains(&needle))
                || entry
                    .body
                    .as_ref()
                    .is_some_and(|body| body.to_lowercase().contains(&needle))
        })
        .map(summarize)
        .collect())
}

pub(crate) fn show_entry(path: &Path, id: &str, tier: Option<Tier>) -> Result<ShownEntry> {
    let file = load_dossier(path)?.ok_or_else(|| AgvtError::new("dossier file does not exist."))?;
    let entry = file
        .entries
        .get(id)
        .ok_or_else(|| AgvtError::new(format!("dossier entry not found: {id}")))?;
    if let Some(tier) = tier {
        if entry.tier != tier {
            return Err(AgvtError::new(format!(
                "dossier entry {id} does not match --tier {}.",
                tier.as_str()
            )));
        }
    }
    let secret_ref = dossier_body_ref(id);
    Ok(ShownEntry {
        id: entry.id.clone(),
        topic: entry.topic.clone(),
        tags: entry.tags.clone(),
        tier: entry.tier,
        updated_at: entry.updated_at.clone(),
        body: match entry.tier {
            Tier::Locked => None,
            Tier::Open | Tier::Standard => entry.body.clone(),
        },
        body_ref: match entry.tier {
            Tier::Locked => Some(format!(
                "agvt://{}/{}/{}",
                secret_ref.vault, secret_ref.item, secret_ref.field
            )),
            Tier::Open | Tier::Standard => None,
        },
    })
}

/// Decrypts one locked body. This is intentionally not reachable from any
/// CLI display flow in Phase 1 (ADR 0014: locked bodies are never returned
/// raw by CLI display flows); it is reserved for the future `agvt run`
/// consumption path and for tests asserting the encryption round trip.
#[allow(dead_code)]
pub(crate) fn read_locked_body(path: &Path, passphrase: &str, id: &str) -> Result<String> {
    let file = load_dossier(path)?.ok_or_else(|| AgvtError::new("dossier file does not exist."))?;
    let entry = file
        .entries
        .get(id)
        .ok_or_else(|| AgvtError::new(format!("dossier entry not found: {id}")))?;
    if entry.tier != Tier::Locked {
        return Err(AgvtError::new("dossier entry is not locked."));
    }
    let encrypted_body = entry
        .encrypted_body
        .as_ref()
        .ok_or_else(|| AgvtError::new("locked dossier entry is missing its encrypted body."))?;
    let key = unlock_dossier_key(&file, passphrase)?;
    decrypt_text(encrypted_body, &key, &entry_aad(id))
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = tags
        .into_iter()
        .map(|tag| tag.trim().to_owned())
        .filter(|tag| !tag.is_empty())
        .collect();
    normalized.dedup();
    normalized
}

fn parse_tags(value: &str) -> Vec<String> {
    value.split(',').map(str::to_owned).collect()
}

// ---------------------------------------------------------------------------
// CLI handlers
// ---------------------------------------------------------------------------

pub(crate) fn handle_dossier(options: &GlobalOptions) -> Result<()> {
    run_dossier(&options.args, &options.global_vault_path)
}

fn run_dossier(args: &[String], global_vault_path: &Path) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(AgvtError::new(
            "dossier requires add, ls, show, edit, rm, or search.",
        ));
    };
    let path = dossier_path();
    let rest = &args[1..];
    match command {
        "add" => handle_add(&path, global_vault_path, rest),
        "ls" | "list" => handle_ls(&path, rest),
        "show" => handle_show(&path, rest),
        "edit" => handle_edit(&path, global_vault_path, rest),
        "rm" | "delete" => handle_rm(&path, rest),
        "search" => handle_search(&path, rest),
        _ => Err(AgvtError::new(
            "dossier requires add, ls, show, edit, rm, or search.",
        )),
    }
}

#[derive(Default)]
struct DossierCliOptions {
    positionals: Vec<String>,
    body: Option<String>,
    body_stdin: bool,
    topic: Option<String>,
    tags: Option<Vec<String>>,
    tier: Option<Tier>,
    id: Option<String>,
    as_json: bool,
}

fn parse_dossier_cli_options(command: &str, args: &[String]) -> Result<DossierCliOptions> {
    let mut options = DossierCliOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--body" => {
                options.body = Some(take_value(args, index, "--body")?);
                index += 1;
            }
            "--body-stdin" => options.body_stdin = true,
            "--topic" => {
                options.topic = Some(take_value(args, index, "--topic")?);
                index += 1;
            }
            "--tags" => {
                options.tags = Some(parse_tags(&take_value(args, index, "--tags")?));
                index += 1;
            }
            "--tier" => {
                options.tier = Some(Tier::parse(&take_value(args, index, "--tier")?)?);
                index += 1;
            }
            "--id" => {
                options.id = Some(take_value(args, index, "--id")?);
                index += 1;
            }
            "--json" => options.as_json = true,
            value if value.starts_with("--") => {
                return Err(AgvtError::new(format!(
                    "unknown dossier {command} option: {value}"
                )))
            }
            value => options.positionals.push(value.to_owned()),
        }
        index += 1;
    }
    Ok(options)
}

fn resolve_body_input(options: &DossierCliOptions) -> Result<Option<String>> {
    if options.body.is_some() && options.body_stdin {
        return Err(AgvtError::new(
            "use either --body or --body-stdin, not both.",
        ));
    }
    if options.body_stdin {
        return Ok(Some(read_stdin()?));
    }
    Ok(options.body.clone())
}

fn handle_add(path: &Path, global_vault_path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("add", args)?;
    let Some(topic) = cli.positionals.first().cloned() else {
        return Err(AgvtError::new("dossier add requires a topic."));
    };
    let body = resolve_body_input(&cli)?
        .ok_or_else(|| AgvtError::new("dossier add requires --body or --body-stdin."))?;
    let tier = cli.tier.unwrap_or(Tier::Standard);
    let passphrase = if tier == Tier::Locked {
        Some(require_passphrase_for_path(global_vault_path)?)
    } else {
        None
    };
    let id = add_entry(
        path,
        AddEntryInput {
            id: cli.id,
            topic,
            body,
            tags: cli.tags.unwrap_or_default(),
            tier,
        },
        passphrase.as_deref(),
    )?;
    audit::record("dossier-add", &dossier_body_ref(&id), "agvt");
    println!("saved dossier entry {id} (tier={})", tier.as_str());
    Ok(())
}

fn handle_edit(path: &Path, global_vault_path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("edit", args)?;
    let Some(id) = cli.positionals.first().cloned() else {
        return Err(AgvtError::new("dossier edit requires an entry id."));
    };
    let body = resolve_body_input(&cli)?;
    let input = EditEntryInput {
        topic: cli.topic,
        body,
        tags: cli.tags,
        tier: cli.tier,
    };

    // A passphrase is needed only when the edit must encrypt a body: the
    // resulting tier is locked and either a new body was supplied or the
    // entry is being upgraded from a plaintext tier.
    let file = load_dossier(path)?.ok_or_else(|| AgvtError::new("dossier file does not exist."))?;
    let entry = file
        .entries
        .get(&id)
        .ok_or_else(|| AgvtError::new(format!("dossier entry not found: {id}")))?;
    let target_tier = input.tier.unwrap_or(entry.tier);
    let needs_passphrase =
        target_tier == Tier::Locked && (input.body.is_some() || entry.tier != Tier::Locked);
    let passphrase = if needs_passphrase {
        Some(require_passphrase_for_path(global_vault_path)?)
    } else {
        None
    };
    edit_entry(path, &id, input, passphrase.as_deref())?;
    audit::record("dossier-edit", &dossier_body_ref(&id), "agvt");
    println!("updated dossier entry {id} (tier={})", target_tier.as_str());
    Ok(())
}

fn handle_rm(path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("rm", args)?;
    let Some(id) = cli.positionals.first().cloned() else {
        return Err(AgvtError::new("dossier rm requires an entry id."));
    };
    remove_entry(path, &id)?;
    audit::record("dossier-rm", &dossier_body_ref(&id), "agvt");
    println!("deleted dossier entry {id}");
    Ok(())
}

fn handle_show(path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("show", args)?;
    let Some(id) = cli.positionals.first().cloned() else {
        return Err(AgvtError::new("dossier show requires an entry id."));
    };
    let shown = show_entry(path, &id, cli.tier)?;
    if shown.tier == Tier::Locked {
        // Locked read attempt: only the reference is returned, never the body.
        audit::record("dossier-read-locked", &dossier_body_ref(&id), "agvt");
    }
    if cli.as_json {
        let mut object = serde_json::json!({
            "id": shown.id,
            "topic": shown.topic,
            "tags": shown.tags,
            "tier": shown.tier.as_str(),
            "updatedAt": shown.updated_at,
            "body": shown.body,
        });
        if let Some(body_ref) = &shown.body_ref {
            object["bodyRef"] = serde_json::Value::String(body_ref.clone());
        }
        println!("{}", serde_json::to_string_pretty(&object)?);
        return Ok(());
    }
    println!("id: {}", shown.id);
    println!("topic: {}", shown.topic);
    println!("tier: {}", shown.tier.as_str());
    println!("tags: {}", shown.tags.join(", "));
    println!("updatedAt: {}", shown.updated_at);
    match (&shown.body, &shown.body_ref) {
        (Some(body), _) => {
            println!("body:");
            println!("{body}");
        }
        (None, Some(body_ref)) => {
            println!(
                "body: [locked] {body_ref} (the raw body is never displayed; consumption is deferred to a future `agvt run` integration)"
            );
        }
        (None, None) => {}
    }
    Ok(())
}

fn handle_ls(path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("ls", args)?;
    let summaries = list_summaries(path, cli.tier)?;
    print_summaries(&summaries, cli.as_json, "No dossier entries.")
}

fn handle_search(path: &Path, args: &[String]) -> Result<()> {
    let cli = parse_dossier_cli_options("search", args)?;
    let Some(query) = cli.positionals.first().cloned() else {
        return Err(AgvtError::new("dossier search requires a query."));
    };
    let summaries = search_entries(path, &query, cli.tier)?;
    print_summaries(&summaries, cli.as_json, "No matching dossier entries.")
}

fn print_summaries(summaries: &[EntrySummary], as_json: bool, empty_message: &str) -> Result<()> {
    if as_json {
        let json_entries: Vec<_> = summaries
            .iter()
            .map(|summary| {
                serde_json::json!({
                    "id": summary.id,
                    "tier": summary.tier.as_str(),
                    "topic": summary.topic,
                    "tags": summary.tags,
                    "updatedAt": summary.updated_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "entries": json_entries }))?
        );
        return Ok(());
    }
    if summaries.is_empty() {
        println!("{empty_message}");
        return Ok(());
    }
    for summary in summaries {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            summary.id,
            summary.tier.as_str(),
            summary.topic,
            summary.tags.join(","),
            summary.updated_at
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "test-passphrase-with-enough-length";

    fn add(path: &Path, topic: &str, body: &str, tier: Tier, tags: &[&str]) -> String {
        add_entry(
            path,
            AddEntryInput {
                id: None,
                topic: topic.to_owned(),
                body: body.to_owned(),
                tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
                tier,
            },
            if tier == Tier::Locked {
                Some(PASSPHRASE)
            } else {
                None
            },
        )
        .unwrap()
    }

    #[test]
    fn add_search_show_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");

        let id = add(
            &path,
            "company-challenges",
            "shipping agent-first products",
            Tier::Standard,
            &["company", "strategy"],
        );

        let by_topic = search_entries(&path, "company", None).unwrap();
        assert_eq!(by_topic.len(), 1);
        assert_eq!(by_topic[0].id, id);
        assert_eq!(by_topic[0].tier, Tier::Standard);

        let by_body = search_entries(&path, "agent-first", None).unwrap();
        assert_eq!(by_body.len(), 1);

        let by_tag = search_entries(&path, "strategy", None).unwrap();
        assert_eq!(by_tag.len(), 1);

        let shown = show_entry(&path, &id, None).unwrap();
        assert_eq!(shown.topic, "company-challenges");
        assert_eq!(shown.body.as_deref(), Some("shipping agent-first products"));
        assert!(shown.body_ref.is_none());
    }

    #[test]
    fn locked_body_is_encrypted_on_disk_and_never_shown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let secret_body = "account-number-1234567890";

        let id = add(&path, "brokerage-account", secret_body, Tier::Locked, &[]);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(secret_body));
        assert!(!raw.contains("1234567890"));

        let shown = show_entry(&path, &id, None).unwrap();
        assert!(shown.body.is_none());
        assert_eq!(
            shown.body_ref.as_deref(),
            Some(format!("agvt://dossier/{id}/body").as_str())
        );

        assert_eq!(
            read_locked_body(&path, PASSPHRASE, &id).unwrap(),
            secret_body
        );
        assert!(read_locked_body(&path, "wrong-passphrase-with-enough-length", &id).is_err());
    }

    #[test]
    fn tier_filter_excludes_locked_entries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");

        add(
            &path,
            "device models",
            "printer model X-1000",
            Tier::Open,
            &[],
        );
        add(&path, "client names", "acme corp", Tier::Standard, &[]);
        let locked_id = add(&path, "account details", "secret-body", Tier::Locked, &[]);

        let open_only = search_entries(&path, "a", Some(Tier::Open)).unwrap();
        assert!(open_only.iter().all(|entry| entry.tier == Tier::Open));
        assert!(!open_only.iter().any(|entry| entry.id == locked_id));

        let listed_open = list_summaries(&path, Some(Tier::Open)).unwrap();
        assert_eq!(listed_open.len(), 1);

        assert!(show_entry(&path, &locked_id, Some(Tier::Open)).is_err());
        assert!(show_entry(&path, &locked_id, Some(Tier::Locked)).is_ok());
    }

    #[test]
    fn default_tier_is_standard_and_open_needs_opt_in() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let options = parse_dossier_cli_options("add", &["topic".to_owned()]).unwrap();
        assert!(options.tier.is_none());

        let id = add(&path, "topic", "body", Tier::Standard, &[]);
        assert_eq!(list_summaries(&path, None).unwrap()[0].tier, Tier::Standard);
        let _ = id;
    }

    #[test]
    fn edit_rejects_locked_downgrade_without_new_body() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let id = add(&path, "contract terms", "secret-clause", Tier::Locked, &[]);

        let error = edit_entry(
            &path,
            &id,
            EditEntryInput {
                tier: Some(Tier::Standard),
                ..EditEntryInput::default()
            },
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("never decrypted"));

        // With an explicit new body the downgrade is allowed and plaintext.
        edit_entry(
            &path,
            &id,
            EditEntryInput {
                tier: Some(Tier::Standard),
                body: Some("public summary".to_owned()),
                ..EditEntryInput::default()
            },
            None,
        )
        .unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-clause"));
        assert!(raw.contains("public summary"));
    }

    #[test]
    fn edit_upgrade_to_locked_encrypts_existing_body() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let id = add(
            &path,
            "tax details",
            "sensitive-tax-figure",
            Tier::Standard,
            &[],
        );

        edit_entry(
            &path,
            &id,
            EditEntryInput {
                tier: Some(Tier::Locked),
                ..EditEntryInput::default()
            },
            Some(PASSPHRASE),
        )
        .unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sensitive-tax-figure"));
        assert_eq!(
            read_locked_body(&path, PASSPHRASE, &id).unwrap(),
            "sensitive-tax-figure"
        );
        // Locked entries never match body search.
        assert!(search_entries(&path, "sensitive-tax-figure", None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rm_removes_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let id = add(&path, "obsolete", "old body", Tier::Open, &[]);
        remove_entry(&path, &id).unwrap();
        assert!(list_summaries(&path, None).unwrap().is_empty());
        assert!(remove_entry(&path, &id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dossier_file_has_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        add(&path, "topic", "body", Tier::Standard, &[]);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn writes_and_locked_reads_are_audited() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        let dossier_path_value = directory.path().join("dossier.json");
        let audit_path = directory.path().join("audit.jsonl");
        env::set_var(AGVT_DOSSIER_PATH_ENV, &dossier_path_value);
        env::set_var(audit::AGVT_AUDIT_PATH_ENV, &audit_path);
        env::set_var(crate::vault::AGVT_PASSPHRASE_ENV, PASSPHRASE);

        let secret_body = "locked-audit-secret-body";
        let global_vault_path = directory.path().join("agent-vault.json");
        run_dossier(
            &[
                "add".to_owned(),
                "audited topic".to_owned(),
                "--body".to_owned(),
                secret_body.to_owned(),
                "--tier".to_owned(),
                "locked".to_owned(),
            ],
            &global_vault_path,
        )
        .unwrap();
        let id = list_summaries(&dossier_path_value, None).unwrap()[0]
            .id
            .clone();
        run_dossier(&["show".to_owned(), id.clone()], &global_vault_path).unwrap();
        run_dossier(&["rm".to_owned(), id.clone()], &global_vault_path).unwrap();

        env::remove_var(AGVT_DOSSIER_PATH_ENV);
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);
        env::remove_var(crate::vault::AGVT_PASSPHRASE_ENV);

        let entries = audit::list_entries(&audit_path).unwrap();
        let ops: Vec<&str> = entries.iter().map(|entry| entry.op.as_str()).collect();
        assert_eq!(
            ops,
            vec!["dossier-add", "dossier-read-locked", "dossier-rm"]
        );
        let expected_ref = format!("agvt://dossier/{id}/body");
        assert!(entries.iter().all(|entry| entry.reference == expected_ref));
        assert!(entries.iter().all(|entry| entry.caller == "agvt"));

        // Neither the audit log nor any error path ever holds the body.
        let raw_audit = fs::read_to_string(&audit_path).unwrap();
        assert!(!raw_audit.contains(secret_body));
    }

    #[test]
    fn dossier_path_prefers_explicit_env_override() {
        let _guard = crate::audit::lock_test_env();
        env::set_var(AGVT_DOSSIER_PATH_ENV, "/tmp/custom-dossier.json");
        assert_eq!(dossier_path(), PathBuf::from("/tmp/custom-dossier.json"));
        env::remove_var(AGVT_DOSSIER_PATH_ENV);
    }

    #[test]
    fn rejects_duplicate_explicit_ids_and_invalid_tiers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        add_entry(
            &path,
            AddEntryInput {
                id: Some("company-notes".to_owned()),
                topic: "notes".to_owned(),
                body: "body".to_owned(),
                tags: Vec::new(),
                tier: Tier::Open,
            },
            None,
        )
        .unwrap();
        assert!(add_entry(
            &path,
            AddEntryInput {
                id: Some("company-notes".to_owned()),
                topic: "notes".to_owned(),
                body: "body".to_owned(),
                tags: Vec::new(),
                tier: Tier::Open,
            },
            None,
        )
        .is_err());
        assert!(Tier::parse("secret").is_err());
        assert_eq!(Tier::parse("LOCKED").unwrap(), Tier::Locked);
    }

    #[test]
    fn locked_add_requires_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dossier.json");
        let error = add_entry(
            &path,
            AddEntryInput {
                id: None,
                topic: "topic".to_owned(),
                body: "body".to_owned(),
                tags: Vec::new(),
                tier: Tier::Locked,
            },
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("passphrase"));
    }
}
