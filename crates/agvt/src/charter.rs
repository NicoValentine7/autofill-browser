use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit;
use crate::error::{AgvtError, Result};
use crate::reference::{validate_name, SecretRef};
use crate::vault::{ensure_parent_dir, set_private_permissions};

pub const AGVT_CHARTER_PATH_ENV: &str = "AGVT_CHARTER_PATH";
const CHARTER_SCHEMA_VERSION: u8 = 1;
const FALLBACK_AUTONOMY: &str = "confirm";
const AUTONOMY_LEVELS: [&str; 4] = ["auto", "branch-auto", "confirm", "deny"];

/// One Charter rule (ADR 0013): who may do what, and how autonomously.
///
/// The Charter is stored as plaintext JSON on purpose — permission rules are
/// not secrets and must stay auditable and diffable.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CharterRule {
    pub capability: String,
    pub scope: String,
    pub autonomy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CharterFile {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub rules: Vec<CharterRule>,
}

impl Default for CharterFile {
    fn default() -> Self {
        Self {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: Vec::new(),
        }
    }
}

pub fn charter_path() -> PathBuf {
    if let Ok(path) = env::var(AGVT_CHARTER_PATH_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(path) = env::var("XDG_DATA_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path).join("agvt").join("charter.json");
        }
    }
    if let Ok(path) = env::var("HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path)
                .join(".local")
                .join("share")
                .join("agvt")
                .join("charter.json");
        }
    }
    PathBuf::from(".local/share/agvt/charter.json")
}

pub fn validate_autonomy(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if AUTONOMY_LEVELS.contains(&trimmed) {
        return Ok(trimmed.to_owned());
    }
    Err(AgvtError::new(
        "autonomy must be auto, branch-auto, confirm, or deny.",
    ))
}

/// Validates a Charter scope.
///
/// Scopes are either `*` (capability default), an exact name such as
/// `repo:autofill-browser`, or a trailing-wildcard prefix such as `repo:*`.
/// `/` is rejected so the audit reference `agvt://charter/<capability>/<scope>`
/// stays unambiguous, and `*` anywhere but the end is rejected because only
/// trailing-wildcard matching is supported (no glob/regex by design).
pub fn validate_scope(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AgvtError::new("scope must be 1-128 characters."));
    }
    if trimmed == "*" {
        return Ok(trimmed.to_owned());
    }
    let body = trimmed.strip_suffix('*').unwrap_or(trimmed);
    if body.is_empty()
        || !body.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
        })
    {
        return Err(AgvtError::new(
            "scope may contain only letters, numbers, dot, underscore, hyphen, or colon, with an optional trailing *.",
        ));
    }
    Ok(trimmed.to_owned())
}

fn load_charter_strict(path: &Path) -> Result<CharterFile> {
    if !path.exists() {
        return Ok(CharterFile::default());
    }
    let raw = fs::read_to_string(path)?;
    let charter: CharterFile = serde_json::from_str(&raw).map_err(|error| {
        AgvtError::new(format!(
            "charter file is unreadable ({}): {error}. Fix or remove it before writing.",
            path.display()
        ))
    })?;
    Ok(charter)
}

/// Loads the Charter for read paths, failing toward `confirm` (ADR 0013).
///
/// A missing, unreadable, or malformed charter file never crashes a consumer;
/// it degrades to an empty rule set so every check resolves to `confirm`.
fn load_charter_lenient(path: &Path) -> CharterFile {
    match load_charter_strict(path) {
        Ok(charter) => charter,
        Err(error) => {
            eprintln!("warning: {error} Falling back to confirm for all checks.");
            CharterFile::default()
        }
    }
}

fn save_charter(path: &Path, charter: &CharterFile) -> Result<()> {
    ensure_parent_dir(path)?;
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(
        &temporary_path,
        format!("{}\n", serde_json::to_string_pretty(charter)?),
    )?;
    set_private_permissions(&temporary_path)?;
    fs::rename(&temporary_path, path)?;
    set_private_permissions(path)?;
    Ok(())
}

/// Resolves the autonomy verdict for one capability/scope pair.
///
/// Matching order (ADR 0013, kept deliberately simple):
/// 1. exact scope match,
/// 2. trailing-wildcard prefix match (`repo:*`) — the longest prefix wins,
/// 3. the capability default `*`,
/// 4. no rule at all -> `confirm` (fail toward confirm).
pub fn resolve(
    charter: &CharterFile,
    capability: &str,
    scope: &str,
) -> (String, Option<CharterRule>) {
    let mut best: Option<(&CharterRule, usize)> = None;
    for rule in charter
        .rules
        .iter()
        .filter(|rule| rule.capability == capability)
    {
        let specificity = if rule.scope == scope {
            // Exact matches outrank any wildcard prefix.
            usize::MAX
        } else if rule.scope == "*" {
            0
        } else if let Some(prefix) = rule.scope.strip_suffix('*') {
            if scope.starts_with(prefix) {
                prefix.len() + 1
            } else {
                continue;
            }
        } else {
            continue;
        };
        match best {
            Some((_, current)) if current >= specificity => {}
            _ => best = Some((rule, specificity)),
        }
    }
    match best {
        Some((rule, _)) => (rule.autonomy.clone(), Some(rule.clone())),
        None => (FALLBACK_AUTONOMY.to_owned(), None),
    }
}

fn rule_json(rule: &CharterRule) -> serde_json::Value {
    serde_json::json!({
        "capability": rule.capability,
        "scope": rule.scope,
        "autonomy": rule.autonomy,
        "conditions": rule.conditions,
        "notes": rule.notes,
    })
}

/// Records one Charter write in the shared audit log (ADR 0013 tamper threat
/// model: Phase 1 mitigates self-escalation by detection, so every write must
/// leave an audit trail). The reference is `agvt://charter/<capability>/<scope>`
/// to stay aligned with the SecretRef reference shape; `audit::record` only
/// formats the reference and never re-validates it as a vault field.
fn record_write(op: &str, capability: &str, scope: &str) {
    audit::record(
        op,
        &SecretRef {
            vault: "charter".to_owned(),
            item: capability.to_owned(),
            field: scope.to_owned(),
        },
        "agvt",
    );
}

pub fn handle_charter(args: &[String]) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(AgvtError::new("charter requires add, ls, show, or check."));
    };
    match command {
        "add" => handle_add(&args[1..]),
        "ls" | "list" => handle_ls(&args[1..]),
        "show" => handle_show(&args[1..]),
        "check" => handle_check(&args[1..]),
        _ => Err(AgvtError::new("charter requires add, ls, show, or check.")),
    }
}

fn handle_add(args: &[String]) -> Result<()> {
    let mut positional = Vec::new();
    let mut conditions = None;
    let mut notes = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--conditions" => {
                conditions = Some(crate::take_value(args, index, "--conditions")?);
                index += 2;
            }
            "--notes" => {
                notes = Some(crate::take_value(args, index, "--notes")?);
                index += 2;
            }
            other if other.starts_with("--") => {
                return Err(AgvtError::new(format!(
                    "unknown charter add option: {other}"
                )));
            }
            other => {
                positional.push(other.to_owned());
                index += 1;
            }
        }
    }
    let [capability, scope, autonomy] = positional.as_slice() else {
        return Err(AgvtError::new(
            "charter add requires <capability> <scope> <autonomy> [--conditions TEXT] [--notes TEXT].",
        ));
    };
    let rule = CharterRule {
        capability: validate_name(capability, "capability")?,
        scope: validate_scope(scope)?,
        autonomy: validate_autonomy(autonomy)?,
        conditions,
        notes,
    };

    let path = charter_path();
    // Writes are strict on purpose: silently replacing a corrupt charter
    // would destroy the very file the audit trail is meant to protect.
    let mut charter = load_charter_strict(&path)?;
    charter.rules.retain(|existing| {
        !(existing.capability == rule.capability && existing.scope == rule.scope)
    });
    charter.rules.push(rule.clone());
    save_charter(&path, &charter)?;
    record_write("charter-add", &rule.capability, &rule.scope);
    println!(
        "charter rule saved: {} {} -> {}",
        rule.capability, rule.scope, rule.autonomy
    );
    Ok(())
}

fn handle_ls(args: &[String]) -> Result<()> {
    let as_json = args.iter().any(|arg| arg == "--json");
    let charter = load_charter_lenient(&charter_path());
    if as_json {
        let rules: Vec<_> = charter.rules.iter().map(rule_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "rules": rules }))?
        );
        return Ok(());
    }
    if charter.rules.is_empty() {
        println!("No charter rules.");
        return Ok(());
    }
    for rule in &charter.rules {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            rule.capability,
            rule.scope,
            rule.autonomy,
            rule.conditions.as_deref().unwrap_or("-"),
            rule.notes.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn handle_show(args: &[String]) -> Result<()> {
    let as_json = args.iter().any(|arg| arg == "--json");
    let Some(capability) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return Err(AgvtError::new("charter show requires a capability name."));
    };
    let charter = load_charter_lenient(&charter_path());
    let rules: Vec<_> = charter
        .rules
        .iter()
        .filter(|rule| &rule.capability == capability)
        .collect();
    if as_json {
        let json_rules: Vec<_> = rules.iter().map(|rule| rule_json(rule)).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "capability": capability, "rules": json_rules })
            )?
        );
        return Ok(());
    }
    if rules.is_empty() {
        println!("No charter rules for {capability}. Checks fall back to confirm.");
        return Ok(());
    }
    for rule in rules {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            rule.capability,
            rule.scope,
            rule.autonomy,
            rule.conditions.as_deref().unwrap_or("-"),
            rule.notes.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn handle_check(args: &[String]) -> Result<()> {
    let positional: Vec<_> = args.iter().filter(|arg| !arg.starts_with("--")).collect();
    let [capability, scope] = positional.as_slice() else {
        return Err(AgvtError::new(
            "charter check requires <capability> <scope>.",
        ));
    };
    let charter = load_charter_lenient(&charter_path());
    let (autonomy, matched) = resolve(&charter, capability, scope);
    let verdict = serde_json::json!({
        "capability": capability,
        "scope": scope,
        "autonomy": autonomy,
        "matchedRule": matched.as_ref().map(rule_json),
    });
    println!("{}", serde_json::to_string_pretty(&verdict)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(capability: &str, scope: &str, autonomy: &str) -> CharterRule {
        CharterRule {
            capability: capability.to_owned(),
            scope: scope.to_owned(),
            autonomy: autonomy.to_owned(),
            conditions: None,
            notes: None,
        }
    }

    #[test]
    fn resolves_iam_autonomy_ledger_equivalents() {
        // Same shape as the per-repository autonomy ledger this generalizes
        // (auto / branch-auto / confirm), defined inline on purpose.
        let charter = CharterFile {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: vec![
                rule("commit", "repo:autofill-browser", "auto"),
                rule("commit", "repo:agent-times", "branch-auto"),
                rule("commit", "repo:iam", "confirm"),
            ],
        };
        let (autonomy, matched) = resolve(&charter, "commit", "repo:autofill-browser");
        assert_eq!(autonomy, "auto");
        assert_eq!(matched.unwrap().scope, "repo:autofill-browser");
        assert_eq!(
            resolve(&charter, "commit", "repo:agent-times").0,
            "branch-auto"
        );
        assert_eq!(resolve(&charter, "commit", "repo:iam").0, "confirm");
    }

    #[test]
    fn exact_match_beats_wildcard_and_longest_prefix_wins() {
        let charter = CharterFile {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: vec![
                rule("commit", "*", "deny"),
                rule("commit", "repo:*", "branch-auto"),
                rule("commit", "repo:autofill-browser", "auto"),
            ],
        };
        assert_eq!(
            resolve(&charter, "commit", "repo:autofill-browser").0,
            "auto"
        );
        assert_eq!(resolve(&charter, "commit", "repo:other").0, "branch-auto");
        assert_eq!(resolve(&charter, "commit", "gist:snippets").0, "deny");
    }

    #[test]
    fn undefined_capability_falls_back_to_confirm() {
        let charter = CharterFile {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: vec![rule("commit", "*", "auto")],
        };
        let (autonomy, matched) = resolve(&charter, "deploy", "repo:autofill-browser");
        assert_eq!(autonomy, "confirm");
        assert!(matched.is_none());

        let (autonomy, matched) = resolve(&CharterFile::default(), "commit", "repo:x");
        assert_eq!(autonomy, "confirm");
        assert!(matched.is_none());
    }

    #[test]
    fn unmatched_scope_of_defined_capability_falls_back_to_confirm() {
        let charter = CharterFile {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: vec![rule("commit", "repo:iam", "auto")],
        };
        let (autonomy, matched) = resolve(&charter, "commit", "repo:other");
        assert_eq!(autonomy, "confirm");
        assert!(matched.is_none());
    }

    #[test]
    fn corrupt_charter_file_degrades_to_empty_rules() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("charter.json");
        fs::write(&path, "{ this is not json").unwrap();

        let charter = load_charter_lenient(&path);
        assert!(charter.rules.is_empty());
        assert_eq!(resolve(&charter, "commit", "repo:x").0, "confirm");

        // Write paths must refuse to clobber the corrupt file.
        assert!(load_charter_strict(&path).is_err());
    }

    #[test]
    fn save_and_reload_round_trip_preserves_rules() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("charter.json");
        let charter = CharterFile {
            schema_version: CHARTER_SCHEMA_VERSION,
            rules: vec![CharterRule {
                conditions: Some("build/test GREEN".to_owned()),
                notes: Some("dogfood".to_owned()),
                ..rule("commit", "repo:autofill-browser", "auto")
            }],
        };
        save_charter(&path, &charter).unwrap();
        let reloaded = load_charter_strict(&path).unwrap();
        assert_eq!(reloaded.rules.len(), 1);
        assert_eq!(
            reloaded.rules[0].conditions.as_deref(),
            Some("build/test GREEN")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn validates_scope_and_autonomy() {
        assert!(validate_scope("repo:autofill-browser").is_ok());
        assert!(validate_scope("repo:*").is_ok());
        assert!(validate_scope("*").is_ok());
        assert!(validate_scope("repo:*foo").is_err());
        assert!(validate_scope("repo/foo").is_err());
        assert!(validate_scope("").is_err());
        assert!(validate_autonomy("branch-auto").is_ok());
        assert!(validate_autonomy("yolo").is_err());
    }
}
