use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

use crate::error::{AgvtError, Result};
use crate::presets::PRESETS;
use crate::reference::{self, item_target_to_ref, validate_env_name};
use crate::vault::{canonical_payload_field, read_secret_field, require_passphrase_for_path};
use crate::{
    import_env_candidates, load_import_env_source, selected_import_presets, take_value,
    GlobalOptions, ImportEnvOptions,
};

#[derive(Default)]
struct PrepareOptions {
    presets: Vec<String>,
    env_files: Vec<String>,
    manifest_path: Option<String>,
    no_manifest: bool,
    no_env_file: bool,
    as_json: bool,
}

struct PrepareManifest {
    path: String,
    presets: Vec<String>,
    secrets: Vec<PrepareManifestSecret>,
}

#[derive(Default)]
struct PrepareManifestSecret {
    item: Option<String>,
    field: Option<String>,
    env_name: Option<String>,
    required: Option<bool>,
    label: Option<String>,
}

#[derive(Clone)]
struct PrepareRequirement {
    item: String,
    field: String,
    env_name: Option<String>,
    required: bool,
    source_kind: &'static str,
    label: Option<String>,
}

struct PrepareFinding {
    requirement: PrepareRequirement,
    status: &'static str,
    source: Option<&'static str>,
    action: Option<String>,
}

struct PrepareSummary {
    repo: String,
    manifest_path: Option<String>,
    manifest_found: bool,
    vault_path: String,
    vault_status: &'static str,
    findings: Vec<PrepareFinding>,
    suggested_commands: Vec<String>,
}

enum PrepareVaultAccess {
    Missing,
    Ready(String),
    Locked,
}

pub(crate) fn handle_prepare(options: &GlobalOptions) -> Result<()> {
    let prepare_options = parse_prepare_options(&options.args)?;
    let manifest = load_prepare_manifest(&prepare_options)?;
    let import_options = ImportEnvOptions {
        env_files: prepare_options.env_files.clone(),
        no_env_file: prepare_options.no_env_file,
        ..ImportEnvOptions::default()
    };
    let source_env = load_import_env_source(&import_options)?;
    let requirements = prepare_requirements(&prepare_options, manifest.as_ref(), &source_env)?;
    let vault_access = prepare_vault_access(&options.vault_path);
    let vault_status = match &vault_access {
        PrepareVaultAccess::Missing => "missing",
        PrepareVaultAccess::Ready(_) => "ready",
        PrepareVaultAccess::Locked => "locked",
    };
    let findings = prepare_findings(
        &requirements,
        &source_env,
        &vault_access,
        &options.vault_path,
        &options.default_vault,
    )?;
    let suggested_commands = prepare_suggested_commands(&findings);
    let summary = PrepareSummary {
        repo: env::current_dir()?
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_owned()),
        manifest_path: manifest.as_ref().map(|manifest| manifest.path.clone()),
        manifest_found: manifest.is_some(),
        vault_path: options.vault_path.display().to_string(),
        vault_status,
        findings,
        suggested_commands,
    };
    print_prepare_summary(&summary, prepare_options.as_json)
}

fn parse_prepare_options(args: &[String]) -> Result<PrepareOptions> {
    let mut options = PrepareOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => {
                index += 1;
            }
            "--json" => {
                options.as_json = true;
                index += 1;
            }
            "--env-file" => {
                options
                    .env_files
                    .push(take_value(args, index, "--env-file")?);
                index += 2;
            }
            "--manifest" => {
                options.manifest_path = Some(take_value(args, index, "--manifest")?);
                index += 2;
            }
            "--no-manifest" => {
                options.no_manifest = true;
                index += 1;
            }
            "--no-env-file" => {
                options.no_env_file = true;
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(AgvtError::new(format!("unknown prepare option: {value}")));
            }
            value => {
                options.presets.push(value.to_owned());
                index += 1;
            }
        }
    }
    Ok(options)
}

fn load_prepare_manifest(options: &PrepareOptions) -> Result<Option<PrepareManifest>> {
    if options.no_manifest {
        return Ok(None);
    }
    let path = options
        .manifest_path
        .as_deref()
        .unwrap_or("agvt.toml")
        .to_owned();
    if !Path::new(&path).is_file() {
        if options.manifest_path.is_some() {
            return Err(AgvtError::new(format!(
                "prepare manifest not found: {path}"
            )));
        }
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    Ok(Some(parse_prepare_manifest(&path, &content)?))
}

fn parse_prepare_manifest(path: &str, content: &str) -> Result<PrepareManifest> {
    enum Section {
        None,
        Prepare,
        PrepareSecret,
    }

    let mut section = Section::None;
    let mut presets = Vec::new();
    let mut secrets = Vec::new();
    let mut current_secret: Option<PrepareManifestSecret> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "[prepare]" {
            finish_prepare_manifest_secret(&mut current_secret, &mut secrets)?;
            section = Section::Prepare;
            continue;
        }
        if trimmed == "[[prepare.secrets]]" {
            finish_prepare_manifest_secret(&mut current_secret, &mut secrets)?;
            current_secret = Some(PrepareManifestSecret::default());
            section = Section::PrepareSecret;
            continue;
        }

        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| AgvtError::new("prepare manifest line must be KEY = VALUE."))?;
        let key = key.trim();
        let value = value.trim();
        match section {
            Section::Prepare if key == "presets" => {
                presets = parse_toml_string_array(value)?;
            }
            Section::PrepareSecret => {
                let secret = current_secret
                    .as_mut()
                    .ok_or_else(|| AgvtError::new("prepare secret section was not started."))?;
                match key {
                    "item" => {
                        secret.item = Some(reference::validate_name(
                            &parse_toml_string(value)?,
                            "item",
                        )?);
                    }
                    "field" => {
                        secret.field = Some(canonical_payload_field(&parse_toml_string(value)?)?);
                    }
                    "env" | "envName" => {
                        secret.env_name = Some(validate_env_name(&parse_toml_string(value)?)?);
                    }
                    "required" => secret.required = Some(parse_toml_bool(value)?),
                    "label" => secret.label = Some(parse_toml_string(value)?),
                    _ => return Err(AgvtError::new(format!("unknown prepare secret key: {key}"))),
                }
            }
            _ => {
                return Err(AgvtError::new(
                    "prepare manifest supports [prepare] and [[prepare.secrets]] only.",
                ));
            }
        }
    }
    finish_prepare_manifest_secret(&mut current_secret, &mut secrets)?;
    Ok(PrepareManifest {
        path: path.to_owned(),
        presets,
        secrets,
    })
}

fn finish_prepare_manifest_secret(
    current_secret: &mut Option<PrepareManifestSecret>,
    secrets: &mut Vec<PrepareManifestSecret>,
) -> Result<()> {
    if let Some(secret) = current_secret.take() {
        if secret.item.is_none() {
            return Err(AgvtError::new("prepare secret requires item."));
        }
        secrets.push(secret);
    }
    Ok(())
}

fn parse_toml_string(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.starts_with('"') {
        return serde_json::from_str(trimmed)
            .map_err(|_| AgvtError::new("manifest string value is invalid."));
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return Ok(trimmed[1..trimmed.len() - 1].to_owned());
    }
    Err(AgvtError::new("manifest value must be a quoted string."))
}

fn parse_toml_string_array(value: &str) -> Result<Vec<String>> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(AgvtError::new("manifest presets must be a string array."));
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|part| parse_toml_string(part.trim()))
        .collect()
}

fn parse_toml_bool(value: &str) -> Result<bool> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AgvtError::new("manifest boolean must be true or false.")),
    }
}

fn prepare_requirements(
    options: &PrepareOptions,
    manifest: Option<&PrepareManifest>,
    source_env: &BTreeMap<String, String>,
) -> Result<Vec<PrepareRequirement>> {
    let mut requirements = BTreeMap::new();
    if let Some(manifest) = manifest {
        add_prepare_preset_requirements(&mut requirements, &manifest.presets)?;
        for secret in &manifest.secrets {
            let item = secret
                .item
                .clone()
                .ok_or_else(|| AgvtError::new("prepare secret requires item."))?;
            add_prepare_requirement(
                &mut requirements,
                PrepareRequirement {
                    item,
                    field: secret.field.clone().unwrap_or_else(|| "token".to_owned()),
                    env_name: secret.env_name.clone(),
                    required: secret.required.unwrap_or(true),
                    source_kind: "manifest",
                    label: secret.label.clone(),
                },
            );
        }
        return Ok(requirements.into_values().collect());
    }

    let presets = if options.presets.is_empty() {
        detect_prepare_presets(source_env)
    } else {
        options.presets.clone()
    };
    add_prepare_preset_requirements(&mut requirements, &presets)?;

    let import_options = ImportEnvOptions::default();
    for candidate in import_env_candidates(source_env, &import_options)? {
        if candidate.source_kind == "custom" {
            add_prepare_requirement(
                &mut requirements,
                PrepareRequirement {
                    item: candidate.item,
                    field: "token".to_owned(),
                    env_name: candidate.source_envs.first().cloned(),
                    required: true,
                    source_kind: "env-detected",
                    label: Some(candidate.label),
                },
            );
        }
    }
    Ok(requirements.into_values().collect())
}

fn add_prepare_preset_requirements(
    requirements: &mut BTreeMap<String, PrepareRequirement>,
    presets: &[String],
) -> Result<()> {
    for preset in selected_import_presets(presets)? {
        for field in preset.fields {
            add_prepare_requirement(
                requirements,
                PrepareRequirement {
                    item: preset.name.to_owned(),
                    field: field.field.to_owned(),
                    env_name: Some(field.env_name.to_owned()),
                    required: field.required,
                    source_kind: "preset",
                    label: Some(preset.label.to_owned()),
                },
            );
        }
    }
    Ok(())
}

fn add_prepare_requirement(
    requirements: &mut BTreeMap<String, PrepareRequirement>,
    requirement: PrepareRequirement,
) {
    let key = format!("{}.{}", requirement.item, requirement.field);
    requirements.entry(key).or_insert(requirement);
}

fn detect_prepare_presets(source_env: &BTreeMap<String, String>) -> Vec<String> {
    let mut presets = Vec::new();
    for preset in PRESETS {
        if preset
            .fields
            .iter()
            .any(|field| source_env.contains_key(field.env_name))
        {
            presets.push(preset.name.to_owned());
        }
    }
    if has_wrangler_config() {
        presets.push("cloudflare".to_owned());
    }
    if Path::new("vercel.json").is_file() {
        presets.push("vercel".to_owned());
    }
    presets.sort();
    presets.dedup();
    presets
}

fn has_wrangler_config() -> bool {
    [
        "wrangler.toml",
        "wrangler.json",
        "wrangler.jsonc",
        "apps/log-worker/wrangler.toml",
        "apps/log-worker/wrangler.json",
        "apps/log-worker/wrangler.jsonc",
    ]
    .iter()
    .any(|path| Path::new(path).is_file())
}

fn prepare_vault_access(vault_path: &Path) -> PrepareVaultAccess {
    if !vault_path.exists() {
        return PrepareVaultAccess::Missing;
    }
    match require_passphrase_for_path(vault_path) {
        Ok(passphrase) => PrepareVaultAccess::Ready(passphrase),
        Err(_error) => PrepareVaultAccess::Locked,
    }
}

fn prepare_findings(
    requirements: &[PrepareRequirement],
    source_env: &BTreeMap<String, String>,
    vault_access: &PrepareVaultAccess,
    vault_path: &Path,
    default_vault: &str,
) -> Result<Vec<PrepareFinding>> {
    let mut findings = Vec::new();
    for requirement in requirements {
        let env_available = requirement
            .env_name
            .as_ref()
            .and_then(|env_name| source_env.get(env_name))
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let vault_present = match vault_access {
            PrepareVaultAccess::Ready(passphrase) => {
                let secret_ref =
                    item_target_to_ref(&requirement.item, default_vault, &requirement.field)?;
                match read_secret_field(vault_path, passphrase, &secret_ref) {
                    Ok(value) => Some(!value.trim().is_empty()),
                    Err(_error) => Some(false),
                }
            }
            PrepareVaultAccess::Missing => Some(false),
            PrepareVaultAccess::Locked => None,
        };
        let (status, source) = match (vault_present, env_available) {
            (Some(true), _) => ("present", Some("vault")),
            (Some(false), true) | (None, true) => {
                ("importable", requirement.env_name.as_ref().map(|_| "env"))
            }
            (Some(false), false) => ("missing", None),
            (None, false) => ("unchecked", None),
        };
        findings.push(PrepareFinding {
            requirement: requirement.clone(),
            status,
            source,
            action: prepare_action(requirement, status),
        });
    }
    findings.sort_by(|left, right| {
        left.requirement
            .item
            .cmp(&right.requirement.item)
            .then(left.requirement.field.cmp(&right.requirement.field))
    });
    Ok(findings)
}

fn prepare_action(requirement: &PrepareRequirement, status: &str) -> Option<String> {
    match status {
        "importable" => Some("agvt import-env --dry-run".to_owned()),
        "missing" if requirement.required && requirement.field == "token" => {
            Some(format!("agvt add {} --from-stdin", requirement.item))
        }
        _ => None,
    }
}

fn prepare_suggested_commands(findings: &[PrepareFinding]) -> Vec<String> {
    let mut commands = Vec::new();
    for finding in findings {
        if let Some(action) = &finding.action {
            if !commands.iter().any(|command| command == action) {
                commands.push(action.clone());
            }
        }
    }
    commands
}

fn print_prepare_summary(summary: &PrepareSummary, as_json: bool) -> Result<()> {
    if as_json {
        let requirements: Vec<_> = summary
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "item": &finding.requirement.item,
                    "field": &finding.requirement.field,
                    "envName": &finding.requirement.env_name,
                    "required": finding.requirement.required,
                    "sourceKind": finding.requirement.source_kind,
                    "label": &finding.requirement.label,
                    "status": finding.status,
                    "source": finding.source,
                    "action": &finding.action
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "repo": &summary.repo,
                "manifest": {
                    "found": summary.manifest_found,
                    "path": &summary.manifest_path
                },
                "vault": {
                    "path": &summary.vault_path,
                    "status": summary.vault_status
                },
                "requirements": requirements,
                "suggestedCommands": &summary.suggested_commands
            }))?
        );
        return Ok(());
    }

    println!("repo: {}", summary.repo);
    println!(
        "manifest: {}",
        summary
            .manifest_path
            .as_deref()
            .unwrap_or(if summary.manifest_found {
                "agvt.toml"
            } else {
                "not found"
            })
    );
    println!("vault: {} ({})", summary.vault_status, summary.vault_path);
    if summary.findings.is_empty() {
        println!("No prepare requirements found.");
        return Ok(());
    }
    print_prepare_group("present", summary, |finding| finding.status == "present");
    print_prepare_group("importable", summary, |finding| {
        finding.status == "importable"
    });
    print_prepare_group("missing", summary, |finding| finding.status == "missing");
    print_prepare_group("unchecked", summary, |finding| {
        finding.status == "unchecked"
    });
    if !summary.suggested_commands.is_empty() {
        println!("suggested next steps:");
        for command in &summary.suggested_commands {
            println!("  {command}");
        }
    }
    Ok(())
}

fn print_prepare_group<F>(label: &str, summary: &PrepareSummary, predicate: F)
where
    F: Fn(&PrepareFinding) -> bool,
{
    let matches: Vec<&PrepareFinding> = summary
        .findings
        .iter()
        .filter(|finding| predicate(finding))
        .collect();
    if matches.is_empty() {
        return;
    }
    println!("{label}:");
    for finding in matches {
        let required = if finding.requirement.required {
            "required"
        } else {
            "optional"
        };
        let env_name = finding.requirement.env_name.as_deref().unwrap_or("-");
        println!(
            "  {}.{}\t{}\t{}",
            finding.requirement.item, finding.requirement.field, required, env_name
        );
    }
}
