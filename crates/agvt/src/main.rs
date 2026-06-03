mod cloudflare;
mod error;
mod help;
mod keychain;
mod prepare;
mod presets;
mod reference;
mod totp;
mod vault;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cloudflare::{create_user_token, load_policy_file, CreateTokenInput};
use error::{AgvtError, Result};
use prepare::handle_prepare;
use presets::{find_preset, PRESETS};
use reference::{
    find_secret_refs, item_target_to_ref, parse_secret_ref, validate_env_name, DEFAULT_VAULT_NAME,
    SECRET_REF_PREFIX,
};
use vault::{
    canonical_payload_field, default_global_vault_path, default_vault_path, delete_item,
    list_items, read_secret_field, require_passphrase_for_path, upsert_api_token, upsert_secret,
    validate_item_kind, validate_passphrase_value, UpsertSecretInput, UpsertTokenInput,
    AGVT_PASSPHRASE_ENV, LEGACY_PASSPHRASE_ENV,
};

#[derive(Debug)]
pub(crate) struct GlobalOptions {
    pub(crate) vault_path: PathBuf,
    pub(crate) global_vault_path: PathBuf,
    pub(crate) single_vault_path: bool,
    pub(crate) default_vault: String,
    command: String,
    pub(crate) args: Vec<String>,
}

#[derive(Default)]
struct AddOptions {
    from_stdin: bool,
    from_env: Option<String>,
    kind: Option<String>,
    label: Option<String>,
    service_url: Option<String>,
    account_name: Option<String>,
    account_id: Option<String>,
    token_id: Option<String>,
    expires_on: Option<String>,
    notes: Option<String>,
    vault: Option<String>,
    fields: Vec<FieldValue>,
    field_envs: Vec<FieldEnvValue>,
    field_stdin: Option<String>,
}

struct FieldValue {
    field: String,
    value: String,
}

struct FieldEnvValue {
    field: String,
    env_name: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let options = parse_global_options(env::args().skip(1).collect())?;
    match options.command.as_str() {
        "help" | "--help" | "-h" => {
            print!("{}", help::help_text(&options.args)?);
            Ok(())
        }
        "add" | "put" => handle_add(&options),
        "read" | "get" => handle_read(&options),
        "run" => handle_run(&options),
        "inject" => handle_inject(&options),
        "import-env" => handle_import_env(&options),
        "prepare" => handle_prepare(&options),
        "totp" => handle_totp(&options),
        "keychain" => handle_keychain(&options),
        "cloudflare" => handle_cloudflare(&options),
        "ls" | "list" => handle_list(&options),
        "delete" | "rm" => handle_delete(&options),
        "presets" => handle_presets(&options.args),
        "version" | "--version" | "-V" => {
            println!("agvt {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        command => Err(AgvtError::new(format!("unknown command: {command}"))),
    }
}

fn parse_global_options(mut args: Vec<String>) -> Result<GlobalOptions> {
    let mut vault_path = PathBuf::from(default_vault_path());
    let mut global_vault_path = PathBuf::from(default_global_vault_path());
    let mut single_vault_path = false;
    let mut default_vault = DEFAULT_VAULT_NAME.to_owned();
    let index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--vault-path" => {
                vault_path = PathBuf::from(take_value(&args, index, "--vault-path")?);
                single_vault_path = true;
                args.drain(index..=index + 1);
            }
            "--global-vault-path" => {
                global_vault_path = PathBuf::from(take_value(&args, index, "--global-vault-path")?);
                args.drain(index..=index + 1);
            }
            "--vault" => {
                default_vault = take_value(&args, index, "--vault")?;
                args.drain(index..=index + 1);
            }
            _ => break,
        }
    }

    let command = if args.is_empty() {
        "help".to_owned()
    } else {
        args.remove(0)
    };

    Ok(GlobalOptions {
        vault_path,
        global_vault_path,
        single_vault_path,
        default_vault,
        command,
        args,
    })
}

pub(crate) fn path_for_secret_ref<'a>(
    options: &'a GlobalOptions,
    secret_ref: &reference::SecretRef,
) -> &'a Path {
    if !options.single_vault_path && secret_ref.vault == "global" {
        return &options.global_vault_path;
    }
    &options.vault_path
}

pub(crate) fn take_value(args: &[String], index: usize, option: &str) -> Result<String> {
    args.get(index + 1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| AgvtError::new(format!("{option} requires a value.")))
}

fn handle_add(options: &GlobalOptions) -> Result<()> {
    let Some(target) = options.args.first() else {
        return Err(AgvtError::new(
            "add requires an item name or secret reference.",
        ));
    };
    let add_options = parse_add_options(&options.args[1..])?;
    let default_vault = add_options
        .vault
        .as_deref()
        .unwrap_or(&options.default_vault);
    let secret_ref = item_target_to_ref(target, default_vault, "token")?;
    let preset = find_preset(&secret_ref.item);
    let kind = add_options
        .kind
        .as_deref()
        .map(validate_item_kind)
        .transpose()?
        .unwrap_or_else(|| "api-token".to_owned());
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;

    if kind != "api-token" {
        let fields = read_secret_fields(&kind, &add_options)?;
        let saved_field = default_secret_value_field(&kind)?;
        upsert_secret(
            vault_path,
            &passphrase,
            UpsertSecretInput {
                secret_ref: secret_ref.clone(),
                kind,
                label: add_options.label,
                fields,
            },
        )?;
        println!(
            "saved agvt://{}/{}/{}",
            secret_ref.vault, secret_ref.item, saved_field
        );
        return Ok(());
    }

    let token = read_token_value(&add_options, preset.map(|preset| preset.env_name))?;
    let account_id = add_options.account_id.or_else(|| {
        preset.and_then(|preset| {
            preset
                .fields
                .iter()
                .find(|field| field.field == "accountId")
                .and_then(|field| env::var(field.env_name).ok())
                .filter(|value| !value.trim().is_empty())
        })
    });

    upsert_api_token(
        vault_path,
        &passphrase,
        UpsertTokenInput {
            secret_ref: secret_ref.clone(),
            token,
            label: add_options
                .label
                .or_else(|| preset.map(|preset| preset.label.to_owned())),
            service_url: add_options
                .service_url
                .or_else(|| preset.map(|preset| preset.service_url.to_owned())),
            account_name: add_options.account_name,
            account_id,
            token_id: add_options.token_id,
            expires_on: add_options.expires_on,
            notes: add_options.notes,
        },
    )?;
    println!(
        "saved agvt://{}/{}/token",
        secret_ref.vault, secret_ref.item
    );
    Ok(())
}

fn parse_add_options(args: &[String]) -> Result<AddOptions> {
    let mut options = AddOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--from-stdin" | "--value-stdin" => options.from_stdin = true,
            "--from-env" | "--value-env" => {
                options.from_env = Some(validate_env_name(&take_value(
                    args,
                    index,
                    args[index].as_str(),
                )?)?);
                index += 1;
            }
            "--kind" => {
                options.kind = Some(take_value(args, index, "--kind")?);
                index += 1;
            }
            "--label" => {
                options.label = Some(take_value(args, index, "--label")?);
                index += 1;
            }
            "--service-url" => {
                options.service_url = Some(take_value(args, index, "--service-url")?);
                index += 1;
            }
            "--account" => {
                options.account_name = Some(take_value(args, index, "--account")?);
                index += 1;
            }
            "--account-id" => {
                options.account_id = Some(take_value(args, index, "--account-id")?);
                index += 1;
            }
            "--token-id" => {
                options.token_id = Some(take_value(args, index, "--token-id")?);
                index += 1;
            }
            "--expires-on" => {
                options.expires_on = Some(take_value(args, index, "--expires-on")?);
                index += 1;
            }
            "--notes" => {
                options.notes = Some(take_value(args, index, "--notes")?);
                index += 1;
            }
            "--field" => {
                let (field, value) = parse_field_assignment(&take_value(args, index, "--field")?)?;
                options.fields.push(FieldValue { field, value });
                index += 1;
            }
            "--field-env" => {
                let (field, env_name) =
                    parse_field_assignment(&take_value(args, index, "--field-env")?)?;
                options.field_envs.push(FieldEnvValue {
                    field,
                    env_name: validate_env_name(&env_name)?,
                });
                index += 1;
            }
            "--field-stdin" => {
                options.field_stdin = Some(canonical_payload_field(&take_value(
                    args,
                    index,
                    "--field-stdin",
                )?)?);
                index += 1;
            }
            "--vault" => {
                options.vault = Some(take_value(args, index, "--vault")?);
                index += 1;
            }
            option => return Err(AgvtError::new(format!("unknown add option: {option}"))),
        }
        index += 1;
    }
    Ok(options)
}

fn parse_field_assignment(value: &str) -> Result<(String, String)> {
    let (field, raw_value) = value
        .split_once('=')
        .ok_or_else(|| AgvtError::new("field assignment must be formatted as NAME=VALUE."))?;
    Ok((canonical_payload_field(field)?, raw_value.to_owned()))
}

fn read_token_value(options: &AddOptions, preset_env_name: Option<&str>) -> Result<String> {
    if options.from_stdin && options.from_env.is_some() {
        return Err(AgvtError::new(
            "use either --from-stdin or --from-env, not both.",
        ));
    }
    if options.from_stdin {
        return read_stdin();
    }
    if let Some(env_name) = &options.from_env {
        return env::var(env_name)
            .map_err(|_| AgvtError::new(format!("environment variable is missing: {env_name}")));
    }
    if let Some(env_name) = preset_env_name {
        if let Ok(value) = env::var(env_name) {
            if !value.trim().is_empty() {
                return Ok(value);
            }
        }
    }
    if !io::stdin().is_terminal() {
        return read_stdin();
    }
    Err(AgvtError::new(
        "token source is required. Use a preset env var, --from-env, or pipe with --from-stdin.",
    ))
}

fn read_secret_fields(kind: &str, options: &AddOptions) -> Result<BTreeMap<String, String>> {
    if options.from_stdin && options.field_stdin.is_some() {
        return Err(AgvtError::new(
            "use either --from-stdin or --field-stdin, not both.",
        ));
    }

    let mut fields = BTreeMap::new();
    for field in &options.fields {
        fields.insert(canonical_payload_field(&field.field)?, field.value.clone());
    }
    for field_env in &options.field_envs {
        let value = env::var(&field_env.env_name).map_err(|_| {
            AgvtError::new(format!(
                "environment variable is missing: {}",
                field_env.env_name
            ))
        })?;
        fields.insert(canonical_payload_field(&field_env.field)?, value);
    }

    let required_field = default_secret_value_field(kind)?;
    if options.from_stdin {
        fields.insert(required_field.to_owned(), read_stdin()?);
    }
    if let Some(env_name) = &options.from_env {
        fields.insert(
            required_field.to_owned(),
            env::var(env_name).map_err(|_| {
                AgvtError::new(format!("environment variable is missing: {env_name}"))
            })?,
        );
    }
    if let Some(field) = &options.field_stdin {
        fields.insert(canonical_payload_field(field)?, read_stdin()?);
    }

    insert_optional_field(&mut fields, "serviceUrl", &options.service_url)?;
    insert_optional_field(&mut fields, "accountName", &options.account_name)?;
    insert_optional_field(&mut fields, "accountId", &options.account_id)?;
    insert_optional_field(&mut fields, "tokenId", &options.token_id)?;
    insert_optional_field(&mut fields, "expiresOn", &options.expires_on)?;
    insert_optional_field(&mut fields, "notes", &options.notes)?;

    Ok(fields)
}

fn default_secret_value_field(kind: &str) -> Result<&'static str> {
    Ok(match validate_item_kind(kind)?.as_str() {
        "api-token" => "token",
        "login" => "password",
        "totp" => "secret",
        "ssh-key" => "privateKey",
        "custom" | "secret" => "secret",
        _ => "secret",
    })
}

fn insert_optional_field(
    fields: &mut BTreeMap<String, String>,
    field: &str,
    value: &Option<String>,
) -> Result<()> {
    if let Some(value) = value.as_ref().filter(|value| !value.trim().is_empty()) {
        fields.insert(canonical_payload_field(field)?, value.clone());
    }
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    Ok(value)
}

fn handle_read(options: &GlobalOptions) -> Result<()> {
    let Some(target) = options.args.first() else {
        return Err(AgvtError::new(
            "read requires an item name or secret reference.",
        ));
    };
    let field = options.args.get(1).map(String::as_str).unwrap_or("token");
    let secret_ref = item_target_to_ref(target, &options.default_vault, field)?;
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;
    println!(
        "{}",
        read_secret_field(vault_path, &passphrase, &secret_ref)?
    );
    Ok(())
}

fn handle_run(options: &GlobalOptions) -> Result<()> {
    let run_options = parse_run_options(&options.args, &options.default_vault)?;
    let source_env: BTreeMap<String, String> = env::vars().collect();
    let mut child_env = if run_options.clean_env {
        build_clean_environment(&source_env)
    } else {
        source_env.clone()
    };
    if run_options.clean_env {
        for (key, value) in &source_env {
            if value.trim().starts_with(SECRET_REF_PREFIX) {
                child_env.insert(key.clone(), value.clone());
            }
        }
    }

    let mut redactions = Vec::new();
    for mapping in run_options.mappings {
        let vault_path = path_for_secret_ref(options, &mapping.secret_ref);
        let passphrase = require_passphrase_for_path(vault_path)?;
        let value = read_secret_field(vault_path, &passphrase, &mapping.secret_ref)?;
        if value.trim().is_empty() && !mapping.required {
            continue;
        }
        if value.trim().is_empty() {
            return Err(AgvtError::new(format!(
                "required Vault field is empty for {}.",
                mapping.env_name
            )));
        }
        redactions.push(value.clone());
        child_env.insert(mapping.env_name, value);
    }
    redactions.extend(resolve_environment_secret_refs(
        options,
        &mut child_env,
        &options.default_vault,
    )?);
    child_env.remove(AGVT_PASSPHRASE_ENV);
    child_env.remove(LEGACY_PASSPHRASE_ENV);

    let status_code = execute_child_command(
        &run_options.command,
        child_env,
        run_options.redact_output,
        run_options.sandbox,
        &redactions,
    )?;

    std::process::exit(status_code);
}

struct EnvMapping {
    env_name: String,
    secret_ref: reference::SecretRef,
    required: bool,
}

#[derive(Clone, Copy)]
enum RunSandbox {
    NoNetwork,
}

struct RunOptions {
    mappings: Vec<EnvMapping>,
    command: Vec<String>,
    clean_env: bool,
    redact_output: bool,
    sandbox: Option<RunSandbox>,
}

fn parse_run_options(args: &[String], default_vault: &str) -> Result<RunOptions> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| AgvtError::new("run requires -- before the command."))?;
    let env_args = &args[..separator];
    let command = args[separator + 1..].to_vec();
    if command.is_empty() {
        return Err(AgvtError::new("run requires a command after --."));
    }

    let mut clean_env = false;
    let mut redact_output = false;
    let mut sandbox = None;
    let mut mappings = Vec::new();
    let mut index = 0;
    while index < env_args.len() {
        if env_args[index] == "--clean-env" {
            clean_env = true;
            index += 1;
            continue;
        }
        if env_args[index] == "--redact-output" {
            redact_output = true;
            index += 1;
            continue;
        }
        if env_args[index] == "--sandbox" {
            let value = take_value(env_args, index, "--sandbox")?;
            sandbox = Some(match value.as_str() {
                "no-network" => RunSandbox::NoNetwork,
                _ => {
                    return Err(AgvtError::new(
                        "--sandbox currently supports only `no-network`.",
                    ))
                }
            });
            index += 2;
            continue;
        }
        if env_args[index] == "--env" {
            let value = take_value(env_args, index, "--env")?;
            let (env_name, raw_ref) = value
                .split_once('=')
                .ok_or_else(|| AgvtError::new("--env must be formatted as ENV=ref."))?;
            mappings.push(EnvMapping {
                env_name: validate_env_name(env_name)?,
                secret_ref: item_target_to_ref(raw_ref, default_vault, "token")?,
                required: true,
            });
            index += 2;
            continue;
        }

        let preset = find_preset(&env_args[index]).ok_or_else(|| {
            AgvtError::new(format!(
                "unknown run preset: {}. Use --env ENV=ref for custom items.",
                env_args[index]
            ))
        })?;
        for field in preset.fields {
            mappings.push(EnvMapping {
                env_name: field.env_name.to_owned(),
                secret_ref: item_target_to_ref(preset.name, default_vault, field.field)?,
                required: field.required,
            });
        }
        index += 1;
    }
    Ok(RunOptions {
        mappings,
        command,
        clean_env,
        redact_output,
        sandbox,
    })
}

fn resolve_environment_secret_refs(
    options: &GlobalOptions,
    child_env: &mut BTreeMap<String, String>,
    default_vault: &str,
) -> Result<Vec<String>> {
    let keys: Vec<String> = child_env
        .iter()
        .filter(|(_key, value)| value.trim().starts_with(SECRET_REF_PREFIX))
        .map(|(key, _value)| key.clone())
        .collect();
    let mut redactions = Vec::new();
    for key in keys {
        if let Some(raw_ref) = child_env.get(&key).cloned() {
            let secret_ref = parse_secret_ref(&raw_ref, default_vault)?;
            let vault_path = path_for_secret_ref(options, &secret_ref);
            let passphrase = require_passphrase_for_path(vault_path)?;
            let value = read_secret_field(vault_path, &passphrase, &secret_ref)?;
            redactions.push(value.clone());
            child_env.insert(key, value);
        }
    }
    Ok(redactions)
}

fn build_clean_environment(source_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut clean = BTreeMap::new();
    for key in [
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TERM", "LANG",
    ] {
        if let Some(value) = source_env.get(key) {
            clean.insert(key.to_owned(), value.clone());
        }
    }
    for (key, value) in source_env {
        if key.starts_with("LC_") {
            clean.insert(key.clone(), value.clone());
        }
    }
    clean
}

fn execute_child_command(
    command: &[String],
    child_env: BTreeMap<String, String>,
    redact_output: bool,
    sandbox: Option<RunSandbox>,
    redactions: &[String],
) -> Result<i32> {
    let (program, args) = sandbox_command(command, sandbox)?;
    let mut child = Command::new(program);
    child
        .args(args)
        .env_clear()
        .envs(child_env)
        .stdin(Stdio::inherit());

    if redact_output {
        let output = child
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        print!(
            "{}",
            redact_text(&String::from_utf8_lossy(&output.stdout), redactions)
        );
        eprint!(
            "{}",
            redact_text(&String::from_utf8_lossy(&output.stderr), redactions)
        );
        return Ok(output.status.code().unwrap_or(1));
    }

    let status = child
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    Ok(status.code().unwrap_or(1))
}

fn sandbox_command(
    command: &[String],
    sandbox: Option<RunSandbox>,
) -> Result<(String, Vec<String>)> {
    match sandbox {
        None => Ok((command[0].clone(), command[1..].to_vec())),
        Some(RunSandbox::NoNetwork) => {
            if !cfg!(target_os = "macos") {
                return Err(AgvtError::new(
                    "--sandbox no-network is currently available only on macOS.",
                ));
            }
            let mut args = vec![
                "-p".to_owned(),
                "(version 1)\n(allow default)\n(deny network*)\n".to_owned(),
            ];
            args.extend_from_slice(command);
            Ok(("sandbox-exec".to_owned(), args))
        }
    }
}

fn redact_text(value: &str, redactions: &[String]) -> String {
    let mut output = value.to_owned();
    for secret in redactions {
        if secret.len() >= 4 {
            output = output.replace(secret, "[REDACTED]");
        }
    }
    output
}

#[derive(Default)]
pub(crate) struct ImportEnvOptions {
    presets: Vec<String>,
    pub(crate) env_files: Vec<String>,
    dry_run: bool,
    as_json: bool,
    preset_only: bool,
    pub(crate) no_env_file: bool,
}

pub(crate) struct ImportCandidate {
    pub(crate) item: String,
    pub(crate) label: String,
    service_url: Option<String>,
    token: String,
    account_id: Option<String>,
    pub(crate) source_envs: Vec<String>,
    pub(crate) source_kind: &'static str,
}

fn handle_import_env(options: &GlobalOptions) -> Result<()> {
    let import_options = parse_import_env_options(&options.args)?;
    let source_env = load_import_env_source(&import_options)?;
    let candidates = import_env_candidates(&source_env, &import_options)?;

    if import_options.dry_run {
        print_import_env_summary(&candidates, true, import_options.as_json)?;
        return Ok(());
    }

    if candidates.is_empty() {
        print_import_env_summary(&candidates, false, import_options.as_json)?;
        return Ok(());
    }

    for candidate in &candidates {
        let secret_ref = item_target_to_ref(&candidate.item, &options.default_vault, "token")?;
        let vault_path = path_for_secret_ref(options, &secret_ref);
        let passphrase = require_passphrase_for_path(vault_path)?;
        upsert_api_token(
            vault_path,
            &passphrase,
            UpsertTokenInput {
                secret_ref,
                token: candidate.token.clone(),
                label: Some(candidate.label.clone()),
                service_url: candidate.service_url.clone(),
                account_name: None,
                account_id: candidate.account_id.clone(),
                token_id: None,
                expires_on: None,
                notes: Some(format!(
                    "imported-by=agvt import-env;source-envs={}",
                    candidate.source_envs.join(",")
                )),
            },
        )?;
    }
    print_import_env_summary(&candidates, false, import_options.as_json)
}

fn parse_import_env_options(args: &[String]) -> Result<ImportEnvOptions> {
    let mut options = ImportEnvOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--env-file" => {
                options
                    .env_files
                    .push(take_value(args, index, "--env-file")?);
                index += 2;
            }
            "--dry-run" => {
                options.dry_run = true;
                index += 1;
            }
            "--json" => {
                options.as_json = true;
                index += 1;
            }
            "--preset-only" => {
                options.preset_only = true;
                index += 1;
            }
            "--no-env-file" => {
                options.no_env_file = true;
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(AgvtError::new(format!(
                    "unknown import-env option: {value}"
                )))
            }
            value => {
                options.presets.push(value.to_owned());
                index += 1;
            }
        }
    }
    Ok(options)
}

pub(crate) fn load_import_env_source(
    options: &ImportEnvOptions,
) -> Result<BTreeMap<String, String>> {
    let mut source_env: BTreeMap<String, String> = env::vars()
        .filter(|(_key, value)| !value.trim().is_empty())
        .collect();

    let env_files = if options.env_files.is_empty() && !options.no_env_file {
        default_import_env_files()
    } else {
        options.env_files.clone()
    };
    for env_file in env_files {
        load_dotenv_file(&env_file, &mut source_env)?;
    }
    Ok(source_env)
}

fn default_import_env_files() -> Vec<String> {
    [".env.local", ".env.development", ".env.production", ".env"]
        .iter()
        .filter(|path| Path::new(path).is_file())
        .map(|path| (*path).to_owned())
        .collect()
}

fn load_dotenv_file(path: &str, source_env: &mut BTreeMap<String, String>) -> Result<()> {
    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((raw_name, raw_value)) = assignment.split_once('=') else {
            continue;
        };
        let name = validate_env_name(raw_name.trim())?;
        let mut value = raw_value.trim().to_owned();
        if value.len() >= 2 {
            let quote = value.as_bytes()[0] as char;
            if matches!(quote, '"' | '\'') && value.ends_with(quote) {
                value = value[1..value.len() - 1].to_owned();
            }
        }
        if !value.trim().is_empty() {
            source_env.insert(name, value);
        }
    }
    Ok(())
}

pub(crate) fn import_env_candidates(
    source_env: &BTreeMap<String, String>,
    options: &ImportEnvOptions,
) -> Result<Vec<ImportCandidate>> {
    let selected_presets = selected_import_presets(&options.presets)?;
    let mut consumed_envs = Vec::new();
    let mut candidates = Vec::new();

    for preset in selected_presets {
        let mut source_envs = Vec::new();
        let mut account_id = None;
        let mut token = None;
        let mut missing_required = false;

        for field in preset.fields {
            match source_env.get(field.env_name) {
                Some(value) if !value.trim().is_empty() => {
                    source_envs.push(field.env_name.to_owned());
                    consumed_envs.push(field.env_name.to_owned());
                    match field.field {
                        "token" => token = Some(value.clone()),
                        "accountId" => account_id = Some(value.clone()),
                        _ => {}
                    }
                }
                _ if field.required => missing_required = true,
                _ => {}
            }
        }

        if missing_required {
            continue;
        }
        if let Some(token) = token {
            candidates.push(ImportCandidate {
                item: preset.name.to_owned(),
                label: preset.label.to_owned(),
                service_url: Some(preset.service_url.to_owned()),
                token,
                account_id,
                source_envs,
                source_kind: "preset",
            });
        }
    }

    if !options.preset_only && options.presets.is_empty() {
        for (env_name, value) in source_env {
            if consumed_envs.iter().any(|consumed| consumed == env_name)
                || !is_custom_secret_env_name(env_name)
            {
                continue;
            }
            candidates.push(ImportCandidate {
                item: env_name_to_item_name(env_name)?,
                label: env_name.clone(),
                service_url: None,
                token: value.clone(),
                account_id: None,
                source_envs: vec![env_name.clone()],
                source_kind: "custom",
            });
        }
    }

    candidates.sort_by(|left, right| left.item.cmp(&right.item));
    Ok(candidates)
}

pub(crate) fn selected_import_presets(names: &[String]) -> Result<Vec<&'static presets::Preset>> {
    if names.is_empty() {
        return Ok(PRESETS.iter().collect());
    }
    let mut selected = Vec::new();
    for name in names {
        selected.push(find_preset(name).ok_or_else(|| {
            AgvtError::new(format!(
                "unknown import-env preset: {name}. Use `agvt presets` to list presets."
            ))
        })?);
    }
    Ok(selected)
}

fn is_custom_secret_env_name(env_name: &str) -> bool {
    if env_name.starts_with("NEXT_PUBLIC_") || env_name.starts_with("PUBLIC_") {
        return false;
    }
    env_name.ends_with("_TOKEN")
        || env_name.ends_with("_API_KEY")
        || env_name.ends_with("_SECRET")
        || env_name.ends_with("_SECRET_KEY")
        || env_name.ends_with("_SERVICE_ROLE_KEY")
        || env_name.ends_with("_PASSWORD")
        || env_name.ends_with("_PRIVATE_KEY")
        || env_name == "DATABASE_URL"
}

fn env_name_to_item_name(env_name: &str) -> Result<String> {
    let item = env_name.to_ascii_lowercase().replace('_', "-");
    reference::validate_name(&item, "item")
}

fn print_import_env_summary(
    candidates: &[ImportCandidate],
    dry_run: bool,
    as_json: bool,
) -> Result<()> {
    if as_json {
        let imports: Vec<_> = candidates
            .iter()
            .map(|candidate| {
                serde_json::json!({
                    "item": candidate.item,
                    "label": candidate.label,
                    "sourceKind": candidate.source_kind,
                    "sourceEnvNames": candidate.source_envs,
                    "saved": !dry_run
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "imports": imports }))?
        );
        return Ok(());
    }

    if candidates.is_empty() {
        println!("No matching environment variables found.");
        return Ok(());
    }
    for candidate in candidates {
        let action = if dry_run { "would import" } else { "imported" };
        println!(
            "{} {}\t{}\t{}",
            action,
            candidate.item,
            candidate.source_kind,
            candidate.source_envs.join(",")
        );
    }
    Ok(())
}

fn handle_inject(options: &GlobalOptions) -> Result<()> {
    let inject_options = parse_inject_options(&options.args)?;
    let input = match inject_options.template.as_deref() {
        Some("-") | None => read_stdin()?,
        Some(path) => std::fs::read_to_string(path)?,
    };
    let mut output = input.clone();
    let refs = find_secret_refs(&input);
    if !refs.is_empty() && !inject_options.redact_output {
        eprintln!(
            "warning: inject prints resolved secret values. Use --redact-output to preview safely."
        );
    }
    for raw_ref in refs {
        let secret_ref = parse_secret_ref(&raw_ref, &options.default_vault)?;
        let vault_path = path_for_secret_ref(options, &secret_ref);
        let passphrase = require_passphrase_for_path(vault_path)?;
        let value = read_secret_field(vault_path, &passphrase, &secret_ref)?;
        let replacement = if inject_options.redact_output {
            "[REDACTED]"
        } else {
            &value
        };
        output = output.replace(&raw_ref, replacement);
    }
    print!("{output}");
    Ok(())
}

#[derive(Default)]
struct InjectOptions {
    template: Option<String>,
    redact_output: bool,
}

fn parse_inject_options(args: &[String]) -> Result<InjectOptions> {
    let mut options = InjectOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--redact-output" => options.redact_output = true,
            value if value.starts_with("--") => {
                return Err(AgvtError::new(format!("unknown inject option: {value}")))
            }
            value => {
                if options.template.is_some() {
                    return Err(AgvtError::new("inject accepts at most one template file."));
                }
                options.template = Some(value.to_owned());
            }
        }
        index += 1;
    }
    Ok(options)
}

fn handle_totp(options: &GlobalOptions) -> Result<()> {
    let Some(target) = options.args.first() else {
        return Err(AgvtError::new("totp requires an item or secret reference."));
    };
    let mut digits = None;
    let mut period = None;
    let mut index = 1;
    while index < options.args.len() {
        match options.args[index].as_str() {
            "--digits" => {
                digits = Some(
                    take_value(&options.args, index, "--digits")?
                        .parse::<u32>()
                        .map_err(|_| AgvtError::new("--digits must be a number."))?,
                );
                index += 2;
            }
            "--period" => {
                period = Some(
                    take_value(&options.args, index, "--period")?
                        .parse::<u64>()
                        .map_err(|_| AgvtError::new("--period must be a number."))?,
                );
                index += 2;
            }
            option => return Err(AgvtError::new(format!("unknown totp option: {option}"))),
        }
    }

    let secret_ref = item_target_to_ref(target, &options.default_vault, "secret")?;
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;
    let secret = read_secret_field(vault_path, &passphrase, &secret_ref)?;
    println!("{}", totp::current_totp_code(&secret, digits, period)?);
    Ok(())
}

fn handle_keychain(options: &GlobalOptions) -> Result<()> {
    let Some(command) = options.args.first().map(String::as_str) else {
        return Err(AgvtError::new("keychain requires set, status, or delete."));
    };
    match command {
        "set" => {
            let add_options = parse_add_options(&options.args[1..])?;
            let passphrase = if add_options.from_stdin {
                read_stdin()?
            } else if let Some(env_name) = add_options.from_env {
                env::var(&env_name).map_err(|_| {
                    AgvtError::new(format!("environment variable is missing: {env_name}"))
                })?
            } else {
                env::var(AGVT_PASSPHRASE_ENV)
                    .or_else(|_| env::var(LEGACY_PASSPHRASE_ENV))
                    .map_err(|_| {
                        AgvtError::new(
                            "keychain set requires AGVT_PASSPHRASE, --from-env, or --from-stdin.",
                        )
                    })?
            };
            let passphrase = validate_passphrase_value(&passphrase, "Keychain passphrase")?;
            let target = keychain::store_passphrase(&options.vault_path, &passphrase)?;
            println!(
                "stored passphrase in macOS Keychain service={} account={}",
                target.service, target.account
            );
            Ok(())
        }
        "status" => {
            let target = keychain::target_for_vault(&options.vault_path);
            let present = keychain::has_passphrase(&options.vault_path)?;
            println!(
                "{}\tservice={}\taccount={}",
                if present { "present" } else { "missing" },
                target.service,
                target.account
            );
            Ok(())
        }
        "delete" | "rm" => {
            let deleted = keychain::delete_passphrase(&options.vault_path)?;
            println!("{}", if deleted { "deleted" } else { "missing" });
            Ok(())
        }
        _ => Err(AgvtError::new("keychain requires set, status, or delete.")),
    }
}

#[derive(Default)]
struct CloudflareCreateOptions {
    item: Option<String>,
    name: Option<String>,
    policy_file: Option<String>,
    factory_token_env: Option<String>,
    factory_token_ref: Option<String>,
    account_id: Option<String>,
    expires_on: Option<String>,
    not_before: Option<String>,
    label: Option<String>,
}

fn handle_cloudflare(options: &GlobalOptions) -> Result<()> {
    let Some(command) = options.args.first().map(String::as_str) else {
        return Err(AgvtError::new("cloudflare requires create-token."));
    };
    match command {
        "create-token" => handle_cloudflare_create_token(options),
        _ => Err(AgvtError::new(
            "cloudflare currently supports create-token.",
        )),
    }
}

fn handle_cloudflare_create_token(options: &GlobalOptions) -> Result<()> {
    let create_options = parse_cloudflare_create_options(&options.args[1..])?;
    let item = create_options
        .item
        .clone()
        .ok_or_else(|| AgvtError::new("cloudflare create-token requires an item name."))?;
    let name = create_options
        .name
        .clone()
        .ok_or_else(|| AgvtError::new("cloudflare create-token requires --name."))?;
    let policy_file = create_options
        .policy_file
        .clone()
        .ok_or_else(|| AgvtError::new("cloudflare create-token requires --policy-file."))?;
    let factory_token = read_cloudflare_factory_token(options, &create_options)?;
    let created = create_user_token(CreateTokenInput {
        factory_token,
        name: name.clone(),
        policies: load_policy_file(&policy_file)?,
        expires_on: create_options.expires_on.clone(),
        not_before: create_options.not_before.clone(),
        condition: None,
    })?;
    let secret_ref = item_target_to_ref(&item, &options.default_vault, "token")?;
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;

    upsert_api_token(
        vault_path,
        &passphrase,
        UpsertTokenInput {
            secret_ref: secret_ref.clone(),
            token: created.value,
            label: create_options.label.or(Some(name)),
            service_url: Some("https://api.cloudflare.com/client/v4".to_owned()),
            account_name: None,
            account_id: create_options.account_id,
            token_id: created.id,
            expires_on: created.expires_on.or(create_options.expires_on),
            notes: Some(format!("created-by=agvt;policy-file={policy_file}")),
        },
    )?;
    println!(
        "created and saved agvt://{}/{}/token",
        secret_ref.vault, secret_ref.item
    );
    Ok(())
}

fn parse_cloudflare_create_options(args: &[String]) -> Result<CloudflareCreateOptions> {
    let mut options = CloudflareCreateOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                options.name = Some(take_value(args, index, "--name")?);
                index += 2;
            }
            "--policy-file" => {
                options.policy_file = Some(take_value(args, index, "--policy-file")?);
                index += 2;
            }
            "--factory-token-env" => {
                options.factory_token_env = Some(validate_env_name(&take_value(
                    args,
                    index,
                    "--factory-token-env",
                )?)?);
                index += 2;
            }
            "--factory-token-ref" => {
                options.factory_token_ref = Some(take_value(args, index, "--factory-token-ref")?);
                index += 2;
            }
            "--account-id" => {
                options.account_id = Some(take_value(args, index, "--account-id")?);
                index += 2;
            }
            "--expires-on" => {
                options.expires_on = Some(take_value(args, index, "--expires-on")?);
                index += 2;
            }
            "--not-before" => {
                options.not_before = Some(take_value(args, index, "--not-before")?);
                index += 2;
            }
            "--label" => {
                options.label = Some(take_value(args, index, "--label")?);
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(AgvtError::new(format!(
                    "unknown cloudflare create-token option: {value}"
                )))
            }
            value => {
                if options.item.is_some() {
                    return Err(AgvtError::new(
                        "cloudflare create-token accepts only one item name.",
                    ));
                }
                options.item = Some(value.to_owned());
                index += 1;
            }
        }
    }
    if options.factory_token_env.is_some() && options.factory_token_ref.is_some() {
        return Err(AgvtError::new(
            "use either --factory-token-env or --factory-token-ref, not both.",
        ));
    }
    Ok(options)
}

fn read_cloudflare_factory_token(
    options: &GlobalOptions,
    create_options: &CloudflareCreateOptions,
) -> Result<String> {
    if let Some(env_name) = &create_options.factory_token_env {
        return env::var(env_name)
            .map_err(|_| AgvtError::new(format!("environment variable is missing: {env_name}")));
    }
    if let Some(raw_ref) = &create_options.factory_token_ref {
        let secret_ref = item_target_to_ref(raw_ref, &options.default_vault, "token")?;
        let vault_path = path_for_secret_ref(options, &secret_ref);
        let passphrase = require_passphrase_for_path(vault_path)?;
        return read_secret_field(vault_path, &passphrase, &secret_ref);
    }
    env::var("CLOUDFLARE_TOKEN_FACTORY_TOKEN")
        .or_else(|_| env::var("CLOUDFLARE_API_TOKEN"))
        .map_err(|_| {
            AgvtError::new(
                "Cloudflare factory token is required. Use --factory-token-env, --factory-token-ref, CLOUDFLARE_TOKEN_FACTORY_TOKEN, or CLOUDFLARE_API_TOKEN.",
            )
        })
}

fn handle_list(options: &GlobalOptions) -> Result<()> {
    let as_json = options.args.iter().any(|arg| arg == "--json");
    let mut items = list_items(&options.vault_path)?;
    if !options.single_vault_path && options.global_vault_path != options.vault_path {
        items.extend(list_items(&options.global_vault_path)?);
    }
    if as_json {
        let json_items: Vec<_> = items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "vault": &item.vault,
                    "item": &item.item,
                    "kind": &item.kind,
                    "label": &item.label,
                    "updatedAt": &item.updated_at
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "items": json_items }))?
        );
        return Ok(());
    }

    if items.is_empty() {
        println!("No Agent Vault items.");
        return Ok(());
    }
    for item in items {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            item.vault, item.item, item.kind, item.label, item.updated_at
        );
    }
    Ok(())
}

fn handle_delete(options: &GlobalOptions) -> Result<()> {
    let Some(target) = options.args.first() else {
        return Err(AgvtError::new(
            "delete requires an item name or secret reference.",
        ));
    };
    let secret_ref = item_target_to_ref(target, &options.default_vault, "token")?;
    let vault_path = path_for_secret_ref(options, &secret_ref);
    let passphrase = require_passphrase_for_path(vault_path)?;
    delete_item(vault_path, &passphrase, &secret_ref)?;
    println!(
        "deleted agvt://{}/{}/token",
        secret_ref.vault, secret_ref.item
    );
    Ok(())
}

fn handle_presets(args: &[String]) -> Result<()> {
    let as_json = args.iter().any(|arg| arg == "--json");
    if as_json {
        let presets: Vec<_> = PRESETS
            .iter()
            .map(|preset| {
                serde_json::json!({
                    "name": preset.name,
                    "envName": preset.env_name,
                    "label": preset.label,
                    "serviceUrl": preset.service_url,
                    "fields": preset.fields.iter().map(|field| serde_json::json!({
                        "envName": field.env_name,
                        "field": field.field,
                        "required": field.required
                    })).collect::<Vec<_>>()
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "presets": presets }))?
        );
        return Ok(());
    }
    for preset in PRESETS {
        println!("{}\t{}\t{}", preset.name, preset.env_name, preset.label);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run_preset_mapping() {
        let options = parse_run_options(
            &["cloudflare".to_owned(), "--".to_owned(), "true".to_owned()],
            "dev",
        )
        .unwrap();
        assert_eq!(options.mappings[0].env_name, "CLOUDFLARE_API_TOKEN");
        assert_eq!(options.mappings[0].secret_ref.item, "cloudflare");
        assert_eq!(options.mappings[1].env_name, "CLOUDFLARE_ACCOUNT_ID");
        assert!(!options.mappings[1].required);
    }

    #[test]
    fn parses_run_custom_mapping() {
        let options = parse_run_options(
            &[
                "--env".to_owned(),
                "TOKEN=agvt://prod/api/token".to_owned(),
                "--clean-env".to_owned(),
                "--redact-output".to_owned(),
                "--".to_owned(),
                "true".to_owned(),
            ],
            "dev",
        )
        .unwrap();
        assert_eq!(options.mappings[0].env_name, "TOKEN");
        assert_eq!(options.mappings[0].secret_ref.vault, "prod");
        assert!(options.clean_env);
        assert!(options.redact_output);
    }
}
