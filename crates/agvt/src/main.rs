mod error;
mod presets;
mod reference;
mod vault;

use std::collections::BTreeMap;
use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use error::{AgvtError, Result};
use presets::{find_preset, PRESETS};
use reference::{
    find_secret_refs, item_target_to_ref, parse_secret_ref, validate_env_name, DEFAULT_VAULT_NAME,
    SECRET_REF_PREFIX,
};
use vault::{
    default_vault_path, delete_item, list_items, read_api_token_field, require_passphrase,
    upsert_api_token, UpsertTokenInput, AGVT_PASSPHRASE_ENV, LEGACY_PASSPHRASE_ENV,
};

const USAGE: &str = r#"Usage:
  agvt add cloudflare
  agvt add <item-or-ref> [--from-stdin | --from-env ENV] [--label TEXT] [--service-url URL] [--account TEXT] [--notes TEXT]
  agvt read <agvt://vault/item/field | item> [field]
  agvt run [preset] [--env ENV=ref] -- <command> [args...]
  agvt inject [template-file|-]
  agvt ls [--json]
  agvt delete <item-or-ref>
  agvt presets [--json]

Secret refs:
  agvt://dev/cloudflare/token
  agvt://cloudflare/token       # defaults to dev vault

Environment:
  AGVT_PASSPHRASE, AGVT_PATH
  AUTOFILL_AGENT_VAULT_PASSPHRASE and AUTOFILL_AGENT_VAULT_PATH are still accepted.
"#;

#[derive(Debug)]
struct GlobalOptions {
    vault_path: PathBuf,
    default_vault: String,
    command: String,
    args: Vec<String>,
}

#[derive(Default)]
struct AddOptions {
    from_stdin: bool,
    from_env: Option<String>,
    label: Option<String>,
    service_url: Option<String>,
    account_name: Option<String>,
    notes: Option<String>,
    vault: Option<String>,
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
            print!("{USAGE}");
            Ok(())
        }
        "add" | "put" => handle_add(&options),
        "read" | "get" => handle_read(&options),
        "run" => handle_run(&options),
        "inject" => handle_inject(&options),
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
    let mut default_vault = DEFAULT_VAULT_NAME.to_owned();
    let index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--vault-path" => {
                vault_path = PathBuf::from(take_value(&args, index, "--vault-path")?);
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
        default_vault,
        command,
        args,
    })
}

fn take_value(args: &[String], index: usize, option: &str) -> Result<String> {
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
    let token = read_token_value(&add_options, preset.map(|preset| preset.env_name))?;
    let passphrase = require_passphrase()?;

    upsert_api_token(
        &options.vault_path,
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
            "--notes" => {
                options.notes = Some(take_value(args, index, "--notes")?);
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
    let passphrase = require_passphrase()?;
    println!(
        "{}",
        read_api_token_field(&options.vault_path, &passphrase, &secret_ref)?
    );
    Ok(())
}

fn handle_run(options: &GlobalOptions) -> Result<()> {
    let separator = options
        .args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| AgvtError::new("run requires -- before the command."))?;
    let env_args = &options.args[..separator];
    let command = &options.args[separator + 1..];
    if command.is_empty() {
        return Err(AgvtError::new("run requires a command after --."));
    }

    let passphrase = require_passphrase()?;
    let mut child_env: BTreeMap<String, String> = env::vars().collect();
    for mapping in parse_run_mappings(env_args, &options.default_vault)? {
        let value = read_api_token_field(&options.vault_path, &passphrase, &mapping.secret_ref)?;
        child_env.insert(mapping.env_name, value);
    }
    resolve_environment_secret_refs(
        &options.vault_path,
        &passphrase,
        &mut child_env,
        &options.default_vault,
    )?;
    child_env.remove(AGVT_PASSPHRASE_ENV);
    child_env.remove(LEGACY_PASSPHRASE_ENV);

    let status = Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(child_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
}

struct EnvMapping {
    env_name: String,
    secret_ref: reference::SecretRef,
}

fn parse_run_mappings(args: &[String], default_vault: &str) -> Result<Vec<EnvMapping>> {
    let mut mappings = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--env" {
            let value = take_value(args, index, "--env")?;
            let (env_name, raw_ref) = value
                .split_once('=')
                .ok_or_else(|| AgvtError::new("--env must be formatted as ENV=ref."))?;
            mappings.push(EnvMapping {
                env_name: validate_env_name(env_name)?,
                secret_ref: item_target_to_ref(raw_ref, default_vault, "token")?,
            });
            index += 2;
            continue;
        }

        let preset = find_preset(&args[index]).ok_or_else(|| {
            AgvtError::new(format!(
                "unknown run preset: {}. Use --env ENV=ref for custom items.",
                args[index]
            ))
        })?;
        mappings.push(EnvMapping {
            env_name: preset.env_name.to_owned(),
            secret_ref: item_target_to_ref(preset.name, default_vault, "token")?,
        });
        index += 1;
    }
    Ok(mappings)
}

fn resolve_environment_secret_refs(
    vault_path: &Path,
    passphrase: &str,
    child_env: &mut BTreeMap<String, String>,
    default_vault: &str,
) -> Result<()> {
    let keys: Vec<String> = child_env
        .iter()
        .filter(|(_key, value)| value.trim().starts_with(SECRET_REF_PREFIX))
        .map(|(key, _value)| key.clone())
        .collect();
    for key in keys {
        if let Some(raw_ref) = child_env.get(&key).cloned() {
            let secret_ref = parse_secret_ref(&raw_ref, default_vault)?;
            let value = read_api_token_field(vault_path, passphrase, &secret_ref)?;
            child_env.insert(key, value);
        }
    }
    Ok(())
}

fn handle_inject(options: &GlobalOptions) -> Result<()> {
    let input = match options.args.first().map(String::as_str) {
        Some("-") | None => read_stdin()?,
        Some(path) => std::fs::read_to_string(path)?,
    };
    let passphrase = require_passphrase()?;
    let mut output = input.clone();
    for raw_ref in find_secret_refs(&input) {
        let secret_ref = parse_secret_ref(&raw_ref, &options.default_vault)?;
        let value = read_api_token_field(&options.vault_path, &passphrase, &secret_ref)?;
        output = output.replace(&raw_ref, &value);
    }
    print!("{output}");
    Ok(())
}

fn handle_list(options: &GlobalOptions) -> Result<()> {
    let as_json = options.args.iter().any(|arg| arg == "--json");
    let items = list_items(&options.vault_path)?;
    if as_json {
        let json_items: Vec<_> = items
            .iter()
            .map(|(vault, item, label, updated_at)| {
                serde_json::json!({
                    "vault": vault,
                    "item": item,
                    "label": label,
                    "updatedAt": updated_at
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
    for (vault, item, label, updated_at) in items {
        println!("{vault}\t{item}\t{label}\t{updated_at}");
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
    let passphrase = require_passphrase()?;
    delete_item(&options.vault_path, &passphrase, &secret_ref)?;
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
                    "serviceUrl": preset.service_url
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
        let mappings = parse_run_mappings(&["cloudflare".to_owned()], "dev").unwrap();
        assert_eq!(mappings[0].env_name, "CLOUDFLARE_API_TOKEN");
        assert_eq!(mappings[0].secret_ref.item, "cloudflare");
    }

    #[test]
    fn parses_run_custom_mapping() {
        let mappings = parse_run_mappings(
            &["--env".to_owned(), "TOKEN=agvt://prod/api/token".to_owned()],
            "dev",
        )
        .unwrap();
        assert_eq!(mappings[0].env_name, "TOKEN");
        assert_eq!(mappings[0].secret_ref.vault, "prod");
    }
}
