use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

fn agvt_command(vault_path: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agvt"));
    command
        .arg("--vault-path")
        .arg(vault_path)
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length");
    command
}

#[test]
fn prints_japanese_and_english_help() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let ja_output = agvt_command(&vault_path)
        .args(["help", "ja"])
        .output()
        .unwrap();
    assert!(
        ja_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ja_output.stderr)
    );
    assert!(String::from_utf8_lossy(&ja_output.stdout).contains("よく使う流れ"));
    assert!(String::from_utf8_lossy(&ja_output.stdout).contains("openai, anthropic, vercel"));
    assert!(String::from_utf8_lossy(&ja_output.stdout).contains("token自動発行はCloudflare専用"));

    let en_output = agvt_command(&vault_path)
        .args(["help", "en"])
        .output()
        .unwrap();
    assert!(
        en_output.status.success(),
        "{}",
        String::from_utf8_lossy(&en_output.stderr)
    );
    assert!(String::from_utf8_lossy(&en_output.stdout).contains("Common flows"));
    assert!(String::from_utf8_lossy(&en_output.stdout).contains("openai, anthropic, vercel"));
    assert!(String::from_utf8_lossy(&en_output.stdout)
        .contains("Automatic token creation is Cloudflare-only"));
}

#[test]
fn keychain_set_rejects_short_passphrase_before_storing() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(vault_path)
        .args(["keychain", "set"])
        .env("AGVT_PASSPHRASE", "short")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Keychain passphrase must be at least 24 characters."));
}

#[test]
fn short_secret_references_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let output = agvt_command(&vault_path)
        .args(["read", "agvt://cloudflare/token"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("short secret references are disabled")
    );
}

#[test]
fn global_refs_use_global_path_without_single_vault_override() {
    let directory = tempfile::tempdir().unwrap();
    let xdg_data_home = directory.path().join("xdg-data");
    let global_vault_path = xdg_data_home.join("agvt").join("agent-vault.json");
    let local_vault_path = directory.path().join(".local").join("agent-vault.json");

    let add_output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .current_dir(directory.path())
        .env_clear()
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .env("XDG_DATA_HOME", &xdg_data_home)
        .env("CLOUDFLARE_API_TOKEN", "global_cloudflare_dummy_secret")
        .args(["add", "agvt://global/cloudflare/token"])
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(global_vault_path.exists());
    assert!(!local_vault_path.exists());

    let read_output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .current_dir(directory.path())
        .env_clear()
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["read", "agvt://global/cloudflare/token"])
        .output()
        .unwrap();
    assert!(
        read_output.status.success(),
        "{}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&read_output.stdout).trim(),
        "global_cloudflare_dummy_secret"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn keychain_status_reports_missing_for_never_created_item() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let account = format!("missing-check-{}", std::process::id());

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(vault_path)
        .args(["keychain", "status"])
        .env("AGVT_KEYCHAIN_SERVICE", "agvt-codex-missing-test")
        .env("AGVT_KEYCHAIN_ACCOUNT", account)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("missing"));
}

#[test]
fn cloudflare_preset_round_trip_and_run() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "cloudflare"])
        .env("CLOUDFLARE_API_TOKEN", "cloudflare_dummy_secret")
        .env("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let raw_vault = fs::read_to_string(&vault_path).unwrap();
    assert!(!raw_vault.contains("cloudflare_dummy_secret"));
    assert!(!raw_vault.contains("api.cloudflare.com"));

    let read_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/cloudflare/token"])
        .output()
        .unwrap();
    assert!(
        read_output.status.success(),
        "{}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&read_output.stdout).trim(),
        "cloudflare_dummy_secret"
    );

    let run_output = agvt_command(&vault_path)
        .args([
            "run",
            "cloudflare",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$CLOUDFLARE_API_TOKEN\" \"$CLOUDFLARE_ACCOUNT_ID\" \"$AGVT_PASSPHRASE\"",
        ])
        .output()
        .unwrap();
    assert!(
        run_output.status.success(),
        "{}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&run_output.stdout),
        "cloudflare_dummy_secret|cloudflare_account_id|"
    );
}

#[test]
fn provider_presets_round_trip_and_run() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let providers = [
        ("openai", "OPENAI_API_KEY", "openai_dummy_secret"),
        ("anthropic", "ANTHROPIC_API_KEY", "anthropic_dummy_secret"),
        ("vercel", "VERCEL_TOKEN", "vercel_dummy_secret"),
        ("stripe", "STRIPE_API_KEY", "stripe_dummy_secret"),
        ("slack", "SLACK_BOT_TOKEN", "slack_dummy_secret"),
    ];

    for (preset, env_name, secret) in providers {
        let add_output = agvt_command(&vault_path)
            .args(["add", preset])
            .env(env_name, secret)
            .output()
            .unwrap();
        assert!(
            add_output.status.success(),
            "{}",
            String::from_utf8_lossy(&add_output.stderr)
        );

        let raw_vault = fs::read_to_string(&vault_path).unwrap();
        assert!(!raw_vault.contains(secret));

        let read_ref = format!("agvt://dev/{preset}/token");
        let read_output = agvt_command(&vault_path)
            .args(["read", &read_ref])
            .output()
            .unwrap();
        assert!(
            read_output.status.success(),
            "{}",
            String::from_utf8_lossy(&read_output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&read_output.stdout).trim(), secret);

        let print_env = format!("printf '%s' \"${env_name}\"");
        let run_output = agvt_command(&vault_path)
            .args(["run", preset, "--", "sh", "-c", &print_env])
            .output()
            .unwrap();
        assert!(
            run_output.status.success(),
            "{}",
            String::from_utf8_lossy(&run_output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&run_output.stdout), secret);
    }
}

#[test]
fn presets_json_lists_provider_presets() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let output = agvt_command(&vault_path)
        .args(["presets", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let presets = parsed["presets"].as_array().unwrap();
    for (name, env_name) in [
        ("cloudflare", "CLOUDFLARE_API_TOKEN"),
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("vercel", "VERCEL_TOKEN"),
        ("stripe", "STRIPE_API_KEY"),
        ("slack", "SLACK_BOT_TOKEN"),
        ("github", "GITHUB_TOKEN"),
    ] {
        let preset = presets
            .iter()
            .find(|preset| preset["name"] == name)
            .unwrap_or_else(|| panic!("missing preset: {name}"));
        assert_eq!(preset["envName"], env_name);
    }
}

#[test]
fn import_env_dry_run_reads_local_env_without_printing_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    fs::write(
        directory.path().join(".env.local"),
        [
            "OPENAI_API_KEY=openai_dummy_secret",
            "STRIPE_SECRET_KEY=stripe_dummy_secret",
            "DATABASE_URL=postgres://dummy_secret@localhost/app",
            "NEXT_PUBLIC_SUPABASE_ANON_KEY=public_value",
        ]
        .join("\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(&vault_path)
        .args(["import-env", "--dry-run"])
        .current_dir(directory.path())
        .env_clear()
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would import openai\tpreset\tOPENAI_API_KEY"));
    assert!(stdout.contains("would import stripe-secret-key\tcustom\tSTRIPE_SECRET_KEY"));
    assert!(stdout.contains("would import database-url\tcustom\tDATABASE_URL"));
    assert!(!stdout.contains("openai_dummy_secret"));
    assert!(!stdout.contains("stripe_dummy_secret"));
    assert!(!stdout.contains("public_value"));
    assert!(!vault_path.exists());
}

#[test]
fn import_env_saves_preset_and_custom_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    fs::write(
        directory.path().join(".env.local"),
        [
            "CLOUDFLARE_API_TOKEN=cloudflare_dummy_secret",
            "CLOUDFLARE_ACCOUNT_ID=cloudflare_account_id",
            "ADMIN_SECRET=admin_dummy_secret",
        ]
        .join("\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(&vault_path)
        .args(["import-env"])
        .current_dir(directory.path())
        .env_clear()
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("imported cloudflare\tpreset\tCLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID")
    );
    assert!(stdout.contains("imported admin-secret\tcustom\tADMIN_SECRET"));

    let raw_vault = fs::read_to_string(&vault_path).unwrap();
    assert!(!raw_vault.contains("cloudflare_dummy_secret"));
    assert!(!raw_vault.contains("cloudflare_account_id"));
    assert!(!raw_vault.contains("admin_dummy_secret"));

    let token_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/cloudflare/token"])
        .output()
        .unwrap();
    assert!(
        token_output.status.success(),
        "{}",
        String::from_utf8_lossy(&token_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&token_output.stdout).trim(),
        "cloudflare_dummy_secret"
    );

    let account_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/cloudflare/account-id"])
        .output()
        .unwrap();
    assert!(
        account_output.status.success(),
        "{}",
        String::from_utf8_lossy(&account_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&account_output.stdout).trim(),
        "cloudflare_account_id"
    );

    let custom_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/admin-secret/token"])
        .output()
        .unwrap();
    assert!(
        custom_output.status.success(),
        "{}",
        String::from_utf8_lossy(&custom_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&custom_output.stdout).trim(),
        "admin_dummy_secret"
    );
}

#[test]
fn prepare_diagnoses_manifest_requirements_without_printing_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    fs::write(
        directory.path().join("agvt.toml"),
        [
            "[prepare]",
            "presets = [\"cloudflare\", \"openai\"]",
            "",
            "[[prepare.secrets]]",
            "item = \"admin-secret\"",
            "field = \"token\"",
            "env = \"ADMIN_SECRET\"",
            "required = true",
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(
        directory.path().join(".env.local"),
        [
            "OPENAI_API_KEY=openai_dummy_secret",
            "ADMIN_SECRET=admin_dummy_secret",
        ]
        .join("\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(&vault_path)
        .args(["prepare", "--dry-run"])
        .current_dir(directory.path())
        .env_clear()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("manifest: agvt.toml"));
    assert!(stdout.contains("vault: missing"));
    assert!(stdout.contains("importable:"));
    assert!(stdout.contains("openai.token\trequired\tOPENAI_API_KEY"));
    assert!(stdout.contains("admin-secret.token\trequired\tADMIN_SECRET"));
    assert!(stdout.contains("missing:"));
    assert!(stdout.contains("cloudflare.token\trequired\tCLOUDFLARE_API_TOKEN"));
    assert!(stdout.contains("agvt import-env --dry-run"));
    assert!(stdout.contains("agvt add cloudflare --from-stdin"));
    assert!(!stdout.contains("openai_dummy_secret"));
    assert!(!stdout.contains("admin_dummy_secret"));
    assert!(!vault_path.exists());
}

#[test]
fn prepare_json_reports_present_vault_fields_without_printing_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "cloudflare"])
        .env("CLOUDFLARE_API_TOKEN", "cloudflare_dummy_secret")
        .env("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(&vault_path)
        .args([
            "prepare",
            "cloudflare",
            "--json",
            "--no-manifest",
            "--no-env-file",
        ])
        .current_dir(directory.path())
        .env_clear()
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("cloudflare_dummy_secret"));
    assert!(!stdout.contains("cloudflare_account_id"));

    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["vault"]["status"], "ready");
    let requirements = parsed["requirements"].as_array().unwrap();
    let token = requirements
        .iter()
        .find(|requirement| requirement["item"] == "cloudflare" && requirement["field"] == "token")
        .unwrap();
    assert_eq!(token["status"], "present");
    assert_eq!(token["source"], "vault");
    let account_id = requirements
        .iter()
        .find(|requirement| {
            requirement["item"] == "cloudflare" && requirement["field"] == "accountId"
        })
        .unwrap();
    assert_eq!(account_id["status"], "present");
    assert_eq!(parsed["suggestedCommands"].as_array().unwrap().len(), 0);
}

#[test]
fn writes_relative_vault_path_without_parent_directory() {
    let directory = tempfile::tempdir().unwrap();

    let add_output = agvt_command(Path::new("agent-vault.json"))
        .current_dir(directory.path())
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(directory.path().join("agent-vault.json").exists());
    assert!(!directory.path().join("agent-vault.json.lock").exists());
}

#[test]
fn run_resolves_environment_secret_references() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let run_output = agvt_command(&vault_path)
        .args(["run", "--", "sh", "-c", "printf '%s' \"$GITHUB_TOKEN\""])
        .env("GITHUB_TOKEN", "agvt://dev/github/token")
        .output()
        .unwrap();
    assert!(
        run_output.status.success(),
        "{}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&run_output.stdout),
        "github_dummy_secret"
    );
}

#[test]
fn stores_totp_items_and_reads_secret_fields() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args([
            "add",
            "github-totp",
            "--kind",
            "totp",
            "--from-env",
            "TOTP_SECRET",
            "--field",
            "issuer=GitHub",
            "--account",
            "deploy-bot",
        ])
        .env("TOTP_SECRET", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&add_output.stdout).contains("saved agvt://dev/github-totp/secret")
    );

    let read_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/github-totp/issuer"])
        .output()
        .unwrap();
    assert!(
        read_output.status.success(),
        "{}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&read_output.stdout).trim(),
        "GitHub"
    );
}

#[test]
fn run_can_redact_output_and_use_clean_environment() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let run_output = agvt_command(&vault_path)
        .args([
            "run",
            "--env",
            "TOKEN=github",
            "--clean-env",
            "--redact-output",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$TOKEN\" \"${LEAK_ME:-}\"",
        ])
        .env("LEAK_ME", "should_not_pass")
        .output()
        .unwrap();
    assert!(
        run_output.status.success(),
        "{}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run_output.stdout), "[REDACTED]|");
}

#[test]
fn inject_replaces_secret_refs() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let template_path = directory.path().join("template.env");

    let add_output = agvt_command(&vault_path)
        .args(["add", "cloudflare"])
        .env("CLOUDFLARE_API_TOKEN", "cloudflare_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    fs::write(&template_path, "TOKEN=agvt://dev/cloudflare/token\n").unwrap();
    let inject_output = agvt_command(&vault_path)
        .args(["inject"])
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        inject_output.status.success(),
        "{}",
        String::from_utf8_lossy(&inject_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&inject_output.stdout),
        "TOKEN=cloudflare_dummy_secret\n"
    );
    assert!(String::from_utf8_lossy(&inject_output.stderr)
        .contains("inject prints resolved secret values"));

    let redacted_output = agvt_command(&vault_path)
        .args(["inject", "--redact-output"])
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        redacted_output.status.success(),
        "{}",
        String::from_utf8_lossy(&redacted_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&redacted_output.stdout),
        "TOKEN=[REDACTED]\n"
    );
    assert!(String::from_utf8_lossy(&redacted_output.stderr).is_empty());
}

#[test]
fn global_read_of_bare_added_item_hints_vault_tag_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let read_output = agvt_command(&vault_path)
        .args(["read", "agvt://global/github/token"])
        .output()
        .unwrap();
    assert!(!read_output.status.success());
    let stderr = String::from_utf8_lossy(&read_output.stderr);
    assert!(stderr.contains("Vault item not found: global:github"));
    assert!(stderr.contains("agvt://dev/github/token"));
    assert!(stderr.contains("full reference"));
    assert!(!stderr.contains("github_dummy_secret"));
}

#[test]
fn delete_with_wrong_vault_tag_fails_with_hint() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let delete_output = agvt_command(&vault_path)
        .args(["delete", "agvt://global/github/token"])
        .output()
        .unwrap();
    assert!(!delete_output.status.success());
    let stderr = String::from_utf8_lossy(&delete_output.stderr);
    assert!(stderr.contains("Vault item not found: global:github"));
    assert!(stderr.contains("agvt://dev/github/token"));

    let list_output = agvt_command(&vault_path)
        .args(["ls", "--json"])
        .output()
        .unwrap();
    assert!(list_output.status.success());
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("\"item\": \"github\""));
}

#[test]
fn file_kind_round_trip_stores_base64_and_decodes_raw_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("AuthKey_TEST.p12");
    let key_bytes: Vec<u8> = (0..=255u8).cycle().take(600).collect();
    fs::write(&key_path, &key_bytes).unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "apple-signing-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(String::from_utf8_lossy(&add_output.stdout)
        .contains("saved agvt://dev/apple-signing-key/content"));

    let list_output = agvt_command(&vault_path)
        .args(["ls", "--json"])
        .output()
        .unwrap();
    assert!(list_output.status.success());
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("\"kind\": \"file\""));

    let filename_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/apple-signing-key/filename"])
        .output()
        .unwrap();
    assert!(
        filename_output.status.success(),
        "{}",
        String::from_utf8_lossy(&filename_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&filename_output.stdout).trim(),
        "AuthKey_TEST.p12"
    );

    let decode_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/apple-signing-key/content", "--decode"])
        .output()
        .unwrap();
    assert!(
        decode_output.status.success(),
        "{}",
        String::from_utf8_lossy(&decode_output.stderr)
    );
    assert_eq!(decode_output.stdout, key_bytes);
}

#[test]
fn read_decode_rejects_non_base64_fields() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "not+base64!!token")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let decode_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/github/token", "--decode"])
        .output()
        .unwrap();
    assert!(!decode_output.status.success());
    assert!(String::from_utf8_lossy(&decode_output.stderr)
        .contains("--decode requires a base64-encoded field value"));
}

#[test]
fn read_decode_of_missing_field_fails_instead_of_writing_empty_output() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("key.p8");
    fs::write(&key_path, b"dummy-key-bytes").unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "apple-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let decode_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/apple-key/notes", "--decode"])
        .output()
        .unwrap();
    assert!(!decode_output.status.success());
    assert!(decode_output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&decode_output.stderr)
        .contains("field `notes` is empty or missing"));
}

#[test]
fn from_file_rejects_files_over_the_raw_size_limit() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("too-large.p12");
    fs::write(&key_path, vec![0_u8; 97 * 1024]).unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "too-large-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(!add_output.status.success());
    assert!(String::from_utf8_lossy(&add_output.stderr).contains("file is too large"));
}

#[test]
fn from_file_requires_file_kind() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("key.pem");
    fs::write(&key_path, b"dummy").unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "some-key", "--kind", "ssh-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(!add_output.status.success());
    assert!(String::from_utf8_lossy(&add_output.stderr)
        .contains("--from-file is only supported with --kind file."));
}

#[test]
fn help_documents_vault_scope_and_file_kind() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let en_output = agvt_command(&vault_path)
        .args(["help", "en"])
        .output()
        .unwrap();
    assert!(en_output.status.success());
    let en_stdout = String::from_utf8_lossy(&en_output.stdout);
    assert!(en_stdout.contains("Vault scope comes from the reference"));
    assert!(en_stdout.contains("--from-file PATH"));
    assert!(en_stdout.contains("--decode"));

    let ja_output = agvt_command(&vault_path)
        .args(["help", "ja"])
        .output()
        .unwrap();
    assert!(ja_output.status.success());
    let ja_stdout = String::from_utf8_lossy(&ja_output.stdout);
    assert!(ja_stdout.contains("vault scopeは参照で指定する"));
    assert!(ja_stdout.contains("--from-file PATH"));
    assert!(ja_stdout.contains("--decode"));
}

#[test]
fn concurrent_writes_keep_all_items() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let mut cloudflare_command = agvt_command(&vault_path);
    cloudflare_command
        .args(["add", "cloudflare"])
        .env("CLOUDFLARE_API_TOKEN", "cloudflare_dummy_secret")
        .env("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let cloudflare_child = cloudflare_command.spawn().unwrap();

    let mut github_command = agvt_command(&vault_path);
    github_command
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let github_output = github_command.output().unwrap();
    let cloudflare_output = cloudflare_child.wait_with_output().unwrap();

    assert!(
        cloudflare_output.status.success(),
        "{}",
        String::from_utf8_lossy(&cloudflare_output.stderr)
    );
    assert!(
        github_output.status.success(),
        "{}",
        String::from_utf8_lossy(&github_output.stderr)
    );

    let list_output = agvt_command(&vault_path)
        .args(["ls", "--json"])
        .output()
        .unwrap();
    assert!(
        list_output.status.success(),
        "{}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains("\"item\": \"cloudflare\""));
    assert!(list_stdout.contains("\"item\": \"github\""));
    assert!(!vault_path.with_file_name("agent-vault.json.lock").exists());
}
