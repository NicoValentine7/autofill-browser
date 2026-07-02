use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

fn agvt_command(vault_path: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agvt"));
    command
        .arg("--vault-path")
        .arg(vault_path)
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        // Keep test audit entries out of the real user audit log.
        .env("AGVT_AUDIT_PATH", vault_path.with_file_name("audit.jsonl"));
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
fn audit_log_records_vault_operations_append_only_without_secret_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let audit_path = directory.path().join("audit.jsonl");
    let template_path = directory.path().join("template.env");

    // add
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
    let after_add = fs::read_to_string(&audit_path).unwrap();
    assert_eq!(after_add.lines().count(), 1);
    assert!(after_add.contains("\"op\":\"add\""));
    assert!(after_add.contains("agvt://dev/cloudflare/token"));

    // read (append-only: previous content stays byte-identical)
    let read_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/cloudflare/token"])
        .output()
        .unwrap();
    assert!(read_output.status.success());
    let after_read = fs::read_to_string(&audit_path).unwrap();
    assert!(after_read.starts_with(&after_add));
    assert_eq!(after_read.lines().count(), 2);
    assert!(after_read.contains("\"op\":\"read\""));

    // run with an explicit --env mapping
    let run_output = agvt_command(&vault_path)
        .args([
            "run",
            "--env",
            "TOKEN=agvt://dev/cloudflare/token",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .output()
        .unwrap();
    assert!(run_output.status.success());
    let after_run = fs::read_to_string(&audit_path).unwrap();
    assert!(after_run.starts_with(&after_read));
    assert_eq!(after_run.lines().count(), 3);
    assert!(after_run.contains("\"op\":\"run\""));
    assert!(after_run.contains("\"caller\":\"sh\""));

    // run resolving an agvt:// ref already present in the environment
    let env_run_output = agvt_command(&vault_path)
        .args(["run", "--", "sh", "-c", "true"])
        .env("EXTRA_TOKEN", "agvt://dev/cloudflare/token")
        .output()
        .unwrap();
    assert!(env_run_output.status.success());
    let after_env_run = fs::read_to_string(&audit_path).unwrap();
    assert!(after_env_run.starts_with(&after_run));
    assert_eq!(after_env_run.lines().count(), 4);

    // inject
    fs::write(&template_path, "TOKEN=agvt://dev/cloudflare/token\n").unwrap();
    let inject_output = agvt_command(&vault_path)
        .args(["inject", "--redact-output"])
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(inject_output.status.success());
    let after_inject = fs::read_to_string(&audit_path).unwrap();
    assert!(after_inject.starts_with(&after_env_run));
    assert_eq!(after_inject.lines().count(), 5);
    assert!(after_inject.contains("\"op\":\"inject\""));

    // delete
    let delete_output = agvt_command(&vault_path)
        .args(["delete", "cloudflare"])
        .output()
        .unwrap();
    assert!(delete_output.status.success());
    let after_delete = fs::read_to_string(&audit_path).unwrap();
    assert!(after_delete.starts_with(&after_inject));
    assert_eq!(after_delete.lines().count(), 6);
    assert!(after_delete.contains("\"op\":\"delete\""));

    // secret values never reach the audit log
    assert!(!after_delete.contains("cloudflare_dummy_secret"));

    // every line is valid JSON with the expected non-secret fields only
    for line in after_delete.lines() {
        let entry: Value = serde_json::from_str(line).unwrap();
        assert!(entry["ts"].as_u64().unwrap() > 0);
        assert!(entry["ref"]
            .as_str()
            .unwrap()
            .starts_with("agvt://dev/cloudflare/"));
        assert!(!entry["op"].as_str().unwrap().is_empty());
        assert!(!entry["caller"].as_str().unwrap().is_empty());
        assert_eq!(entry["schemaVersion"], 1);
    }
}

#[test]
fn audit_log_records_import_env_operations() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let audit_path = directory.path().join("audit.jsonl");
    fs::write(
        directory.path().join(".env.local"),
        [
            "CLOUDFLARE_API_TOKEN=cloudflare_dummy_secret",
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
        .env("AGVT_AUDIT_PATH", &audit_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let audit_raw = fs::read_to_string(&audit_path).unwrap();
    assert_eq!(audit_raw.lines().count(), 2);
    assert!(audit_raw.contains("\"op\":\"import-env\""));
    assert!(audit_raw.contains("agvt://dev/cloudflare/token"));
    assert!(audit_raw.contains("agvt://dev/admin-secret/token"));
    assert!(!audit_raw.contains("cloudflare_dummy_secret"));
    assert!(!audit_raw.contains("admin_dummy_secret"));
}

#[test]
fn audit_ls_lists_entries_without_secret_values() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let empty_output = agvt_command(&vault_path)
        .args(["audit", "ls"])
        .output()
        .unwrap();
    assert!(
        empty_output.status.success(),
        "{}",
        String::from_utf8_lossy(&empty_output.stderr)
    );
    assert!(String::from_utf8_lossy(&empty_output.stdout).contains("No audit entries."));

    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "github_dummy_secret")
        .output()
        .unwrap();
    assert!(add_output.status.success());

    let ls_output = agvt_command(&vault_path)
        .args(["audit", "ls"])
        .output()
        .unwrap();
    assert!(
        ls_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ls_output.stderr)
    );
    let ls_stdout = String::from_utf8_lossy(&ls_output.stdout);
    assert!(ls_stdout.contains("add\tagvt://dev/github/token\tagvt"));
    assert!(!ls_stdout.contains("github_dummy_secret"));

    let json_output = agvt_command(&vault_path)
        .args(["audit", "ls", "--json"])
        .output()
        .unwrap();
    assert!(
        json_output.status.success(),
        "{}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let json_stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(!json_stdout.contains("github_dummy_secret"));
    let parsed: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let entries = parsed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["op"], "add");
    assert_eq!(entries[0]["ref"], "agvt://dev/github/token");
    assert_eq!(entries[0]["caller"], "agvt");
    assert!(entries[0]["ts"].as_u64().unwrap() > 0);
}

#[test]
fn audit_write_failure_warns_but_vault_operation_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let blocker_path = directory.path().join("blocker");
    fs::write(&blocker_path, "not a directory").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agvt"))
        .arg("--vault-path")
        .arg(&vault_path)
        .args(["add", "github"])
        .env("AGVT_PASSPHRASE", "test-passphrase-with-enough-length")
        .env("GITHUB_TOKEN", "github_dummy_secret")
        // A file in the parent chain makes the audit write fail.
        .env("AGVT_AUDIT_PATH", blocker_path.join("audit.jsonl"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved agvt://dev/github/token"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("audit log write failed"));
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

fn charter_command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agvt"));
    command
        // Keep test charter and audit entries out of the real user files.
        .env("AGVT_CHARTER_PATH", directory.join("charter.json"))
        .env("AGVT_AUDIT_PATH", directory.join("audit.jsonl"));
    command
}

fn dossier_command(directory: &Path) -> Command {
    let mut command = agvt_command(&directory.join("agent-vault.json"));
    command.env("AGVT_DOSSIER_PATH", directory.join("dossier.json"));
    command
}

#[test]
fn charter_check_matches_autonomy_ledger_rules_and_records_writes() {
    let directory = tempfile::tempdir().unwrap();

    // Same three autonomy levels as the per-repository orchestration ledger
    // (auto / branch-auto / confirm), defined inline as test data.
    for (scope, autonomy) in [
        ("repo:autofill-browser", "auto"),
        ("repo:agent-times", "branch-auto"),
        ("repo:iam", "confirm"),
    ] {
        let add_output = charter_command(directory.path())
            .args([
                "charter",
                "add",
                "commit",
                scope,
                autonomy,
                "--conditions",
                "build/test GREEN",
            ])
            .output()
            .unwrap();
        assert!(
            add_output.status.success(),
            "{}",
            String::from_utf8_lossy(&add_output.stderr)
        );
    }

    for (scope, autonomy) in [
        ("repo:autofill-browser", "auto"),
        ("repo:agent-times", "branch-auto"),
        ("repo:iam", "confirm"),
    ] {
        let check_output = charter_command(directory.path())
            .args(["charter", "check", "commit", scope])
            .output()
            .unwrap();
        assert!(
            check_output.status.success(),
            "{}",
            String::from_utf8_lossy(&check_output.stderr)
        );
        let verdict: Value = serde_json::from_slice(&check_output.stdout).unwrap();
        assert_eq!(verdict["capability"], "commit");
        assert_eq!(verdict["scope"], scope);
        assert_eq!(verdict["autonomy"], autonomy);
        assert_eq!(verdict["matchedRule"]["scope"], scope);
        assert_eq!(verdict["matchedRule"]["conditions"], "build/test GREEN");
    }

    // Every charter write must land in the audit log (self-escalation
    // detection line, ADR 0013).
    let audit_raw = fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert_eq!(audit_raw.lines().count(), 3);
    assert!(audit_raw.contains("\"op\":\"charter-add\""));
    assert!(audit_raw.contains("agvt://charter/commit/repo:autofill-browser"));
    assert!(audit_raw.contains("agvt://charter/commit/repo:iam"));

    // The charter file itself stays plaintext and diffable.
    let charter_raw = fs::read_to_string(directory.path().join("charter.json")).unwrap();
    assert!(charter_raw.contains("\"autonomy\": \"branch-auto\""));
}

#[test]
fn charter_check_falls_back_to_confirm_for_undefined_capability() {
    let directory = tempfile::tempdir().unwrap();

    // No charter file at all: still a clean confirm verdict.
    let check_output = charter_command(directory.path())
        .args(["charter", "check", "deploy", "repo:autofill-browser"])
        .output()
        .unwrap();
    assert!(
        check_output.status.success(),
        "{}",
        String::from_utf8_lossy(&check_output.stderr)
    );
    let verdict: Value = serde_json::from_slice(&check_output.stdout).unwrap();
    assert_eq!(verdict["autonomy"], "confirm");
    assert!(verdict["matchedRule"].is_null());
}

#[test]
fn charter_check_survives_corrupt_charter_file_with_confirm() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("charter.json"), "{ not json").unwrap();

    let check_output = charter_command(directory.path())
        .args(["charter", "check", "commit", "repo:autofill-browser"])
        .output()
        .unwrap();
    assert!(
        check_output.status.success(),
        "{}",
        String::from_utf8_lossy(&check_output.stderr)
    );
    let verdict: Value = serde_json::from_slice(&check_output.stdout).unwrap();
    assert_eq!(verdict["autonomy"], "confirm");
    assert!(verdict["matchedRule"].is_null());
    assert!(String::from_utf8_lossy(&check_output.stderr).contains("charter file is unreadable"));

    // Writes must refuse to clobber the corrupt file.
    let add_output = charter_command(directory.path())
        .args(["charter", "add", "commit", "repo:iam", "auto"])
        .output()
        .unwrap();
    assert!(!add_output.status.success());
    assert!(String::from_utf8_lossy(&add_output.stderr).contains("charter file is unreadable"));
}

#[test]
fn charter_add_upserts_and_ls_show_report_rules() {
    let directory = tempfile::tempdir().unwrap();

    let add_output = charter_command(directory.path())
        .args(["charter", "add", "commit", "repo:*", "confirm"])
        .output()
        .unwrap();
    assert!(add_output.status.success());

    // Re-adding the same capability/scope replaces the rule instead of
    // duplicating it.
    let upsert_output = charter_command(directory.path())
        .args(["charter", "add", "commit", "repo:*", "branch-auto"])
        .output()
        .unwrap();
    assert!(upsert_output.status.success());

    let ls_output = charter_command(directory.path())
        .args(["charter", "ls", "--json"])
        .output()
        .unwrap();
    assert!(ls_output.status.success());
    let listed: Value = serde_json::from_slice(&ls_output.stdout).unwrap();
    let rules = listed["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["autonomy"], "branch-auto");

    let show_output = charter_command(directory.path())
        .args(["charter", "show", "commit"])
        .output()
        .unwrap();
    assert!(show_output.status.success());
    assert!(String::from_utf8_lossy(&show_output.stdout).contains("repo:*\tbranch-auto"));

    // Wildcard prefix rule applies to unseen repositories.
    let check_output = charter_command(directory.path())
        .args(["charter", "check", "commit", "repo:brand-new"])
        .output()
        .unwrap();
    let verdict: Value = serde_json::from_slice(&check_output.stdout).unwrap();
    assert_eq!(verdict["autonomy"], "branch-auto");
    assert_eq!(verdict["matchedRule"]["scope"], "repo:*");

    let bad_output = charter_command(directory.path())
        .args(["charter", "add", "commit", "repo:x", "yolo"])
        .output()
        .unwrap();
    assert!(!bad_output.status.success());
    assert!(String::from_utf8_lossy(&bad_output.stderr)
        .contains("autonomy must be auto, branch-auto, confirm, or deny."));
}

#[test]
fn dossier_add_search_show_round_trip() {
    let directory = tempfile::tempdir().unwrap();

    let add_output = dossier_command(directory.path())
        .args([
            "dossier",
            "add",
            "company-challenges",
            "--body",
            "shipping agent-first products",
            "--tags",
            "company,strategy",
            "--tier",
            "open",
            "--id",
            "company-challenges",
        ])
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(String::from_utf8_lossy(&add_output.stdout)
        .contains("saved dossier entry company-challenges (tier=open)"));

    let search_output = dossier_command(directory.path())
        .args(["dossier", "search", "agent-first", "--json"])
        .output()
        .unwrap();
    assert!(
        search_output.status.success(),
        "{}",
        String::from_utf8_lossy(&search_output.stderr)
    );
    let search_stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(search_stdout.contains("\"id\": \"company-challenges\""));
    assert!(search_stdout.contains("\"tier\": \"open\""));
    // Search output holds metadata only, never bodies.
    assert!(!search_stdout.contains("shipping agent-first products"));

    let show_output = dossier_command(directory.path())
        .args(["dossier", "show", "company-challenges"])
        .output()
        .unwrap();
    assert!(
        show_output.status.success(),
        "{}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    let show_stdout = String::from_utf8_lossy(&show_output.stdout);
    assert!(show_stdout.contains("shipping agent-first products"));
    assert!(show_stdout.contains("tier: open"));
}

#[test]
fn dossier_locked_entries_stay_encrypted_everywhere_and_are_audited() {
    let directory = tempfile::tempdir().unwrap();
    let dossier_path = directory.path().join("dossier.json");
    let audit_path = directory
        .path()
        .join("agent-vault.json")
        .with_file_name("audit.jsonl");
    let secret_body = "account-number-9876543210-locked";

    let add_output = dossier_command(directory.path())
        .args([
            "dossier",
            "add",
            "brokerage account",
            "--body",
            secret_body,
            "--tier",
            "locked",
            "--id",
            "brokerage",
        ])
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );
    assert!(!String::from_utf8_lossy(&add_output.stdout).contains(secret_body));

    // On disk: encrypted only.
    let raw_dossier = fs::read_to_string(&dossier_path).unwrap();
    assert!(!raw_dossier.contains(secret_body));

    // show returns the reference, never the raw body.
    let show_output = dossier_command(directory.path())
        .args(["dossier", "show", "brokerage", "--json"])
        .output()
        .unwrap();
    assert!(
        show_output.status.success(),
        "{}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    let show_stdout = String::from_utf8_lossy(&show_output.stdout);
    assert!(show_stdout.contains("\"bodyRef\": \"agvt://dossier/brokerage/body\""));
    assert!(show_stdout.contains("\"body\": null"));
    assert!(!show_stdout.contains(secret_body));

    // ls prints metadata only.
    let ls_output = dossier_command(directory.path())
        .args(["dossier", "ls"])
        .output()
        .unwrap();
    assert!(ls_output.status.success());
    assert!(!String::from_utf8_lossy(&ls_output.stdout).contains(secret_body));

    // --tier open filter never returns the locked entry.
    let filtered_output = dossier_command(directory.path())
        .args(["dossier", "search", "brokerage", "--tier", "open", "--json"])
        .output()
        .unwrap();
    assert!(filtered_output.status.success());
    assert!(!String::from_utf8_lossy(&filtered_output.stdout).contains("brokerage"));
    let filtered_show = dossier_command(directory.path())
        .args(["dossier", "show", "brokerage", "--tier", "open"])
        .output()
        .unwrap();
    assert!(!filtered_show.status.success());
    assert!(!String::from_utf8_lossy(&filtered_show.stderr).contains(secret_body));

    // Audit log holds the write and the locked read attempt, never the body.
    let raw_audit = fs::read_to_string(&audit_path).unwrap();
    assert!(raw_audit.contains("\"op\":\"dossier-add\""));
    assert!(raw_audit.contains("\"op\":\"dossier-read-locked\""));
    assert!(raw_audit.contains("agvt://dossier/brokerage/body"));
    assert!(!raw_audit.contains(secret_body));
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
fn from_file_records_size_and_sha256_metadata_visible_in_ls_json() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("AuthKey_META.p8");
    let key_bytes = b"agvt u1 residual test key bytes\n";
    // Precomputed sha256 hex digest of key_bytes.
    let expected_sha256 = "648842974acd51134a8497c6d7b071f3b4fe6f57572f3102bfde3eeefa036319";
    fs::write(&key_path, key_bytes).unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "apple-meta-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let list_output = agvt_command(&vault_path)
        .args(["ls", "--json"])
        .output()
        .unwrap();
    assert!(list_output.status.success());
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    let item = parsed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["item"] == "apple-meta-key")
        .unwrap();
    assert_eq!(item["kind"], "file");
    assert_eq!(item["filename"], "AuthKey_META.p8");
    assert_eq!(item["size"], key_bytes.len().to_string());
    assert_eq!(item["sha256"], expected_sha256);
    // Metadata only: the base64 content never appears in ls output.
    let content_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(key_bytes)
    };
    assert!(!stdout.contains(&content_b64));

    // The same metadata is also stored as encrypted payload fields and can be
    // read back through references.
    let sha_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/apple-meta-key/sha256"])
        .output()
        .unwrap();
    assert!(
        sha_output.status.success(),
        "{}",
        String::from_utf8_lossy(&sha_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&sha_output.stdout).trim(),
        expected_sha256
    );
    let size_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/apple-meta-key/size"])
        .output()
        .unwrap();
    assert!(size_output.status.success());
    assert_eq!(String::from_utf8_lossy(&size_output.stdout).trim(), "32");
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn read_out_restores_original_bytes_with_private_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("AuthKey_OUT.p12");
    let out_path = directory.path().join("restored.p12");
    let key_bytes: Vec<u8> = (0..=255u8).cycle().take(600).collect();
    fs::write(&key_path, &key_bytes).unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "apple-out-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let read_output = agvt_command(&vault_path)
        .args([
            "read",
            "agvt://dev/apple-out-key/content",
            "--decode",
            "--out",
        ])
        .arg(&out_path)
        .output()
        .unwrap();
    assert!(
        read_output.status.success(),
        "{}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    // Stdout carries only metadata (byte count and path), never the content.
    let stdout = String::from_utf8_lossy(&read_output.stdout);
    assert!(stdout.contains("wrote 600 bytes"));
    assert!(!read_output
        .stdout
        .windows(16)
        .any(|window| window == &key_bytes[..16]));
    assert_eq!(fs::read(&out_path).unwrap(), key_bytes);
    #[cfg(unix)]
    assert_eq!(file_mode(&out_path), 0o600);
}

#[test]
fn read_out_refuses_to_overwrite_existing_file_unless_forced() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let key_path = directory.path().join("key.p8");
    let out_path = directory.path().join("existing.p8");
    let key_bytes = b"replacement key bytes";
    fs::write(&key_path, key_bytes).unwrap();
    fs::write(&out_path, b"precious existing data").unwrap();

    let add_output = agvt_command(&vault_path)
        .args(["add", "overwrite-key", "--from-file"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let blocked_output = agvt_command(&vault_path)
        .args([
            "read",
            "agvt://dev/overwrite-key/content",
            "--decode",
            "--out",
        ])
        .arg(&out_path)
        .output()
        .unwrap();
    assert!(!blocked_output.status.success());
    assert!(String::from_utf8_lossy(&blocked_output.stderr)
        .contains("refusing to overwrite existing file"));
    assert_eq!(fs::read(&out_path).unwrap(), b"precious existing data");

    let forced_output = agvt_command(&vault_path)
        .args([
            "read",
            "agvt://dev/overwrite-key/content",
            "--decode",
            "--out",
        ])
        .arg(&out_path)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        forced_output.status.success(),
        "{}",
        String::from_utf8_lossy(&forced_output.stderr)
    );
    assert_eq!(fs::read(&out_path).unwrap(), key_bytes);
    #[cfg(unix)]
    assert_eq!(file_mode(&out_path), 0o600);
}

#[test]
fn read_succeeds_with_warning_for_unknown_item_kind() {
    use std::num::NonZeroU32;

    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    use ring::pbkdf2;

    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");
    let passphrase = "test-passphrase-with-enough-length";

    // Seed the vault through the CLI so file format and KDF are authentic.
    let add_output = agvt_command(&vault_path)
        .args(["add", "github"])
        .env("GITHUB_TOKEN", "dummy_known_kind_token")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "{}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    // Inject an item with a kind this binary does not know directly into the
    // vault JSON, simulating a vault written by a newer agvt version.
    let mut vault: Value = serde_json::from_str(&fs::read_to_string(&vault_path).unwrap()).unwrap();
    let salt = BASE64
        .decode(vault["kdf"]["salt"].as_str().unwrap())
        .unwrap();
    let iterations = u32::try_from(vault["kdf"]["iterations"].as_u64().unwrap()).unwrap();
    let mut key_bytes = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        &salt,
        passphrase.as_bytes(),
        &mut key_bytes,
    );
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let vault_id = vault["vaultId"].as_str().unwrap().to_owned();
    let storage_name = "future-item";
    let kind = "quantum-key";
    // Mirrors vault::build_item_aad.
    let aad = format!(
        "[\"item\",1,\"PBKDF2-SHA256/AES-GCM\",{},{},{}]",
        serde_json::to_string(&vault_id).unwrap(),
        serde_json::to_string(storage_name).unwrap(),
        serde_json::to_string(kind).unwrap()
    );
    let payload =
        r#"{"schemaVersion":1,"kind":"quantum-key","secret":"future-value","novelField":"x"}"#;
    let iv = [7_u8; 12];
    let nonce = Nonce::try_assume_unique_for_key(&iv).unwrap();
    let mut in_out = payload.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad.as_bytes()), &mut in_out)
        .unwrap();
    vault["items"][storage_name] = serde_json::json!({
        "schemaVersion": 1,
        "kind": kind,
        "label": "Future",
        "encryptedValue": {
            "schemaVersion": 1,
            "algorithm": "AES-GCM",
            "iv": BASE64.encode(iv),
            "ciphertext": BASE64.encode(&in_out)
        },
        "createdAt": "0",
        "updatedAt": "0"
    });
    fs::write(
        &vault_path,
        format!("{}\n", serde_json::to_string_pretty(&vault).unwrap()),
    )
    .unwrap();

    // Reading the unknown-kind item succeeds with a stderr warning.
    let read_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/future-item/secret"])
        .output()
        .unwrap();
    assert!(
        read_output.status.success(),
        "{}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&read_output.stdout).trim(),
        "future-value"
    );
    assert!(String::from_utf8_lossy(&read_output.stderr)
        .contains("unknown Vault item kind `quantum-key`"));

    // Known items in the same vault keep working, ls shows both, and the
    // write path stays strict for unknown kinds.
    let token_output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/github/token"])
        .output()
        .unwrap();
    assert!(token_output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&token_output.stdout).trim(),
        "dummy_known_kind_token"
    );
    let list_output = agvt_command(&vault_path)
        .args(["ls", "--json"])
        .output()
        .unwrap();
    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains("future-item"));
    assert!(list_stdout.contains("github"));
    let strict_add_output = agvt_command(&vault_path)
        .args([
            "add",
            "another",
            "--kind",
            "quantum-key",
            "--from-env",
            "SOME_ENV",
        ])
        .env("SOME_ENV", "value")
        .output()
        .unwrap();
    assert!(!strict_add_output.status.success());
    assert!(String::from_utf8_lossy(&strict_add_output.stderr).contains("kind must be one of"));
}

#[test]
fn read_force_without_out_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("agent-vault.json");

    let output = agvt_command(&vault_path)
        .args(["read", "agvt://dev/github/token", "--force"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--force is only supported with --out")
    );
}
