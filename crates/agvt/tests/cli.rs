use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

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
        .args(["read", "agvt://cloudflare/token"])
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
        .env("GITHUB_TOKEN", "agvt://github/token")
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
        .args(["read", "agvt://github-totp/issuer"])
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

    fs::write(&template_path, "TOKEN=agvt://cloudflare/token\n").unwrap();
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
