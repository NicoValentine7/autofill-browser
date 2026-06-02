use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{AgvtError, Result};

pub const AGVT_KEYCHAIN_ENV: &str = "AGVT_KEYCHAIN";
pub const AGVT_KEYCHAIN_SERVICE_ENV: &str = "AGVT_KEYCHAIN_SERVICE";
pub const AGVT_KEYCHAIN_ACCOUNT_ENV: &str = "AGVT_KEYCHAIN_ACCOUNT";
pub const AGVT_SECURITY_PATH_ENV: &str = "AGVT_SECURITY_PATH";

const DEFAULT_KEYCHAIN_SERVICE: &str = "agvt";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeychainTarget {
    pub service: String,
    pub account: String,
}

pub fn keychain_enabled() -> bool {
    !matches!(
        env::var(AGVT_KEYCHAIN_ENV)
            .unwrap_or_else(|_| "1".to_owned())
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "off" | "no"
    )
}

pub fn target_for_vault(path: &Path) -> KeychainTarget {
    let service = env::var(AGVT_KEYCHAIN_SERVICE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KEYCHAIN_SERVICE.to_owned());
    let account = env::var(AGVT_KEYCHAIN_ACCOUNT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("vault:{}", stable_path(path).display()));

    KeychainTarget { service, account }
}

pub fn read_passphrase(path: &Path) -> Result<Option<String>> {
    if !keychain_enabled() {
        return Ok(None);
    }
    platform_read_passphrase(&target_for_vault(path))
}

pub fn store_passphrase(path: &Path, passphrase: &str) -> Result<KeychainTarget> {
    let target = target_for_vault(path);
    platform_store_passphrase(&target, passphrase)?;
    Ok(target)
}

pub fn delete_passphrase(path: &Path) -> Result<bool> {
    platform_delete_passphrase(&target_for_vault(path))
}

pub fn has_passphrase(path: &Path) -> Result<bool> {
    Ok(read_passphrase(path)?.is_some())
}

fn stable_path(path: &Path) -> PathBuf {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map(|current_dir| current_dir.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };

    if let Ok(canonical) = std::fs::canonicalize(&absolute_path) {
        return canonical;
    }

    if let (Some(parent), Some(file_name)) = (absolute_path.parent(), absolute_path.file_name()) {
        if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
            return canonical_parent.join(file_name);
        }
    }

    absolute_path
}

#[cfg(target_os = "macos")]
fn platform_read_passphrase(target: &KeychainTarget) -> Result<Option<String>> {
    let output = Command::new(security_path())
        .args([
            "find-generic-password",
            "-s",
            &target.service,
            "-a",
            &target.account,
            "-w",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        ));
    }

    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn platform_read_passphrase(_target: &KeychainTarget) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn platform_store_passphrase(target: &KeychainTarget, passphrase: &str) -> Result<()> {
    let mut child = Command::new(security_path())
        .args([
            "add-generic-password",
            "-U",
            "-s",
            &target.service,
            "-a",
            &target.account,
            "-w",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(passphrase.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }

    let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(AgvtError::new(if message.is_empty() {
        "failed to store passphrase in macOS Keychain.".to_owned()
    } else {
        format!("failed to store passphrase in macOS Keychain: {message}")
    }))
}

#[cfg(not(target_os = "macos"))]
fn platform_store_passphrase(_target: &KeychainTarget, _passphrase: &str) -> Result<()> {
    Err(AgvtError::new(
        "macOS Keychain integration is only available on macOS.",
    ))
}

#[cfg(target_os = "macos")]
fn platform_delete_passphrase(target: &KeychainTarget) -> Result<bool> {
    let output = Command::new(security_path())
        .args([
            "delete-generic-password",
            "-s",
            &target.service,
            "-a",
            &target.account,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;

    Ok(output.status.success())
}

#[cfg(not(target_os = "macos"))]
fn platform_delete_passphrase(_target: &KeychainTarget) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn security_path() -> String {
    env::var(AGVT_SECURITY_PATH_ENV).unwrap_or_else(|_| "security".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_vault_path_in_default_account() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-vault.json");
        let target = target_for_vault(&path);
        assert_eq!(target.service, "agvt");
        assert!(target.account.contains("agent-vault.json"));
    }
}
