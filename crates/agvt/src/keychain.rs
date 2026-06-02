use std::env;
#[cfg(target_os = "macos")]
use std::os::raw::{c_char, c_void};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::ptr;

use crate::error::{AgvtError, Result};

pub const AGVT_KEYCHAIN_ENV: &str = "AGVT_KEYCHAIN";
pub const AGVT_KEYCHAIN_SERVICE_ENV: &str = "AGVT_KEYCHAIN_SERVICE";
pub const AGVT_KEYCHAIN_ACCOUNT_ENV: &str = "AGVT_KEYCHAIN_ACCOUNT";

const DEFAULT_KEYCHAIN_SERVICE: &str = "agvt";

#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: OsStatus = -25300;

#[cfg(target_os = "macos")]
type OsStatus = i32;

#[cfg(target_os = "macos")]
type SecKeychainItemRef = *mut c_void;

#[cfg(target_os = "macos")]
type CFTypeRef = *const c_void;

#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecKeychainFindGenericPassword(
        keychain_or_array: *mut c_void,
        service_name_length: u32,
        service_name: *const c_char,
        account_name_length: u32,
        account_name: *const c_char,
        password_length: *mut u32,
        password_data: *mut *mut c_void,
        item_ref: *mut SecKeychainItemRef,
    ) -> OsStatus;

    fn SecKeychainAddGenericPassword(
        keychain: *mut c_void,
        service_name_length: u32,
        service_name: *const c_char,
        account_name_length: u32,
        account_name: *const c_char,
        password_length: u32,
        password_data: *const c_void,
        item_ref: *mut SecKeychainItemRef,
    ) -> OsStatus;

    fn SecKeychainItemModifyAttributesAndData(
        item_ref: SecKeychainItemRef,
        attr_list: *const c_void,
        length: u32,
        data: *const c_void,
    ) -> OsStatus;

    fn SecKeychainItemDelete(item_ref: SecKeychainItemRef) -> OsStatus;

    fn SecKeychainItemFreeContent(attr_list: *mut c_void, data: *mut c_void) -> OsStatus;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: CFTypeRef);
}

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
    let service = keychain_attribute_bytes("service", &target.service)?;
    let account = keychain_attribute_bytes("account", &target.account)?;
    let mut password_length = 0_u32;
    let mut password_data = ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            ptr::null_mut(),
            service.len() as u32,
            service.as_ptr().cast::<c_char>(),
            account.len() as u32,
            account.as_ptr().cast::<c_char>(),
            &mut password_length,
            &mut password_data,
            ptr::null_mut(),
        )
    };

    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    check_status(status, "read macOS Keychain passphrase")?;

    let password = if password_length == 0 {
        Vec::new()
    } else {
        if password_data.is_null() {
            return Err(AgvtError::new(
                "macOS Keychain returned a passphrase length without passphrase data.",
            ));
        }
        unsafe {
            std::slice::from_raw_parts(password_data.cast::<u8>(), password_length as usize)
                .to_vec()
        }
    };
    if !password_data.is_null() {
        let free_status = unsafe { SecKeychainItemFreeContent(ptr::null_mut(), password_data) };
        check_status(free_status, "free macOS Keychain passphrase")?;
    }
    String::from_utf8(password)
        .map(Some)
        .map_err(|_| AgvtError::new("macOS Keychain passphrase is not valid UTF-8."))
}

#[cfg(not(target_os = "macos"))]
fn platform_read_passphrase(_target: &KeychainTarget) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn platform_store_passphrase(target: &KeychainTarget, passphrase: &str) -> Result<()> {
    let service = keychain_attribute_bytes("service", &target.service)?;
    let account = keychain_attribute_bytes("account", &target.account)?;
    let passphrase_bytes = keychain_secret_bytes(passphrase)?;
    let mut item_ref = ptr::null_mut();
    let find_status = unsafe {
        SecKeychainFindGenericPassword(
            ptr::null_mut(),
            service.len() as u32,
            service.as_ptr().cast::<c_char>(),
            account.len() as u32,
            account.as_ptr().cast::<c_char>(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut item_ref,
        )
    };

    if find_status == 0 {
        let update_status = unsafe {
            SecKeychainItemModifyAttributesAndData(
                item_ref,
                ptr::null(),
                passphrase_bytes.len() as u32,
                passphrase_bytes.as_ptr().cast::<c_void>(),
            )
        };
        release_item(item_ref);
        return check_status(update_status, "update macOS Keychain passphrase");
    }
    if find_status != ERR_SEC_ITEM_NOT_FOUND {
        return check_status(find_status, "find macOS Keychain passphrase for update");
    }

    let mut added_item_ref = ptr::null_mut();
    let add_status = unsafe {
        SecKeychainAddGenericPassword(
            ptr::null_mut(),
            service.len() as u32,
            service.as_ptr().cast::<c_char>(),
            account.len() as u32,
            account.as_ptr().cast::<c_char>(),
            passphrase_bytes.len() as u32,
            passphrase_bytes.as_ptr().cast::<c_void>(),
            &mut added_item_ref,
        )
    };
    release_item(added_item_ref);
    check_status(add_status, "store macOS Keychain passphrase")
}

#[cfg(not(target_os = "macos"))]
fn platform_store_passphrase(_target: &KeychainTarget, _passphrase: &str) -> Result<()> {
    Err(AgvtError::new(
        "macOS Keychain integration is only available on macOS.",
    ))
}

#[cfg(target_os = "macos")]
fn platform_delete_passphrase(target: &KeychainTarget) -> Result<bool> {
    let service = keychain_attribute_bytes("service", &target.service)?;
    let account = keychain_attribute_bytes("account", &target.account)?;
    let mut item_ref = ptr::null_mut();
    let find_status = unsafe {
        SecKeychainFindGenericPassword(
            ptr::null_mut(),
            service.len() as u32,
            service.as_ptr().cast::<c_char>(),
            account.len() as u32,
            account.as_ptr().cast::<c_char>(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut item_ref,
        )
    };

    if find_status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(false);
    }
    check_status(find_status, "find macOS Keychain passphrase for delete")?;
    let delete_status = unsafe { SecKeychainItemDelete(item_ref) };
    release_item(item_ref);
    check_status(delete_status, "delete macOS Keychain passphrase")?;
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn platform_delete_passphrase(_target: &KeychainTarget) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn keychain_attribute_bytes(name: &str, value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.contains(&0) {
        return Err(AgvtError::new(format!(
            "macOS Keychain {name} cannot contain NUL bytes."
        )));
    }
    if bytes.len() > u32::MAX as usize {
        return Err(AgvtError::new(format!(
            "macOS Keychain {name} is too long."
        )));
    }
    Ok(bytes.to_vec())
}

#[cfg(target_os = "macos")]
fn keychain_secret_bytes(value: &str) -> Result<&[u8]> {
    let bytes = value.as_bytes();
    if bytes.len() > u32::MAX as usize {
        return Err(AgvtError::new("macOS Keychain passphrase is too long."));
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn check_status(status: OsStatus, action: &str) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    Err(AgvtError::new(format!(
        "{action} failed: OSStatus {status}"
    )))
}

#[cfg(target_os = "macos")]
fn release_item(item_ref: SecKeychainItemRef) {
    if !item_ref.is_null() {
        unsafe { CFRelease(item_ref.cast::<c_void>()) };
    }
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
