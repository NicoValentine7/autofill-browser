use crate::error::{AgvtError, Result};

pub const DEFAULT_VAULT_NAME: &str = "dev";
pub const SECRET_REF_PREFIX: &str = "agvt://";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRef {
    pub vault: String,
    pub item: String,
    pub field: String,
}

impl SecretRef {
    pub fn storage_name(&self) -> String {
        if self.vault == DEFAULT_VAULT_NAME {
            self.item.clone()
        } else {
            format!("{}:{}", self.vault, self.item)
        }
    }
}

pub fn validate_name(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AgvtError::new(format!("{label} must be 1-128 characters.")));
    }

    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return Err(AgvtError::new(format!("{label} is required.")));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(AgvtError::new(format!(
            "{label} must start with a letter or number."
        )));
    }
    if !chars
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(AgvtError::new(format!(
            "{label} may contain only letters, numbers, dot, underscore, or hyphen."
        )));
    }

    Ok(trimmed.to_owned())
}

pub fn validate_env_name(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return Err(AgvtError::new("environment variable name is required."));
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(AgvtError::new(
            "environment variable names must match [A-Za-z_][A-Za-z0-9_]*.",
        ));
    }
    if !chars.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        return Err(AgvtError::new(
            "environment variable names must match [A-Za-z_][A-Za-z0-9_]*.",
        ));
    }
    Ok(trimmed.to_owned())
}

pub fn validate_field_name(value: &str) -> Result<String> {
    match value {
        "token" | "serviceUrl" | "service-url" | "accountName" | "account" | "notes" => {
            Ok(value.to_owned())
        }
        _ => Err(AgvtError::new(
            "field must be one of token, serviceUrl, service-url, accountName, account, or notes.",
        )),
    }
}

pub fn canonical_field_name(value: &str) -> Result<String> {
    Ok(match validate_field_name(value)?.as_str() {
        "service-url" => "serviceUrl".to_owned(),
        "account" => "accountName".to_owned(),
        other => other.to_owned(),
    })
}

pub fn parse_secret_ref(value: &str, default_vault: &str) -> Result<SecretRef> {
    let trimmed = value.trim();
    if !trimmed.starts_with(SECRET_REF_PREFIX) {
        return Err(AgvtError::new("secret reference must start with agvt://."));
    }

    let path = &trimmed[SECRET_REF_PREFIX.len()..];
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match parts.as_slice() {
        [item, field] => Ok(SecretRef {
            vault: validate_name(default_vault, "vault")?,
            item: validate_name(item, "item")?,
            field: canonical_field_name(field)?,
        }),
        [vault, item, field] => Ok(SecretRef {
            vault: validate_name(vault, "vault")?,
            item: validate_name(item, "item")?,
            field: canonical_field_name(field)?,
        }),
        _ => Err(AgvtError::new(
            "secret reference must be agvt://item/field or agvt://vault/item/field.",
        )),
    }
}

pub fn item_target_to_ref(target: &str, default_vault: &str, field: &str) -> Result<SecretRef> {
    if target.trim().starts_with(SECRET_REF_PREFIX) {
        return parse_secret_ref(target, default_vault);
    }

    Ok(SecretRef {
        vault: validate_name(default_vault, "vault")?,
        item: validate_name(target, "item")?,
        field: canonical_field_name(field)?,
    })
}

pub fn find_secret_refs(value: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut index = 0;
    while let Some(offset) = value[index..].find(SECRET_REF_PREFIX) {
        let start = index + offset;
        let mut end = start + SECRET_REF_PREFIX.len();
        for character in value[end..].chars() {
            if character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '_' | '-') {
                end += character.len_utf8();
            } else {
                break;
            }
        }
        refs.push(value[start..end].to_owned());
        index = end;
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_and_short_references() {
        assert_eq!(
            parse_secret_ref("agvt://prod/cloudflare/token", DEFAULT_VAULT_NAME).unwrap(),
            SecretRef {
                vault: "prod".to_owned(),
                item: "cloudflare".to_owned(),
                field: "token".to_owned()
            }
        );
        assert_eq!(
            parse_secret_ref("agvt://cloudflare/service-url", DEFAULT_VAULT_NAME).unwrap(),
            SecretRef {
                vault: "dev".to_owned(),
                item: "cloudflare".to_owned(),
                field: "serviceUrl".to_owned()
            }
        );
    }

    #[test]
    fn finds_secret_refs_inside_templates() {
        assert_eq!(
            find_secret_refs("TOKEN=agvt://cloudflare/token\nOTHER=1"),
            vec!["agvt://cloudflare/token"]
        );
    }
}
