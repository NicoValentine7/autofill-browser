use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::error::{AgvtError, Result};

const DEFAULT_CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const AGVT_CURL_PATH_ENV: &str = "AGVT_CURL_PATH";
const AGVT_CLOUDFLARE_API_BASE_ENV: &str = "AGVT_CLOUDFLARE_API_BASE";

#[derive(Clone, Debug)]
pub struct CreateTokenInput {
    pub factory_token: String,
    pub name: String,
    pub policies: Value,
    pub expires_on: Option<String>,
    pub not_before: Option<String>,
    pub condition: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedToken {
    pub id: Option<String>,
    pub value: String,
    pub expires_on: Option<String>,
}

pub fn create_user_token(input: CreateTokenInput) -> Result<CreatedToken> {
    if input.factory_token.trim().is_empty() {
        return Err(AgvtError::new("Cloudflare factory token is required."));
    }
    if input.name.trim().is_empty() {
        return Err(AgvtError::new("Cloudflare token name is required."));
    }

    let body = build_create_token_body(&input)?;
    let response = post_cloudflare_json("/user/tokens", &input.factory_token, &body)?;
    parse_create_token_response(&response)
}

pub fn load_policy_file(path: &str) -> Result<Value> {
    let raw = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    if let Some(policies) = parsed.get("policies") {
        return Ok(policies.clone());
    }
    Ok(parsed)
}

fn build_create_token_body(input: &CreateTokenInput) -> Result<Value> {
    if !input.policies.is_array() {
        return Err(AgvtError::new(
            "Cloudflare policy file must be a policies array or an object with a policies field.",
        ));
    }

    let mut body = Map::new();
    body.insert(
        "name".to_owned(),
        Value::String(input.name.trim().to_owned()),
    );
    body.insert("policies".to_owned(), input.policies.clone());
    if let Some(expires_on) = input
        .expires_on
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "expires_on".to_owned(),
            Value::String(expires_on.trim().to_owned()),
        );
    }
    if let Some(not_before) = input
        .not_before
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "not_before".to_owned(),
            Value::String(not_before.trim().to_owned()),
        );
    }
    if let Some(condition) = &input.condition {
        body.insert("condition".to_owned(), condition.clone());
    }

    Ok(Value::Object(body))
}

fn post_cloudflare_json(path: &str, bearer_token: &str, body: &Value) -> Result<Value> {
    let body_path = write_temp_body(body)?;
    let api_base = env::var(AGVT_CLOUDFLARE_API_BASE_ENV)
        .unwrap_or_else(|_| DEFAULT_CLOUDFLARE_API_BASE.to_owned())
        .trim_end_matches('/')
        .to_owned();
    let url = format!("{api_base}{path}");
    let config = format!(
        "silent\nshow-error\nrequest = \"POST\"\nurl = \"{}\"\nheader = \"Content-Type: application/json\"\nheader = \"Authorization: Bearer {}\"\ndata-binary = \"@{}\"\n",
        curl_escape(&url),
        curl_escape(bearer_token),
        curl_escape(&body_path.display().to_string())
    );

    let mut child = Command::new(curl_path())
        .args(["-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(config.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    let _ = fs::remove_file(&body_path);

    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(AgvtError::new(if message.is_empty() {
            "Cloudflare API request failed.".to_owned()
        } else {
            format!("Cloudflare API request failed: {message}")
        }));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|_| AgvtError::new("Cloudflare API response was not valid JSON."))
}

fn parse_create_token_response(response: &Value) -> Result<CreatedToken> {
    if response.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(AgvtError::new(format!(
            "Cloudflare API did not create the token: {}",
            summarize_cloudflare_errors(response)
        )));
    }

    let result = response
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| AgvtError::new("Cloudflare API response did not include result."))?;
    let value = result
        .get("value")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AgvtError::new("Cloudflare API response did not include the token value.")
        })?;

    Ok(CreatedToken {
        id: result
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        value: value.to_owned(),
        expires_on: result
            .get("expires_on")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn summarize_cloudflare_errors(response: &Value) -> String {
    let errors = response
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let messages: Vec<String> = errors
        .iter()
        .filter_map(|error| error.get("message").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    if messages.is_empty() {
        "no error details returned".to_owned()
    } else {
        messages.join("; ")
    }
}

fn write_temp_body(body: &Value) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!(
        "agvt-cloudflare-{}-{timestamp}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_vec(body)?)?;
    set_private_permissions(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn set_private_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &PathBuf) -> Result<()> {
    Ok(())
}

fn curl_path() -> String {
    env::var(AGVT_CURL_PATH_ENV).unwrap_or_else(|_| "curl".to_owned())
}

fn curl_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_created_token_without_leaking_errors() {
        let parsed = parse_create_token_response(&json!({
            "success": true,
            "result": {
                "id": "token-id",
                "value": "created-token",
                "expires_on": "2026-12-31T00:00:00Z"
            }
        }))
        .unwrap();

        assert_eq!(
            parsed,
            CreatedToken {
                id: Some("token-id".to_owned()),
                value: "created-token".to_owned(),
                expires_on: Some("2026-12-31T00:00:00Z".to_owned())
            }
        );
    }

    #[test]
    fn accepts_policy_array_or_object_with_policies() {
        let array = json!([{ "effect": "allow", "permission_groups": [], "resources": {} }]);
        assert!(build_create_token_body(&CreateTokenInput {
            factory_token: "factory".to_owned(),
            name: "test".to_owned(),
            policies: array,
            expires_on: None,
            not_before: None,
            condition: None
        })
        .is_ok());
    }
}
