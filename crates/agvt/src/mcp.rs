//! Agent Home MCP server (`agvt mcp`).
//!
//! Implements the MCP stdio transport directly on JSON-RPC 2.0: one JSON
//! message per line on stdin/stdout, no external SDK (serde/serde_json only),
//! synchronous single-threaded loop, clean exit on EOF (ADR 0013).
//!
//! Security invariants (ADR 0011/0013/0014):
//! - Raw secret values are never read, held, or serialized here. No code path
//!   in this module calls a vault decryption function.
//! - Locked dossier bodies are never decrypted or returned; `dossier_read`
//!   answers with an `agvt://dossier/<id>/body` reference plus consumption
//!   instructions.
//! - `vault_ls` exposes item names, kinds, and labels only.
//! - `secret_handoff` returns an `agvt://` reference plus consumption
//!   instructions, never a value.
//! - Every tool call is recorded in the append-only audit log with
//!   op `mcp-<tool>` and caller `mcp` (locked dossier reads are recorded as
//!   `mcp-dossier_read-locked` so the audit log distinguishes them, ADR 0014).

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::audit;
use crate::charter;
use crate::dossier::{self, EntrySummary, Tier};
use crate::error::{AgvtError, Result};
use crate::reference::{canonical_field_name, validate_name, SecretRef};
use crate::vault::list_items;
use crate::GlobalOptions;

const MCP_CALLER: &str = "mcp";
/// Fallback only: `initialize` echoes the client's requested version.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

struct McpContext {
    dossier_path: PathBuf,
    charter_path: PathBuf,
    global_vault_path: PathBuf,
}

struct RpcError {
    code: i64,
    message: String,
}

pub(crate) fn handle_mcp(options: &GlobalOptions) -> Result<()> {
    if !options.args.is_empty() {
        return Err(AgvtError::new(
            "mcp takes no arguments. Run `agvt mcp` and speak JSON-RPC 2.0 over stdio, one message per line.",
        ));
    }
    let context = McpContext {
        dossier_path: dossier::dossier_path(),
        charter_path: charter::charter_path(),
        global_vault_path: options.global_vault_path.clone(),
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(stdin.lock(), stdout.lock(), &context)
}

/// Reads newline-delimited JSON-RPC messages until EOF and writes one
/// response line per request. Notifications and malformed lines never stop
/// the loop; EOF is a normal shutdown.
fn serve(reader: impl BufRead, mut writer: impl Write, context: &McpContext) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle_line(&line, context) {
            writer.write_all(serde_json::to_string(&response)?.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

fn handle_line(line: &str, context: &McpContext) -> Option<Value> {
    let message: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => {
            // The id is unknowable from a malformed line (JSON-RPC 2.0: null).
            return Some(error_response(
                Value::Null,
                PARSE_ERROR,
                "parse error: request line is not valid JSON.",
            ));
        }
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);
    let Some(id) = id else {
        // A message without an id is a notification and must never be
        // answered. `notifications/initialized` is accepted here; unknown
        // notifications are ignored by design.
        return None;
    };
    let Some(method) = method else {
        return Some(error_response(
            id,
            INVALID_REQUEST,
            "invalid request: method is required.",
        ));
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let outcome = match method {
        "initialize" => Ok(initialize_result(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(&params, context),
        other => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("method not found: {other}"),
        }),
    };
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => error_response(id, error.code, &error.message),
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn initialize_result(params: &Value) -> Value {
    // Echo the requested protocol version: this server's surface is small
    // enough to be version-agnostic across published MCP revisions.
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "agvt", "version": env!("CARGO_PKG_VERSION") },
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "dossier_search",
            "description": "Search Agent Home dossier entries by case-insensitive substring over topic, tags, and open/standard bodies. Locked bodies are encrypted and never searched; locked entries match on topic and tags only. Results carry metadata only (id, topic, tags, tier, updatedAt), never bodies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Substring to search for."
                    },
                    "tier": {
                        "type": "string",
                        "enum": ["open", "standard", "locked"],
                        "description": "Optional filter to one sensitivity tier."
                    }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "dossier_read",
            "description": "Read one dossier entry by id. open/standard entries return their body. locked entries never return the body: the response carries an agvt://dossier/<id>/body reference and consumption instructions instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Dossier entry id (as returned by dossier_search)."
                    }
                },
                "required": ["id"]
            }
        }),
        json!({
            "name": "charter_check",
            "description": "Resolve the autonomy verdict for one capability/scope pair from the Agent Home charter. Returns {capability, scope, autonomy, matchedRule}; undefined capabilities, unmatched scopes, and a missing or unreadable charter always resolve to \"confirm\".",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "description": "Capability name, e.g. \"commit\"."
                    },
                    "scope": {
                        "type": "string",
                        "description": "Scope, e.g. \"repo:autofill-browser\"."
                    }
                },
                "required": ["capability", "scope"]
            }
        }),
        json!({
            "name": "vault_ls",
            "description": "List global vault item metadata: item name, kind, and label only. Secret values are never included; use secret_handoff to obtain a consumable agvt:// reference.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "secret_handoff",
            "description": "Return an agvt://global/<item>/<field> reference plus consumption instructions for one global vault secret. The secret value itself is never returned; consume the reference via `agvt run` environment injection.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": {
                        "type": "string",
                        "description": "Global vault item name."
                    },
                    "field": {
                        "type": "string",
                        "description": "Field name (default: token)."
                    }
                },
                "required": ["item"]
            }
        }),
    ]
}

fn call_tool(params: &Value, context: &McpContext) -> std::result::Result<Value, RpcError> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err(RpcError {
            code: INVALID_PARAMS,
            message: "tools/call requires params.name.".to_owned(),
        });
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let payload = match name {
        "dossier_search" => dossier_search(&arguments, context),
        "dossier_read" => dossier_read(&arguments, context),
        "charter_check" => charter_check(&arguments, context),
        "vault_ls" => vault_ls(context),
        "secret_handoff" => secret_handoff(&arguments, context),
        other => {
            return Err(RpcError {
                code: INVALID_PARAMS,
                message: format!("unknown tool: {other}"),
            })
        }
    };
    // Tool-level failures (entry not found, invalid tier, ...) are execution
    // errors, reported inside the result per the MCP tool contract.
    Ok(match payload {
        Ok(value) => tool_result(&value),
        Err(error) => tool_error(&error.to_string()),
    })
}

fn tool_result(payload: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": payload.to_string() }],
        "isError": false,
    })
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

fn require_string(arguments: &Value, key: &str, tool: &str) -> Result<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AgvtError::new(format!(
                "{tool} requires a non-empty string argument: {key}"
            ))
        })
}

fn optional_tier(arguments: &Value) -> Result<Option<Tier>> {
    match arguments.get("tier") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(Tier::parse(value)?)),
        Some(_) => Err(AgvtError::new("tier must be a string.")),
    }
}

fn summary_json(summary: &EntrySummary) -> Value {
    json!({
        "id": summary.id,
        "topic": summary.topic,
        "tags": summary.tags,
        "tier": summary.tier.as_str(),
        "updatedAt": summary.updated_at,
    })
}

fn dossier_search(arguments: &Value, context: &McpContext) -> Result<Value> {
    let query = require_string(arguments, "query", "dossier_search")?;
    let tier = optional_tier(arguments)?;
    // The query text is deliberately not recorded: the audit log holds
    // references only, never payloads.
    audit::record(
        "mcp-dossier_search",
        &SecretRef {
            vault: "dossier".to_owned(),
            item: "*".to_owned(),
            field: "search".to_owned(),
        },
        MCP_CALLER,
    );
    let summaries = dossier::search_entries(&context.dossier_path, &query, tier)?;
    Ok(json!({
        "entries": summaries.iter().map(summary_json).collect::<Vec<_>>(),
    }))
}

fn dossier_read(arguments: &Value, context: &McpContext) -> Result<Value> {
    let id = validate_name(
        &require_string(arguments, "id", "dossier_read")?,
        "dossier id",
    )?;
    let shown = match dossier::show_entry(&context.dossier_path, &id, None) {
        Ok(shown) => shown,
        Err(error) => {
            audit::record(
                "mcp-dossier_read",
                &dossier::dossier_body_ref(&id),
                MCP_CALLER,
            );
            return Err(error);
        }
    };
    let op = if shown.tier == Tier::Locked {
        // ADR 0014: the audit log must distinguish locked reads.
        "mcp-dossier_read-locked"
    } else {
        "mcp-dossier_read"
    };
    audit::record(op, &dossier::dossier_body_ref(&id), MCP_CALLER);
    if shown.tier == Tier::Locked {
        // The locked body is never decrypted here (no decryption call exists
        // in this module); only the reference leaves the process.
        return Ok(json!({
            "id": shown.id,
            "topic": shown.topic,
            "tags": shown.tags,
            "tier": "locked",
            "updatedAt": shown.updated_at,
            "reference": shown.body_ref,
            "instruction": "The locked body is never returned over MCP. Consume it via `agvt run` environment injection, referencing it by the agvt:// reference above.",
        }));
    }
    Ok(json!({
        "id": shown.id,
        "topic": shown.topic,
        "tags": shown.tags,
        "tier": shown.tier.as_str(),
        "updatedAt": shown.updated_at,
        "body": shown.body,
    }))
}

fn charter_check(arguments: &Value, context: &McpContext) -> Result<Value> {
    let capability = require_string(arguments, "capability", "charter_check")?;
    let scope = require_string(arguments, "scope", "charter_check")?;
    audit::record(
        "mcp-charter_check",
        &SecretRef {
            vault: "charter".to_owned(),
            item: capability.clone(),
            field: scope.clone(),
        },
        MCP_CALLER,
    );
    let charter = charter::load_charter_lenient(&context.charter_path);
    let (autonomy, matched) = charter::resolve(&charter, &capability, &scope);
    Ok(json!({
        "capability": capability,
        "scope": scope,
        "autonomy": autonomy,
        "matchedRule": matched.as_ref().map(charter::rule_json),
    }))
}

fn vault_ls(context: &McpContext) -> Result<Value> {
    audit::record(
        "mcp-vault_ls",
        &SecretRef {
            vault: "global".to_owned(),
            item: "*".to_owned(),
            field: "ls".to_owned(),
        },
        MCP_CALLER,
    );
    let items = list_items(&context.global_vault_path)?;
    Ok(json!({
        "items": items
            .iter()
            .map(|item| json!({
                "item": item.item,
                "kind": item.kind,
                "label": item.label,
            }))
            .collect::<Vec<_>>(),
    }))
}

fn secret_handoff(arguments: &Value, context: &McpContext) -> Result<Value> {
    let item = validate_name(
        &require_string(arguments, "item", "secret_handoff")?,
        "item",
    )?;
    let field = match arguments.get("field") {
        None | Some(Value::Null) => "token".to_owned(),
        Some(Value::String(value)) => canonical_field_name(value)?,
        Some(_) => return Err(AgvtError::new("field must be a string.")),
    };
    let secret_ref = SecretRef {
        vault: "global".to_owned(),
        item,
        field,
    };
    audit::record("mcp-secret_handoff", &secret_ref, MCP_CALLER);
    // Existence is metadata (vault_ls already exposes item names); the value
    // itself is never read or decrypted on this path.
    let item_found = list_items(&context.global_vault_path)?
        .iter()
        .any(|listed| listed.vault == "global" && listed.item == secret_ref.item);
    let reference = format!(
        "agvt://{}/{}/{}",
        secret_ref.vault, secret_ref.item, secret_ref.field
    );
    Ok(json!({
        "reference": reference,
        "itemFound": item_found,
        "instruction": format!(
            "Never print the secret value. Consume the reference via environment injection: `agvt run --env ENV_NAME={reference} -- <command>`."
        ),
    }))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::io::Cursor;
    use std::path::Path;

    use super::*;
    use crate::dossier::AddEntryInput;
    use crate::reference::item_target_to_ref;
    use crate::vault::UpsertTokenInput;

    const PASSPHRASE: &str = "test-passphrase-with-enough-length";

    fn context(directory: &Path) -> McpContext {
        McpContext {
            dossier_path: directory.join("dossier.json"),
            charter_path: directory.join("charter.json"),
            global_vault_path: directory.join("agent-vault.json"),
        }
    }

    fn serve_lines(lines: &[Value], context: &McpContext) -> Vec<Value> {
        let input = lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, context).unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    fn tool_call(id: u64, tool: &str, arguments: Value) -> Value {
        request(
            id,
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
    }

    /// Extracts the JSON payload from a tools/call result.
    fn tool_payload(response: &Value) -> Value {
        assert_eq!(response["result"]["isError"], false, "{response}");
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    fn add_dossier_entry(context: &McpContext, id: &str, topic: &str, body: &str, tier: Tier) {
        dossier::add_entry(
            &context.dossier_path,
            AddEntryInput {
                id: Some(id.to_owned()),
                topic: topic.to_owned(),
                body: body.to_owned(),
                tags: vec!["test-tag".to_owned()],
                tier,
            },
            if tier == Tier::Locked {
                Some(PASSPHRASE)
            } else {
                None
            },
        )
        .unwrap();
    }

    #[test]
    fn initialize_echoes_protocol_version_and_lists_all_five_tools() {
        let directory = tempfile::tempdir().unwrap();
        let responses = serve_lines(
            &[
                request(
                    1,
                    "initialize",
                    json!({ "protocolVersion": "2024-11-05", "capabilities": {} }),
                ),
                json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
                request(2, "tools/list", Value::Null),
            ],
            &context(directory.path()),
        );

        // The initialized notification gets no response line.
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "agvt");
        assert_eq!(
            responses[0]["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(responses[0]["result"]["capabilities"]["tools"].is_object());

        let tools = responses[1]["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "dossier_search",
                "dossier_read",
                "charter_check",
                "vault_ls",
                "secret_handoff"
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn unknown_method_and_malformed_json_keep_the_loop_alive() {
        let directory = tempfile::tempdir().unwrap();
        let input = format!(
            "{}\nthis is not json\n{}\n",
            request(1, "no/such/method", Value::Null),
            request(2, "ping", Value::Null)
        );
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &context(directory.path())).unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], -32601);
        assert_eq!(responses[1]["error"]["code"], -32700);
        assert!(responses[1]["id"].is_null());
        // The loop survives the malformed line and answers the next request.
        assert_eq!(responses[2]["id"], 2);
        assert!(responses[2]["result"].is_object());
    }

    #[test]
    fn request_without_method_is_invalid_request() {
        let directory = tempfile::tempdir().unwrap();
        let responses = serve_lines(
            &[json!({ "jsonrpc": "2.0", "id": 9 })],
            &context(directory.path()),
        );
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["error"]["code"], -32600);
        assert_eq!(responses[0]["id"], 9);
    }

    #[test]
    fn dossier_search_returns_metadata_only_and_honors_tier_filter() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        env::set_var(
            audit::AGVT_AUDIT_PATH_ENV,
            directory.path().join("audit.jsonl"),
        );
        let context = context(directory.path());
        add_dossier_entry(
            &context,
            "company-notes",
            "company challenges",
            "shipping agent-first products",
            Tier::Open,
        );
        add_dossier_entry(
            &context,
            "client-names",
            "company clients",
            "acme corp",
            Tier::Standard,
        );

        let responses = serve_lines(
            &[
                tool_call(1, "dossier_search", json!({ "query": "company" })),
                tool_call(
                    2,
                    "dossier_search",
                    json!({ "query": "company", "tier": "open" }),
                ),
            ],
            &context,
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);

        let all = tool_payload(&responses[0]);
        assert_eq!(all["entries"].as_array().unwrap().len(), 2);
        // Search results are metadata only: no body field, no body text.
        let raw = responses[0].to_string();
        assert!(!raw.contains("shipping agent-first products"));
        assert!(!raw.contains("acme corp"));
        assert!(all["entries"][0]["updatedAt"].is_string());

        let open_only = tool_payload(&responses[1]);
        let entries = open_only["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["id"], "company-notes");
        assert_eq!(entries[0]["tier"], "open");
    }

    #[test]
    fn dossier_read_returns_open_bodies_but_only_references_for_locked() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        env::set_var(audit::AGVT_AUDIT_PATH_ENV, &audit_path);
        let context = context(directory.path());
        let secret_body = "account-number-1234567890-locked";
        add_dossier_entry(
            &context,
            "public-notes",
            "notes",
            "open body text",
            Tier::Open,
        );
        add_dossier_entry(
            &context,
            "brokerage",
            "brokerage account",
            secret_body,
            Tier::Locked,
        );

        let responses = serve_lines(
            &[
                tool_call(1, "dossier_read", json!({ "id": "public-notes" })),
                tool_call(2, "dossier_read", json!({ "id": "brokerage" })),
            ],
            &context,
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);

        let open = tool_payload(&responses[0]);
        assert_eq!(open["body"], "open body text");
        assert_eq!(open["tier"], "open");

        let locked = tool_payload(&responses[1]);
        assert_eq!(locked["tier"], "locked");
        assert_eq!(locked["reference"], "agvt://dossier/brokerage/body");
        assert!(locked["instruction"].as_str().unwrap().contains("agvt run"));
        assert!(locked.get("body").is_none());

        // Non-inclusion over the entire serialized response stream.
        let full_stream = serde_json::to_string(&responses).unwrap();
        assert!(!full_stream.contains(secret_body));

        // Locked reads are distinguishable in the audit log (ADR 0014).
        let raw_audit = fs::read_to_string(&audit_path).unwrap();
        assert!(raw_audit.contains("\"op\":\"mcp-dossier_read\""));
        assert!(raw_audit.contains("\"op\":\"mcp-dossier_read-locked\""));
        assert!(raw_audit.contains("agvt://dossier/brokerage/body"));
        assert!(!raw_audit.contains(secret_body));
    }

    #[test]
    fn dossier_read_missing_entry_is_a_tool_error_not_a_crash() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        env::set_var(
            audit::AGVT_AUDIT_PATH_ENV,
            directory.path().join("audit.jsonl"),
        );
        let responses = serve_lines(
            &[tool_call(1, "dossier_read", json!({ "id": "nope" }))],
            &context(directory.path()),
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);
        assert_eq!(responses[0]["result"]["isError"], true);
    }

    #[test]
    fn charter_check_resolves_rules_and_falls_back_to_confirm() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        env::set_var(
            audit::AGVT_AUDIT_PATH_ENV,
            directory.path().join("audit.jsonl"),
        );
        let context = context(directory.path());
        fs::write(
            &context.charter_path,
            serde_json::to_string_pretty(&json!({
                "schemaVersion": 1,
                "rules": [{
                    "capability": "commit",
                    "scope": "repo:autofill-browser",
                    "autonomy": "auto",
                }],
            }))
            .unwrap(),
        )
        .unwrap();

        let responses = serve_lines(
            &[
                tool_call(
                    1,
                    "charter_check",
                    json!({ "capability": "commit", "scope": "repo:autofill-browser" }),
                ),
                tool_call(
                    2,
                    "charter_check",
                    json!({ "capability": "deploy", "scope": "repo:autofill-browser" }),
                ),
            ],
            &context,
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);

        let matched = tool_payload(&responses[0]);
        assert_eq!(matched["autonomy"], "auto");
        assert_eq!(matched["matchedRule"]["scope"], "repo:autofill-browser");

        let fallback = tool_payload(&responses[1]);
        assert_eq!(fallback["autonomy"], "confirm");
        assert!(fallback["matchedRule"].is_null());
    }

    #[test]
    fn vault_ls_and_secret_handoff_never_expose_values() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        env::set_var(audit::AGVT_AUDIT_PATH_ENV, &audit_path);
        let context = context(directory.path());
        let secret_value = "github_dummy_secret_value";
        let secret_ref =
            item_target_to_ref("agvt://global/github/token", "global", "token").unwrap();
        crate::vault::upsert_api_token(
            &context.global_vault_path,
            PASSPHRASE,
            UpsertTokenInput {
                secret_ref,
                token: secret_value.to_owned(),
                label: Some("GitHub".to_owned()),
                service_url: None,
                account_name: None,
                account_id: None,
                token_id: None,
                expires_on: None,
                notes: None,
            },
        )
        .unwrap();

        let responses = serve_lines(
            &[
                tool_call(1, "vault_ls", json!({})),
                tool_call(2, "secret_handoff", json!({ "item": "github" })),
                tool_call(
                    3,
                    "secret_handoff",
                    json!({ "item": "missing-item", "field": "token" }),
                ),
            ],
            &context,
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);

        let listed = tool_payload(&responses[0]);
        assert_eq!(listed["items"][0]["item"], "github");
        assert_eq!(listed["items"][0]["kind"], "api-token");
        assert_eq!(listed["items"][0]["label"], "GitHub");

        let handoff = tool_payload(&responses[1]);
        assert_eq!(handoff["reference"], "agvt://global/github/token");
        assert_eq!(handoff["itemFound"], true);
        assert!(handoff["instruction"]
            .as_str()
            .unwrap()
            .contains("agvt run"));

        let missing = tool_payload(&responses[2]);
        assert_eq!(missing["itemFound"], false);

        // The secret value appears nowhere in the whole response stream nor
        // in the audit log.
        let full_stream = serde_json::to_string(&responses).unwrap();
        assert!(!full_stream.contains(secret_value));
        let raw_audit = fs::read_to_string(&audit_path).unwrap();
        assert!(raw_audit.contains("\"op\":\"mcp-vault_ls\""));
        assert!(raw_audit.contains("\"op\":\"mcp-secret_handoff\""));
        assert!(raw_audit.contains("agvt://global/github/token"));
        assert!(!raw_audit.contains(secret_value));
    }

    #[test]
    fn unknown_tool_and_missing_arguments_are_rejected() {
        let _guard = crate::audit::lock_test_env();
        let directory = tempfile::tempdir().unwrap();
        env::set_var(
            audit::AGVT_AUDIT_PATH_ENV,
            directory.path().join("audit.jsonl"),
        );
        let responses = serve_lines(
            &[
                tool_call(1, "no_such_tool", json!({})),
                tool_call(2, "dossier_search", json!({})),
                tool_call(
                    3,
                    "dossier_search",
                    json!({ "query": "x", "tier": "secret" }),
                ),
            ],
            &context(directory.path()),
        );
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);

        assert_eq!(responses[0]["error"]["code"], -32602);
        assert_eq!(responses[1]["result"]["isError"], true);
        assert!(responses[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("query"));
        assert_eq!(responses[2]["result"]["isError"], true);
    }
}
