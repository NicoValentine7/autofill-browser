//! Binary integration tests for `agvt mcp`: a real child process speaking
//! newline-delimited JSON-RPC 2.0 over stdin/stdout, with all state paths
//! injected into a temporary directory.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const PASSPHRASE: &str = "test-passphrase-with-enough-length";

fn agvt_command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agvt"));
    command
        // Only the global vault path is overridden: passing --vault-path
        // would switch agvt into single-vault mode and route agvt://global/
        // references away from the global vault file.
        .arg("--global-vault-path")
        .arg(directory.join("global-vault.json"))
        .env("AGVT_PASSPHRASE", PASSPHRASE)
        // Keep every state file inside the test directory.
        .env("AGVT_AUDIT_PATH", directory.join("audit.jsonl"))
        .env("AGVT_CHARTER_PATH", directory.join("charter.json"))
        .env("AGVT_DOSSIER_PATH", directory.join("dossier.json"));
    command
}

fn seed(directory: &Path, secret_body: &str, secret_token: &str) {
    let seeds: Vec<Vec<String>> = vec![
        vec![
            "dossier".into(),
            "add".into(),
            "company challenges".into(),
            "--body".into(),
            "shipping agent-first products".into(),
            "--tags".into(),
            "company,strategy".into(),
            "--tier".into(),
            "open".into(),
            "--id".into(),
            "company-notes".into(),
        ],
        vec![
            "dossier".into(),
            "add".into(),
            "brokerage account".into(),
            "--body".into(),
            secret_body.into(),
            "--tier".into(),
            "locked".into(),
            "--id".into(),
            "brokerage".into(),
        ],
        vec![
            "charter".into(),
            "add".into(),
            "commit".into(),
            "repo:autofill-browser".into(),
            "auto".into(),
        ],
    ];
    for arguments in seeds {
        let output = agvt_command(directory).args(&arguments).output().unwrap();
        assert!(
            output.status.success(),
            "seed {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = agvt_command(directory)
        .args([
            "add",
            "agvt://global/github/token",
            "--from-env",
            "SEED_TOKEN",
        ])
        .env("SEED_TOKEN", secret_token)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "vault seed failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Sends one line per message to a real `agvt mcp` child process, closes
/// stdin, and returns (stdout responses, stderr).
fn run_mcp_session(directory: &Path, messages: &[String]) -> (Vec<Value>, String) {
    let mut child = agvt_command(directory)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for message in messages {
            stdin.write_all(message.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    // Dropping stdin sends EOF; the server must exit cleanly.
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "agvt mcp exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (
        responses,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn tool_payload(response: &Value) -> Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn mcp_full_round_trip_over_child_process_stdio() {
    let directory = tempfile::tempdir().unwrap();
    let secret_body = "locked-account-number-9876543210";
    let secret_token = "github_dummy_secret_value";
    seed(directory.path(), secret_body, secret_token);

    let messages = vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0.0.1"},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string(),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "dossier_search", "arguments": {"query": "brokerage"},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "dossier_read", "arguments": {"id": "brokerage"},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "charter_check",
            "arguments": {"capability": "commit", "scope": "repo:autofill-browser"},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
            "name": "vault_ls", "arguments": {},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "secret_handoff", "arguments": {"item": "github"},
        }})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 8, "method": "no/such/method"}).to_string(),
        "{ this is not valid json".to_owned(),
    ];
    let (responses, _stderr) = run_mcp_session(directory.path(), &messages);

    // 10 lines in, 1 notification (unanswered) -> 9 responses out, in order.
    assert_eq!(responses.len(), 9);

    // initialize: echoed protocol version, tools capability, serverInfo.
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "agvt");
    assert!(responses[0]["result"]["capabilities"]["tools"].is_object());

    // tools/list: exactly the five Agent Home tools.
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

    // dossier_search: the locked entry matches on topic, metadata only.
    let search = tool_payload(&responses[2]);
    let entries = search["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "brokerage");
    assert_eq!(entries[0]["tier"], "locked");

    // dossier_read on locked: reference + instruction, never the body.
    let locked = tool_payload(&responses[3]);
    assert_eq!(locked["tier"], "locked");
    assert_eq!(locked["reference"], "agvt://dossier/brokerage/body");
    assert!(locked["instruction"].as_str().unwrap().contains("agvt run"));

    // charter_check matches the CLI verdict for the same rule.
    let verdict = tool_payload(&responses[4]);
    assert_eq!(verdict["autonomy"], "auto");
    assert_eq!(verdict["matchedRule"]["scope"], "repo:autofill-browser");

    // vault_ls: names/kinds/labels only.
    let listed = tool_payload(&responses[5]);
    assert_eq!(listed["items"][0]["item"], "github");
    assert_eq!(listed["items"][0]["kind"], "api-token");

    // secret_handoff: reference and consumption instruction only.
    let handoff = tool_payload(&responses[6]);
    assert_eq!(handoff["reference"], "agvt://global/github/token");
    assert_eq!(handoff["itemFound"], true);
    assert!(handoff["instruction"]
        .as_str()
        .unwrap()
        .contains("agvt run"));

    // Unknown method -> -32601 with the request id.
    assert_eq!(responses[7]["id"], 8);
    assert_eq!(responses[7]["error"]["code"], -32601);

    // Malformed JSON -> -32700 with null id, without killing the server
    // (the process still exited cleanly on EOF afterwards).
    assert!(responses[8]["id"].is_null());
    assert_eq!(responses[8]["error"]["code"], -32700);

    // Security invariant: neither the locked body nor the secret value
    // appears anywhere in the entire response stream.
    let full_stream = serde_json::to_string(&responses).unwrap();
    assert!(!full_stream.contains(secret_body));
    assert!(!full_stream.contains(secret_token));

    // Every tools/call left an audit entry with caller "mcp" and no secrets.
    let raw_audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(raw_audit.contains("\"op\":\"mcp-dossier_search\""));
    assert!(raw_audit.contains("\"op\":\"mcp-dossier_read-locked\""));
    assert!(raw_audit.contains("\"op\":\"mcp-charter_check\""));
    assert!(raw_audit.contains("\"op\":\"mcp-vault_ls\""));
    assert!(raw_audit.contains("\"op\":\"mcp-secret_handoff\""));
    assert!(raw_audit.contains("\"caller\":\"mcp\""));
    assert!(!raw_audit.contains(secret_body));
    assert!(!raw_audit.contains(secret_token));
}

#[test]
fn mcp_rejects_extra_cli_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let output = agvt_command(directory.path())
        .args(["mcp", "extra"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("mcp takes no arguments"));
}
