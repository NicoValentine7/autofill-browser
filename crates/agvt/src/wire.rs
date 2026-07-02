//! `agvt wire` — environment bootstrap wiring (ADR 0013).
//!
//! Generates configuration only: an `.mcp.json` server registration and a
//! CLAUDE.md/AGENTS.md bootstrap fragment. Wire output must never contain
//! secret values, `standard`/`locked` dossier bodies, or any reference value
//! other than the `agvt://` scheme (ADR 0014). This is deliberately distinct
//! from `agvt inject`, which resolves secret references into rendered values.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::audit;
use crate::charter;
use crate::dossier;
use crate::error::{AgvtError, Result};
use crate::reference::SecretRef;
use crate::{take_value, GlobalOptions};

const MCP_FILE_NAME: &str = ".mcp.json";
const FRAGMENT_FILE_NAME: &str = ".agent-home.md";

#[derive(Debug, Default)]
pub(crate) struct WireCliOptions {
    pub target: Option<PathBuf>,
    pub print: bool,
}

/// What one `agvt wire` invocation produced. The handler decides how to
/// present it; keeping this separate from printing makes the security
/// invariants testable on the exact bytes written.
#[derive(Debug)]
pub(crate) struct WireOutcome {
    pub fragment: String,
    pub mcp_path: Option<PathBuf>,
    pub fragment_path: Option<PathBuf>,
}

pub(crate) fn handle_wire(options: &GlobalOptions) -> Result<()> {
    let cli = parse_wire_cli_options(&options.args)?;
    let outcome = run_wire(&cli, &dossier::dossier_path(), &charter::charter_path())?;
    if cli.print {
        print!("{}", outcome.fragment);
    }
    if let (Some(mcp_path), Some(fragment_path)) = (&outcome.mcp_path, &outcome.fragment_path) {
        println!(
            "wrote {} (registered mcpServers.agvt -> `agvt mcp`)",
            mcp_path.display()
        );
        println!(
            "wrote {} (Agent Home bootstrap fragment)",
            fragment_path.display()
        );
        println!();
        println!("Next steps:");
        println!(
            "  - Claude Code: add `@{FRAGMENT_FILE_NAME}` on its own line to CLAUDE.md in the target directory."
        );
        println!(
            "  - Codex and other agents: append the contents of {FRAGMENT_FILE_NAME} to AGENTS.md."
        );
        println!(
            "  - The fragment holds open-tier context only; standard/locked entries stay behind `agvt mcp`."
        );
    }
    Ok(())
}

fn parse_wire_cli_options(args: &[String]) -> Result<WireCliOptions> {
    let mut options = WireCliOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--target" => {
                options.target = Some(PathBuf::from(take_value(args, index, "--target")?));
                index += 1;
            }
            "--print" => options.print = true,
            other => {
                return Err(AgvtError::new(format!("unknown wire option: {other}")));
            }
        }
        index += 1;
    }
    if options.target.is_none() && !options.print {
        return Err(AgvtError::new(
            "wire requires --target DIR and/or --print. \
             --target DIR merges an agvt server entry into DIR/.mcp.json and writes DIR/.agent-home.md; \
             --print writes the bootstrap fragment to stdout for copy-paste into cloud environments.",
        ));
    }
    Ok(options)
}

pub(crate) fn run_wire(
    cli: &WireCliOptions,
    dossier_path: &Path,
    charter_path: &Path,
) -> Result<WireOutcome> {
    let fragment = build_fragment(dossier_path, charter_path)?;
    let mut outcome = WireOutcome {
        fragment,
        mcp_path: None,
        fragment_path: None,
    };
    if let Some(target) = &cli.target {
        if !target.is_dir() {
            return Err(AgvtError::new(format!(
                "wire --target directory does not exist: {}",
                target.display()
            )));
        }
        let mcp_path = target.join(MCP_FILE_NAME);
        let existing = if mcp_path.exists() {
            Some(fs::read_to_string(&mcp_path)?)
        } else {
            None
        };
        // Merge before writing anything: a corrupt .mcp.json aborts the whole
        // wiring so the target directory is never left half-configured.
        let merged = merged_mcp_config(existing.as_deref())?;
        write_atomic(&mcp_path, &merged)?;
        write_atomic(&target.join(FRAGMENT_FILE_NAME), &outcome.fragment)?;
        outcome.mcp_path = Some(mcp_path);
        outcome.fragment_path = Some(target.join(FRAGMENT_FILE_NAME));
        audit::record("wire", &wire_ref("target"), "agvt");
    }
    if cli.print {
        audit::record("wire", &wire_ref("print"), "agvt");
    }
    Ok(outcome)
}

/// Audit reference for wire runs. Wire handles no items or fields, so the
/// reference records only the delivery mode; target paths and dossier
/// contents never enter the audit log.
fn wire_ref(mode: &str) -> SecretRef {
    SecretRef {
        vault: "wire".to_owned(),
        item: "bootstrap".to_owned(),
        field: mode.to_owned(),
    }
}

/// Merges the agvt server registration into an existing `.mcp.json` document.
///
/// Every key other than `mcpServers.agvt` is preserved verbatim. A file that
/// does not parse as JSON, or whose top level / `mcpServers` is not an
/// object, is refused rather than rewritten — clobbering a hand-maintained
/// config to register ourselves is never acceptable.
fn merged_mcp_config(existing_raw: Option<&str>) -> Result<String> {
    let mut root = match existing_raw {
        Some(raw) => serde_json::from_str::<Value>(raw).map_err(|error| {
            AgvtError::new(format!(
                "existing {MCP_FILE_NAME} is not valid JSON ({error}); refusing to rewrite it. Fix the file and rerun `agvt wire`."
            ))
        })?,
        None => serde_json::json!({}),
    };
    let Value::Object(object) = &mut root else {
        return Err(AgvtError::new(format!(
            "existing {MCP_FILE_NAME} must hold a JSON object at the top level; refusing to rewrite it."
        )));
    };
    let servers = object
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    let Value::Object(servers) = servers else {
        return Err(AgvtError::new(format!(
            "existing {MCP_FILE_NAME} has a non-object mcpServers; refusing to rewrite it."
        )));
    };
    servers.insert(
        "agvt".to_owned(),
        serde_json::json!({ "command": "agvt", "args": ["mcp"] }),
    );
    Ok(format!("{}\n", serde_json::to_string_pretty(&root)?))
}

/// Builds the bootstrap fragment: open-tier dossier summary, MCP connection
/// notes, and the Charter digest. Security invariant (ADR 0013/0014): no
/// secret values, and for standard/locked entries neither bodies nor topics —
/// only their counts appear.
pub(crate) fn build_fragment(dossier_path: &Path, charter_path: &Path) -> Result<String> {
    let context = dossier::wire_context(dossier_path)?;
    let rules = charter::wire_rules(charter_path);

    let mut out = String::new();
    out.push_str("<!-- Generated by `agvt wire`. Rerun `agvt wire` to refresh instead of editing by hand. -->\n");
    out.push_str("# Agent Home bootstrap (agvt)\n\n");
    out.push_str(
        "This fragment wires an agent environment to the local Agent Home\n\
         (Vault / Dossier / Charter). It contains open-tier context only:\n\
         no secret values and no standard/locked dossier content.\n\n",
    );

    out.push_str("## Open context (Dossier)\n\n");
    if context.open_entries.is_empty() {
        out.push_str("No open-tier dossier entries.\n\n");
    } else {
        for entry in &context.open_entries {
            out.push_str(&format!("### {}\n\n{}\n\n", entry.topic, entry.body));
        }
    }
    out.push_str(&format!(
        "Additional dossier entries not embedded here — standard: {}, locked: {}.\n\
         standard entries are served only by the local `agvt mcp` server; locked\n\
         entries resolve to `agvt://` references consumed via `agvt run`.\n\n",
        context.standard_count, context.locked_count
    ));

    out.push_str("## MCP connection\n\n");
    out.push_str(
        "`agvt mcp` runs a stdio MCP server (registered as the `agvt` server in\n\
         `.mcp.json`). It exposes:\n\n\
         - `dossier_search` / `dossier_read` — tier-filtered context lookup.\n\
         - `charter_check` — machine-readable autonomy verdicts.\n\
         - `vault_ls` — item names only, never values.\n\
         - `secret_handoff` — returns an `agvt://` reference, never a raw value.\n\n\
         Raw secret values and locked bodies never appear in MCP responses.\n\
         Consume references with `agvt run --env NAME=agvt://... -- <command>`.\n\n\
         `.mcp.json` registration:\n\n\
         ```json\n\
         {\n  \"mcpServers\": {\n    \"agvt\": { \"command\": \"agvt\", \"args\": [\"mcp\"] }\n  }\n}\n\
         ```\n\n",
    );

    out.push_str("## Charter digest\n\n");
    if rules.is_empty() {
        out.push_str("No charter rules are defined.\n");
    } else {
        out.push_str("| capability | scope | autonomy | conditions |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for rule in &rules {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                rule.capability,
                rule.scope,
                rule.autonomy,
                rule.conditions.as_deref().unwrap_or("-")
            ));
        }
    }
    out.push_str(
        "\nAnything not listed resolves to `confirm` (fail toward confirm).\n\
         Verify with `agvt charter check <capability> <scope>`.\n",
    );
    Ok(out)
}

fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary_path, contents)?;
    fs::rename(&temporary_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::audit::TEST_ENV_LOCK as ENV_LOCK;
    use crate::dossier::{add_entry, AddEntryInput, Tier};

    const PASSPHRASE: &str = "wire-test-passphrase-with-enough-length";
    const OPEN_TOPIC: &str = "open-device-models";
    const OPEN_BODY: &str = "printer model X-1000, laptop model Y-2000";
    const STANDARD_TOPIC: &str = "std-client-names-xyz";
    const STANDARD_BODY: &str = "std-body-acme-corp-xyz";
    const LOCKED_TOPIC: &str = "locked-account-topic-xyz";
    const LOCKED_BODY: &str = "locked-account-number-9876543210";

    fn seed(directory: &Path) -> (PathBuf, PathBuf) {
        let dossier_path = directory.join("dossier.json");
        let charter_path = directory.join("charter.json");
        for (topic, body, tier) in [
            (OPEN_TOPIC, OPEN_BODY, Tier::Open),
            (STANDARD_TOPIC, STANDARD_BODY, Tier::Standard),
            (LOCKED_TOPIC, LOCKED_BODY, Tier::Locked),
        ] {
            add_entry(
                &dossier_path,
                AddEntryInput {
                    id: None,
                    topic: topic.to_owned(),
                    body: body.to_owned(),
                    tags: Vec::new(),
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
        fs::write(
            &charter_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "rules": [{
                    "capability": "commit",
                    "scope": "repo:autofill-browser",
                    "autonomy": "auto",
                    "conditions": "build/test GREEN",
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        (dossier_path, charter_path)
    }

    /// Runs `run_wire` with the audit log redirected to a temp file so tests
    /// never touch the real user audit log.
    fn run_wire_audited(
        cli: &WireCliOptions,
        dossier_path: &Path,
        charter_path: &Path,
        audit_path: &Path,
    ) -> Result<WireOutcome> {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var(audit::AGVT_AUDIT_PATH_ENV, audit_path);
        let outcome = run_wire(cli, dossier_path, charter_path);
        env::remove_var(audit::AGVT_AUDIT_PATH_ENV);
        outcome
    }

    #[test]
    fn fragment_contains_open_only_and_charter_digest() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());

        let fragment = build_fragment(&dossier_path, &charter_path).unwrap();

        // open tier: topic and body are embedded.
        assert!(fragment.contains(OPEN_TOPIC));
        assert!(fragment.contains(OPEN_BODY));
        // standard/locked: neither bodies nor topics may appear (ADR 0014);
        // only their counts do.
        assert!(!fragment.contains(STANDARD_TOPIC));
        assert!(!fragment.contains(STANDARD_BODY));
        assert!(!fragment.contains(LOCKED_TOPIC));
        assert!(!fragment.contains(LOCKED_BODY));
        assert!(fragment.contains("standard: 1, locked: 1"));
        // charter digest row and fail-toward-confirm note.
        assert!(fragment.contains("| commit | repo:autofill-browser | auto | build/test GREEN |"));
        assert!(fragment.contains("resolves to `confirm`"));
        // the only reference scheme mentioned anywhere is agvt://.
        assert!(fragment.contains("agvt://"));
    }

    #[test]
    fn fragment_handles_missing_dossier_and_charter() {
        let directory = tempfile::tempdir().unwrap();
        let fragment = build_fragment(
            &directory.path().join("missing-dossier.json"),
            &directory.path().join("missing-charter.json"),
        )
        .unwrap();
        assert!(fragment.contains("No open-tier dossier entries."));
        assert!(fragment.contains("No charter rules are defined."));
        assert!(fragment.contains("standard: 0, locked: 0"));
    }

    #[test]
    fn target_creates_mcp_json_and_fragment() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let target = directory.path().join("project");
        fs::create_dir(&target).unwrap();

        let outcome = run_wire_audited(
            &WireCliOptions {
                target: Some(target.clone()),
                print: false,
            },
            &dossier_path,
            &charter_path,
            &directory.path().join("audit.jsonl"),
        )
        .unwrap();

        let mcp: Value =
            serde_json::from_str(&fs::read_to_string(target.join(MCP_FILE_NAME)).unwrap()).unwrap();
        assert_eq!(mcp["mcpServers"]["agvt"]["command"], "agvt");
        assert_eq!(
            mcp["mcpServers"]["agvt"]["args"],
            serde_json::json!(["mcp"])
        );

        let written_fragment = fs::read_to_string(target.join(FRAGMENT_FILE_NAME)).unwrap();
        assert_eq!(written_fragment, outcome.fragment);
        // The generated .mcp.json carries no dossier or secret content at all.
        let raw_mcp = fs::read_to_string(target.join(MCP_FILE_NAME)).unwrap();
        for leak in [
            OPEN_BODY,
            STANDARD_TOPIC,
            STANDARD_BODY,
            LOCKED_TOPIC,
            LOCKED_BODY,
        ] {
            assert!(!raw_mcp.contains(leak));
        }
    }

    #[test]
    fn target_merges_existing_mcp_json_without_breaking_other_servers() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let target = directory.path().join("project");
        fs::create_dir(&target).unwrap();
        fs::write(
            target.join(MCP_FILE_NAME),
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "other": { "command": "other-server", "args": ["--flag"] },
                    "agvt": { "command": "stale-agvt-path", "args": [] },
                },
                "topLevelSetting": "keep-me",
            }))
            .unwrap(),
        )
        .unwrap();

        run_wire_audited(
            &WireCliOptions {
                target: Some(target.clone()),
                print: false,
            },
            &dossier_path,
            &charter_path,
            &directory.path().join("audit.jsonl"),
        )
        .unwrap();

        let merged: Value =
            serde_json::from_str(&fs::read_to_string(target.join(MCP_FILE_NAME)).unwrap()).unwrap();
        // Other servers and unrelated top-level keys survive untouched.
        assert_eq!(merged["mcpServers"]["other"]["command"], "other-server");
        assert_eq!(
            merged["mcpServers"]["other"]["args"],
            serde_json::json!(["--flag"])
        );
        assert_eq!(merged["topLevelSetting"], "keep-me");
        // A stale agvt entry is replaced with the canonical registration.
        assert_eq!(merged["mcpServers"]["agvt"]["command"], "agvt");
        assert_eq!(
            merged["mcpServers"]["agvt"]["args"],
            serde_json::json!(["mcp"])
        );
    }

    #[test]
    fn invalid_existing_mcp_json_errors_without_rewriting_anything() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let target = directory.path().join("project");
        fs::create_dir(&target).unwrap();
        let corrupt = "{ this is not json";
        fs::write(target.join(MCP_FILE_NAME), corrupt).unwrap();

        let error = run_wire_audited(
            &WireCliOptions {
                target: Some(target.clone()),
                print: false,
            },
            &dossier_path,
            &charter_path,
            &directory.path().join("audit.jsonl"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("not valid JSON"));
        assert_eq!(
            fs::read_to_string(target.join(MCP_FILE_NAME)).unwrap(),
            corrupt
        );
        assert!(!target.join(FRAGMENT_FILE_NAME).exists());
    }

    #[test]
    fn non_object_mcp_servers_is_refused() {
        assert!(merged_mcp_config(Some("{\"mcpServers\": []}")).is_err());
        assert!(merged_mcp_config(Some("[]")).is_err());
    }

    #[test]
    fn print_produces_the_same_fragment_as_target() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let target = directory.path().join("project");
        fs::create_dir(&target).unwrap();

        let outcome = run_wire_audited(
            &WireCliOptions {
                target: Some(target.clone()),
                print: true,
            },
            &dossier_path,
            &charter_path,
            &directory.path().join("audit.jsonl"),
        )
        .unwrap();

        // --print emits `outcome.fragment` verbatim; it must be byte-identical
        // to the fragment written into the target directory.
        assert_eq!(
            fs::read_to_string(target.join(FRAGMENT_FILE_NAME)).unwrap(),
            outcome.fragment
        );
    }

    #[test]
    fn wire_runs_are_audited_without_content() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let target = directory.path().join("project");
        fs::create_dir(&target).unwrap();
        let audit_path = directory.path().join("audit.jsonl");

        run_wire_audited(
            &WireCliOptions {
                target: Some(target),
                print: true,
            },
            &dossier_path,
            &charter_path,
            &audit_path,
        )
        .unwrap();

        let entries = audit::list_entries(&audit_path).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.op == "wire"));
        assert!(entries.iter().all(|entry| entry.caller == "agvt"));
        let references: Vec<&str> = entries
            .iter()
            .map(|entry| entry.reference.as_str())
            .collect();
        assert!(references.contains(&"agvt://wire/bootstrap/target"));
        assert!(references.contains(&"agvt://wire/bootstrap/print"));

        // The audit log records mode only — no paths, topics, or bodies.
        let raw_audit = fs::read_to_string(&audit_path).unwrap();
        for leak in [OPEN_BODY, STANDARD_BODY, LOCKED_BODY, LOCKED_TOPIC] {
            assert!(!raw_audit.contains(leak));
        }
    }

    #[test]
    fn wire_without_flags_is_a_usage_error() {
        let error = parse_wire_cli_options(&[]).unwrap_err();
        assert!(error.to_string().contains("--target"));
        assert!(error.to_string().contains("--print"));
        assert!(parse_wire_cli_options(&["--bogus".to_owned()]).is_err());
    }

    #[test]
    fn missing_target_directory_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let (dossier_path, charter_path) = seed(directory.path());
        let error = run_wire_audited(
            &WireCliOptions {
                target: Some(directory.path().join("does-not-exist")),
                print: false,
            },
            &dossier_path,
            &charter_path,
            &directory.path().join("audit.jsonl"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }
}
