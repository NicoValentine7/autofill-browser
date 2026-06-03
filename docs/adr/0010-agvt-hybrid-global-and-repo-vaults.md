# agvt uses hybrid global and repo-local vaults

Status: Accepted

## Context

Agent Vault started as a repo-local encrypted file at `.local/agent-vault.json`. That boundary is easy to reason about, but it is awkward for Codex and Claude Code workflows that reuse the same provider tokens across multiple repositories.

A fully global vault would feel closer to 1Password, but short references such as `agvt://cloudflare/token` become ambiguous once a repository can also have its own Cloudflare token. The operator is usually an agent, so slightly longer explicit references are acceptable if they reduce accidental cross-repo token use.

## Decision

Use a hybrid model:

- Global/shared items live in the global vault file: `~/.local/share/agvt/agent-vault.json`, overridable with `AGVT_GLOBAL_PATH`.
- Repo-specific items live in the repo-local vault file: `.local/agent-vault.json`, overridable with `AGVT_PATH`.
- `agvt://global/<item>/<field>` resolves to the global vault file unless `--vault-path` is explicitly supplied for single-file compatibility.
- Any other explicit vault name, such as `agvt://repo/<item>/<field>`, resolves to the repo-local vault file.
- Short secret references such as `agvt://cloudflare/token` are invalid. Callers must use `agvt://<vault>/<item>/<field>`.

The `--vault-path` option remains a compatibility and test escape hatch. When supplied, all references are resolved against that one file.

## Why

This keeps the 1Password-like global sharing benefit while preserving a clear repo-local boundary for tokens whose meaning or blast radius is repository-specific. Requiring the vault segment makes the target visible in chat transcripts, shell commands, templates, and agent-generated plans without exposing any secret value.

## Consequences

Existing commands that use item names, such as `agvt add cloudflare`, continue to work as repo-local compatibility flows. New templates and agent-authored commands should prefer explicit references such as `agvt://global/cloudflare/token` or `agvt://repo/github-ssh/private-key`.

macOS Keychain passphrases remain vault-path scoped. A global vault and a repo-local vault naturally use separate Keychain accounts unless `AGVT_KEYCHAIN_ACCOUNT` is explicitly set.

The Chrome native messaging bridge receives both a scope (`repo` or `global`) and an item name from the popup. Missing scope is treated as `repo` for compatibility, and the host calls `agvt` with an explicit `agvt://<scope>/<item>/token` reference.

## Verification Expectations

- `agvt://cloudflare/token` fails with a clear error.
- `agvt://global/cloudflare/token` can be saved and read from the global vault path.
- `--vault-path` still allows tests and compatibility callers to use a single explicit vault file.
- Secret values are never printed by import dry-runs, list output, or redacted inject previews.
