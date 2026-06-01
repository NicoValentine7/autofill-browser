# Rust agvt uses 1Password-style secret references

Status: Accepted

## Context

The first Agent Vault CLI proved the security boundary, but the UX still felt too heavy for daily Codex and Claude Code work. The target experience is closer to 1Password CLI: short command names, `run` as the main handoff, and secret references that can live in environment variables or templates without storing plaintext tokens in project files.

## Decision

Add a Rust CLI named `agvt`. It keeps the existing encrypted `.local/agent-vault.json` file format so the earlier Node CLI remains a compatibility path, but the intended interface moves to `agvt`.

`agvt` accepts secret references in this form:

- `agvt://dev/cloudflare/token`
- `agvt://cloudflare/token`

The short form defaults to the `dev` vault. Internally, `dev` items reuse the existing item key for compatibility, while non-default vaults are stored as `vault:item`.

The primary commands are:

- `agvt add cloudflare`
- `agvt read agvt://cloudflare/token`
- `agvt run cloudflare -- <command>`
- `CLOUDFLARE_API_TOKEN=agvt://cloudflare/token agvt run -- <command>`
- `agvt inject <template>`
- `agvt ls`
- `agvt delete <item-or-ref>`
- `agvt presets`

`agvt` supports `AGVT_PASSPHRASE` and `AGVT_PATH`, while still accepting the older `AUTOFILL_AGENT_VAULT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PATH`. `run` removes both passphrase environment variables from the child process.

## Why

This makes the common Cloudflare/GitHub flows short enough to be used from development sessions while still preserving the earlier encrypted local vault model. Secret references also let `.env` templates or shell environment variables point to a token without containing the token itself.

## Consequences

The Rust CLI depends on audited Rust crypto crates instead of hand-rolled cryptography. The command still performs a scoped handoff: any child process receiving the token can print or misuse it, so users should keep commands narrow.

The Chrome extension Secure Vault remains separate. Bridging Chrome Secure Vault and Agent Vault still needs a future broker design.

## Verification Expectations

- Rust unit and integration tests cover add, read, run preset injection, env reference resolution, inject, wrong passphrase, and encrypted-at-rest checks.
- `agvt run` removes `AGVT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PASSPHRASE` from the child process.
- Rust `agvt` can read and write the existing Agent Vault file format.
- README documents the shorter 1Password-like command flow.
