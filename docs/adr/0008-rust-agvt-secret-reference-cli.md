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
- `agvt run cloudflare --clean-env --redact-output -- <command>`
- `CLOUDFLARE_API_TOKEN=agvt://cloudflare/token agvt run -- <command>`
- `agvt inject --redact-output <template>`
- `agvt keychain set`
- `agvt cloudflare create-token <item> --policy-file <file>`
- `agvt add <item> --kind totp|ssh-key|login|custom`
- `agvt totp <item>`
- `agvt ls`
- `agvt delete <item-or-ref>`
- `agvt presets`

`agvt` supports `AGVT_PASSPHRASE` and `AGVT_PATH`, while still accepting the older `AUTOFILL_AGENT_VAULT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PATH`. If the passphrase env vars are absent on macOS, `agvt` can read a vault-path-scoped passphrase from Keychain. `run` removes both passphrase environment variables from the child process.

Cloudflare remains explicit: token creation requires a token-create-capable factory token and a policy JSON file. `agvt` stores the returned token value immediately instead of printing it. The `cloudflare` preset treats `accountId` as a first-class encrypted field and injects `CLOUDFLARE_ACCOUNT_ID` when present.

Vault writes take a vault-file lock before load/modify/save so parallel `agvt add` or `agvt delete` processes do not overwrite each other's changes. `inject` still supports printing resolved values for template generation, but warns when it does so and supports `--redact-output` for safe previews.

## Why

This makes the common Cloudflare/GitHub flows short enough to be used from development sessions while still preserving the earlier encrypted local vault model. Secret references also let `.env` templates or shell environment variables point to a token without containing the token itself.

## Consequences

The Rust CLI depends on audited Rust crypto crates instead of hand-rolled cryptography. The command still performs a scoped handoff: any child process receiving the token can print or misuse it, so users should keep commands narrow. `run --clean-env`, `run --redact-output`, `inject --redact-output`, and macOS `--sandbox no-network` reduce accidental leakage but do not turn arbitrary child commands into a complete security boundary.

The encrypted file schema remains compatible for `api-token` items. Non-token kinds are readable by Rust `agvt`; the older Node compatibility CLI ignores those items.

## Verification Expectations

- Rust unit and integration tests cover add, read, run preset injection, env reference resolution, inject redaction/warnings, TOTP storage, wrong passphrase, output redaction, clean env, concurrent writes, Keychain missing-state behavior, and encrypted-at-rest checks.
- `agvt run` removes `AGVT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PASSPHRASE` from the child process.
- Rust `agvt` can read and write the existing Agent Vault file format.
- README documents the shorter 1Password-like command flow.
