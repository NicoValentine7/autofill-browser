# agvt Rust CLI self review

Date: 2026-06-01

## Scope

Reviewed the Rust `agvt` implementation for the Agent Vault development-token workflow:

- 1Password-like secret references: `agvt://vault/item/field`
- Default `dev` vault short form: `agvt://item/field`
- `add`, `read`, `run`, `inject`, `ls`, `delete`, and `presets`
- Existing `.local/agent-vault.json` encrypted file compatibility

## UX Review

- The common Cloudflare flow is short: `agvt add cloudflare` and `agvt run cloudflare -- <command>`.
- 1Password-like references can be used directly in env values: `CLOUDFLARE_API_TOKEN=agvt://cloudflare/token agvt run -- <command>`.
- `inject` supports template replacement for `.env.template` style files.
- `pnpm agvt ...` remains available for repo-local use, while `cargo install --path crates/agvt` provides the direct `agvt` command.

## Security Review

- Tokens are read from preset env vars, stdin, or named env vars; they are not accepted as positional token arguments.
- Token payload fields stay encrypted with PBKDF2-SHA256 and AES-GCM.
- `run` removes `AGVT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PASSPHRASE` from the child process environment.
- Tests assert encrypted-at-rest behavior and child-process passphrase removal.
- Remaining risk: a child command that receives an injected token can still print or exfiltrate it. This is an intentional scoped handoff, not a sandbox.

## Compatibility Review

- The Rust CLI keeps the previous Agent Vault file schema.
- The default `dev` vault maps to the existing item key, so earlier `cloudflare` and `github` items remain readable as `agvt://cloudflare/token`.
- Non-default vaults use `vault:item` storage keys.

## Verification

- `cargo fmt --manifest-path crates/agvt/Cargo.toml -- --check`
- `cargo clippy --manifest-path crates/agvt/Cargo.toml -- -D warnings`
- `pnpm test:agvt`
- `pnpm verify:agent-vault`
- `pnpm test:extension -- agent-vault-lib.test.mjs`

## Follow-Ups

- macOS Keychain support can remove the need to export `AGVT_PASSPHRASE` each session.
- A future broker can connect Chrome Secure Vault and Agent Vault without scraping extension storage.
