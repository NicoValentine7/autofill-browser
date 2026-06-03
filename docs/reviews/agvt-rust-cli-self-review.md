# agvt Rust CLI self review

Date: 2026-06-02

## Scope

Reviewed the Rust `agvt` implementation for the Agent Vault development-token workflow:

- 1Password-like secret references: `agvt://vault/item/field`
- Explicit vault references after ADR 0010: `agvt://global/item/field` or `agvt://repo/item/field`
- `add`, `read`, `run`, `inject`, `totp`, `keychain`, `cloudflare create-token`, `ls`, `delete`, and `presets`
- API token, TOTP, SSH key, login, custom secret item kinds
- macOS Keychain passphrase lookup
- Chrome native messaging bridge for explicit popup-to-Agent-Vault saves
- Existing `.local/agent-vault.json` encrypted file compatibility

## UX Review

- The common Cloudflare flow is short: `agvt add cloudflare` and `agvt run cloudflare -- <command>`.
- 1Password-like references can be used directly in env values: `CLOUDFLARE_API_TOKEN=agvt://global/cloudflare/token agvt run -- <command>`.
- `inject` supports template replacement for `.env.template` style files.
- `pnpm agvt ...` remains available for repo-local use, while `pnpm install:agvt` provides the direct `agvt` command.
- `agvt keychain set` removes the need to export `AGVT_PASSPHRASE` in each shell session on macOS.
- The Cloudflare preset now injects `CLOUDFLARE_ACCOUNT_ID` when the encrypted `accountId` field exists.
- `agvt cloudflare create-token` stores the returned token instead of printing it.

## Security Review

- Tokens are read from preset env vars, stdin, or named env vars; they are not accepted as positional token arguments.
- Token payload fields stay encrypted with PBKDF2-SHA256 and AES-GCM.
- `run` removes `AGVT_PASSPHRASE` and `AUTOFILL_AGENT_VAULT_PASSPHRASE` from the child process environment.
- `run --clean-env` reduces inherited environment leakage, and `run --redact-output` redacts exact injected secret values from captured stdout/stderr.
- `run --sandbox no-network` uses macOS `sandbox-exec` as a best-effort network deny mode.
- The native host passes token values to `agvt add --from-stdin` instead of command arguments.
- Tests assert encrypted-at-rest behavior and child-process passphrase removal.
- Remaining risk: a child command that receives an injected token can still misuse it unless the user chooses a constrained command and safety flags. Redaction is exact-value best effort, not a proof against transformed output.

## Compatibility Review

- The Rust CLI keeps the previous Agent Vault file schema.
- The default `dev` vault maps to the existing item key for item-name compatibility, but short secret references are disabled after ADR 0010.
- Non-default vaults use `vault:item` storage keys.
- The older Node compatibility CLI continues to support `api-token` items; Rust-only non-token kinds are outside that compatibility surface.

## Verification

- `cargo fmt --manifest-path crates/agvt/Cargo.toml -- --check`
- `cargo clippy --manifest-path crates/agvt/Cargo.toml -- -D warnings`
- `pnpm test:agvt`
- `pnpm typecheck:extension`
- `pnpm verify:agent-vault`
- `pnpm test:extension -- agent-vault-lib.test.mjs`

## Follow-Ups

- Add a richer Cloudflare policy builder once permission group discovery UX is settled.
- Add bulk import/export for existing Chrome Secure Vault API token entries if explicit one-by-one bridge saves are too slow.
