# Agent Vault access for development tools

Status: Accepted

## Context

The Chrome extension Secure Vault can now store explicit API Token items, but that popup-centered flow is not enough for Codex or Claude Code development workflows. Those agents operate through local terminal commands and need a controlled way to retrieve a token or inject it into a subprocess without scraping Chrome extension storage or relying on clipboard history.

Chrome extension storage also has a different unlock boundary. The Secure Vault Key lives in `chrome.storage.session`, while a terminal process does not naturally share that context.

## Decision

Add a separate local Agent Vault operated by `pnpm agent-vault`. The default file is `.local/agent-vault.json`, which is ignored by git. API Token payloads are encrypted with PBKDF2-SHA256 derived from `AUTOFILL_AGENT_VAULT_PASSPHRASE` and AES-GCM. The plaintext token, service URL, account name, and notes remain inside the encrypted payload. The item name and label are plaintext metadata for selection and listing.

The CLI supports:

- `put <name>` with `--value-stdin` or `--value-env` for saving API Tokens without putting token values in command arguments.
- `read <name>` for explicit token handoff to stdout.
- `run --env ENV_NAME=item -- <command>` for scoped subprocess environment injection.
- `list` and `delete` for management.

`run` removes `AUTOFILL_AGENT_VAULT_PASSPHRASE` from the child process environment and injects only the requested token variables.

Do not read Chrome extension storage directly from the CLI. A future bridge may connect the Chrome Secure Vault and Agent Vault, but that requires a separate accepted design for user unlock, authorization prompts, audit logging, and native messaging or broker ownership.

## Why

This makes the development-agent use case practical without weakening the existing browser autofill boundary. Codex and Claude Code can run commands with required tokens, while the repository avoids plaintext `.env` files, shell-history token arguments, and clipboard-only workflows.

## Consequences

Users must manage the Agent Vault passphrase outside git. A command that receives injected environment variables can still print or misuse them, so `run` is a scoped handoff rather than a sandbox. The local file is machine/repo-local and is not yet synchronized with the Chrome Secure Vault.

Keeping Agent Vault separate avoids pretending that a terminal process has the same trust boundary as an unlocked extension popup. It also leaves room for a future broker that can add explicit approvals and better audit trails.

## Verification Expectations

- `.local/agent-vault.json` is ignored by git and written with `0600` permissions.
- Saving an API Token does not write the token, service URL, account name, or notes in plaintext.
- Listing items exposes only non-secret metadata.
- Reading with the wrong passphrase fails.
- `run --env` injects requested token values into the child process and does not pass `AUTOFILL_AGENT_VAULT_PASSPHRASE` onward.
- The CLI can save, read, list, inject, and delete a dummy API Token through an automated verifier.
