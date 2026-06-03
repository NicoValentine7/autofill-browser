# Agent Vault bridge uses Chrome native messaging

Status: Accepted

## Context

The Chrome extension Secure Vault and the local Agent Vault CLI originally stored API tokens in separate vaults. The extension cannot safely read or write `.local/agent-vault.json` directly from browser code, and scraping Chrome extension storage from the CLI would break the Secure Vault key boundary.

## Decision

Use a Chrome native messaging host named `io.nico.agvt` as the bridge. The fixed local extension ID is allowed to send explicit API token save requests to `scripts/agvt-native-host.mjs`. The host calls the installed `agvt` binary and passes token values through stdin, not command arguments.

The popup keeps its existing Secure Vault write path. If the user fills the `Agent Vault item` field, the popup also sends the selected Agent Vault scope (`repo` or `global`) and token metadata to the native host so the same item is saved into Agent Vault. If the native host is missing or `agvt` cannot unlock the vault, the Secure Vault save still succeeds and the popup reports the bridge failure.

## Why

Native messaging preserves the browser security model while giving the local CLI a controlled broker. It avoids granting the extension arbitrary filesystem access and avoids putting the Agent Vault passphrase into extension storage. With macOS Keychain enabled for `agvt`, the host can unlock the local vault without the popup handling the passphrase.

## Consequences

- Installing the bridge requires `pnpm install:agvt-native-host`, which writes a Chrome NativeMessagingHosts manifest under the user's home directory.
- The bridge only syncs explicit popup saves with an `Agent Vault item` value; it does not bulk-export existing Secure Vault entries.
- The bridge defaults missing scope to `repo` for older popup payloads and passes explicit `agvt://<scope>/<item>/token` references to `agvt`.
- The native host receives plaintext token values for the save operation, so it must remain local, repo-owned, and small.
- Web Store extension IDs need their own native messaging manifest allowlist if the extension is distributed there.

## Verification Expectations

- Extension typecheck covers the native messaging helper.
- The native host never places token values in command-line arguments.
- README documents the install order: install `agvt`, install the native host, rebuild or reload the extension.
