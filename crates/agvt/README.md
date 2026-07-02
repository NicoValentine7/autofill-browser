# agvt

**The secrets manager built for AI agents — humans welcome too.**

`agvt` (Agent Vault) is a local-first CLI that lets AI agents *use* your secrets and context without ever *seeing* them. Instead of pasting API keys into prompts or `.env` files, agents work with opaque `agvt://` references; the real values only ever exist inside the environment of a child process you explicitly launch. Every access is audit-logged.

It is the foundation of **Agent Home**: inject your "trained self" — credentials, personal/company context, and autonomy rules — into any agent environment, local or cloud, through one CLI and one MCP server.

## Why agent-first?

Password managers are built for humans clicking browser extensions. Agents need something different:

- **Reference, not value.** Agents pass around `agvt://global/openai/api-key`, never `sk-...`. A leaked transcript leaks nothing.
- **Injection, not display.** `agvt run` resolves references directly into a child process environment. Secrets never touch stdout, shell history, or the agent's context window.
- **Machine-readable boundaries.** The charter tells an agent what it may do autonomously (`auto` / `branch-auto` / `confirm` / `deny`) before it acts.
- **Audit by default.** Every vault operation, MCP tool call, and locked-context read is appended to a tamper-evident local log.

## Quick Start

```sh
# Install (from source; crates.io release pending)
cargo install --path crates/agvt

# 1. Store your vault passphrase in the macOS Keychain
agvt keychain set

# 2. Save a secret (value is read from the environment — never typed into a prompt)
agvt add openai --from-env OPENAI_API_KEY

# 3. Run anything with the secret injected; stdout can be redacted
agvt run openai -- python my_agent.py

# 4. Expose vault, dossier, and charter to agents over MCP (stdio)
agvt mcp

# 5. Wire a project: register the MCP server in .mcp.json and
#    generate an agent bootstrap fragment (.agent-home.md)
agvt wire --target ~/projects/my-repo
```

Cloud environment without a filesystem to wire? `agvt wire --print` emits the same bootstrap fragment for copy-paste.

## The three layers

Agent Home is three layers behind one CLI ([ADR 0013](../../docs/adr/0013-agent-home-three-layers.md)):

| Layer | What it holds | Command | Storage |
|---|---|---|---|
| **Vault** | Credentials: API tokens, SSH keys, TOTP seeds, key files (`.p8`/`.p12`) | `agvt add` / `read` / `run` / `totp` | Encrypted (`ring`), global + per-repo hybrid |
| **Dossier** | Structured personal/company context: preferences, projects, bookkeeping facts | `agvt dossier add` / `search` / `show` | JSON with per-entry sensitivity tiers |
| **Charter** | Autonomy rules: which capability may run at which autonomy level in which scope | `agvt charter add` / `check` | Plaintext JSON — rules are auditable, not secret |

### Sensitivity tiers

Every dossier entry carries a tier ([ADR 0014](../../docs/adr/0014-sensitivity-tiers.md)):

- **`open`** — shareable with any agent, zero friction (company challenges, device models, preferences)
- **`standard`** — flows to local, trusted environments by default (client names, revenue scale)
- **`locked`** — encrypted like vault secrets; agents get an `agvt://` reference, never the body

## Security model

- **Values are never displayed.** `agvt ls`, `dossier ls`, audit entries, and MCP responses contain metadata and references only. `agvt run --redact-output` masks secrets that a child process echoes.
- **`agvt://` references are the only currency.** MCP tools (`dossier_search`, `dossier_read`, `charter_check`, `vault_ls`, `secret_handoff`) return references plus "consume via `agvt run`" instructions for anything sensitive. There is no unlock-and-return path ([ADR 0011](../../docs/adr/0011-agvt-is-agent-facing.md)).
- **Append-only audit.** Vault operations, charter writes, locked dossier reads, and every MCP tool call are recorded (operation, reference, timestamp, caller — never values). Inspect with `agvt audit ls`.
- **Local-first, zero-knowledge sync planned.** Data lives on your machine. The sync design keeps servers unable to decrypt anything ([ADR 0002](../../docs/adr/0002-zero-knowledge-secure-vault.md), [ADR 0003](../../docs/adr/0003-vault-key-recovery-uses-passphrase-wrapping.md)).

Found a vulnerability? See [SECURITY.md](../../SECURITY.md).

## Platform notes

macOS is the primary target (Keychain integration for the vault passphrase). On other platforms set `AGVT_PASSPHRASE`, or disable Keychain lookup with `AGVT_KEYCHAIN=0`.

## Design decisions

The architecture is documented as ADRs in [`docs/adr/`](../../docs/adr/), notably:

- [0002 — Zero-knowledge secure vault](../../docs/adr/0002-zero-knowledge-secure-vault.md)
- [0008 — Rust `agvt` secret-reference CLI](../../docs/adr/0008-rust-agvt-secret-reference-cli.md)
- [0010 — Hybrid global and repo vaults](../../docs/adr/0010-agvt-hybrid-global-and-repo-vaults.md)
- [0011 — agvt is agent-facing](../../docs/adr/0011-agvt-is-agent-facing.md)
- [0013 — Agent Home three layers](../../docs/adr/0013-agent-home-three-layers.md)
- [0014 — Sensitivity tiers](../../docs/adr/0014-sensitivity-tiers.md)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
