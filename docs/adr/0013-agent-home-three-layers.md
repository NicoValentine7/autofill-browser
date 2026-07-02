# Agent Home is three layers: Vault, Dossier, and Charter

Status: Proposed

## Context

agvt started as an agent-facing secret handoff CLI (ADR 0008, 0010, 0011). The
product direction is now larger: **Agent Home** injects a "trained self" into
any agent environment in one step. The pain it solves is that agents start
cold — every user hand-crafts CLAUDE.md files, memory notes, and permission
conventions per environment, and rebuilding that context in a cloud session or
a new machine burns hours. Secrets are only one of three things an agent needs
to know about its principal; the other two are context and permissions.

The primary user deliberately trades strict lock-down for productivity: they
want to hand agents company-specific knowledge (challenges, device model
numbers, accounting practices) freely, while keeping value-grade data (keys,
account numbers) under the existing zero-knowledge discipline. Safety must be
a designed product feature (tiers, references), not a reason to refuse.

## Decision

Agent Home consists of three layers, all owned by the `agvt` CLI:

1. **Vault** — the existing encrypted secret store. Unchanged by this ADR.
   Values are consumed via `agvt://<vault>/<item>/<field>` references and
   `agvt run` environment injection, never displayed (ADR 0011).

2. **Dossier** — structured personal/company context entries.
   - Schema per entry: `id`, `topic`, `body`, `tags[]`, `tier`
     (`open | standard | locked`, see ADR 0014), `updatedAt`.
   - Storage: `~/.local/share/agvt/dossier.json`.
   - `locked` bodies are encrypted with the same passphrase mechanism as the
     Vault; `open` and `standard` bodies are plaintext JSON.
   - CLI: `agvt dossier add|ls|show|edit|rm|search`.

3. **Charter** — machine-readable autonomy and permission rules.
   - Schema per rule: `capability`, `scope`, `autonomy`
     (`auto | branch-auto | confirm | deny`), `conditions`, `notes`.
   - Storage: `~/.local/share/agvt/charter.json`, plaintext — permission
     rules are not secrets and must stay auditable and diffable.
   - CLI: `agvt charter add|ls|show|check`. `check <capability> <scope>`
     returns a machine-readable verdict. An undefined capability always
     resolves to `confirm`.
   - This generalizes the per-repository autonomy ledger previously kept in
     the user's orchestration repo (`repositories.json` `autonomy` field).

Delivery surfaces:

- **`agvt mcp`** — a stdio MCP server exposing `dossier_search`,
  `dossier_read` (tier-filtered), `charter_check`, `vault_ls` (item names
  only), and `secret_handoff`. `secret_handoff` and any access to `locked`
  material return an `agvt://` reference plus consumption instructions —
  **raw secret values and locked bodies never appear in MCP responses**.
  Every MCP access is audit-logged.
- **`agvt wire`** — generates environment bootstrap material: an `.mcp.json`
  server registration and a CLAUDE.md/AGENTS.md fragment containing the
  `open`-tier summary, MCP connection instructions, and the Charter digest.
  `agvt wire` output must never contain secret values or `standard`/`locked`
  bodies.

Naming boundary: `agvt wire` is deliberately distinct from the existing
`agvt inject`, which resolves secret references into rendered output and can
emit secret values by design. The two commands must never be merged or
aliased; help text must state the difference.

Charter tamper threat model: an agent can edit the Charter through the same
CLI it is governed by, so self-escalation is possible. Phase 1 mitigates by
**detection**: every Charter write is recorded in the append-only audit log.
Write-gating behind explicit user approval is deferred to Phase 2. Consumers
must fail toward `confirm` whenever the Charter is missing or unreadable.

## Why

Context, credentials, and policy aggregation is currently hand-rolled per
environment and per user. Unifying the three layers under one CLI makes
injection a single command while each layer keeps its own security posture:
Vault stays zero-knowledge (ADR 0002), Dossier spends encryption only where
the tier demands it (ADR 0014), and Charter stays transparent because its
value is auditability. Keeping raw values out of MCP responses preserves the
boundary that made agvt safe for agents in the first place (ADR 0011).

## Consequences

- `dossier.json` and `charter.json` become new user-data files: the sync
  design (ADR 0002/0003 implementation) must include them in encrypted
  snapshots, with a `schemaVersion` for forward compatibility.
- The MCP server becomes the primary agent-facing surface; its tier
  filtering and no-raw-value rules require dedicated tests.
- The audit log becomes load-bearing for Charter trust; audit must land
  before or with Dossier/Charter write paths.
- The existing `agvt inject` remains unchanged but is now name-frozen:
  future bootstrap features go to `agvt wire`.
