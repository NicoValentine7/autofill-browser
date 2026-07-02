# Dossier entries carry one of three sensitivity tiers

Status: Proposed

## Context

Agent Home's value is zero-friction context injection: the user wants agents
to know their company's challenges, device model numbers, accounting
practices, and preferences without ceremony. Applying Vault-grade
zero-knowledge discipline to every fact would reintroduce exactly the
friction the product exists to remove. Applying no discipline at all would
leak value-grade data (account numbers, contract terms) into transcripts,
cloud sessions, and generated files. Graduation must be a designed property.

## Decision

Every Dossier entry has exactly one tier:

- **`open`** — zero friction. For non-identifying context: company
  challenges and goals, product/device model numbers, tooling preferences,
  writing style. `open` entries are included in `agvt wire` bootstrap
  fragments and returned by MCP tools to any connected environment, local or
  cloud.

- **`standard`** — default-local. For business context that identifies
  parties or magnitudes: client names, revenue scale, tax-situation details,
  investment policy. `standard` entries are returned over MCP (the server
  runs on the user's machine), but are **never embedded in generated
  artifacts** — not in `agvt wire` fragments, not in files that may be
  committed or pasted into remote environments.

- **`locked`** — value-grade. For sensitive prose and identifiers: account
  numbers, contract terms, anything whose leak is an incident. Stored
  encrypted with the Vault passphrase mechanism. **Never returned raw** by
  MCP or CLI display flows; access yields an `agvt://` reference consumed via
  `agvt run` environment injection. Every read is audit-logged. Credentials
  themselves belong in the Vault, not in a `locked` Dossier entry.

The default tier for a new entry is `standard`: defaulting to `open` would
silently widen exposure, and defaulting to `locked` would tax the common
case. `agvt dossier add --tier open` is the explicit opt-in for freely
shareable context.

## Use-case mapping

The three driving use cases are expressible as follows:

1. **Delegating company tax work** — accounting policies and freee
   operational notes: `open`. Client names, revenue scale: `standard`.
   freee API token: Vault. Charter rows: `accounting/freee-entry = auto`
   (drafting bookkeeping entries), `accounting/filing = confirm`
   (submitting anything to authorities).

2. **Managing a brokerage account** — investment policy and rebalancing
   rules: `standard`. Account numbers: `locked`. Brokerage credentials:
   Vault. Charter rows: `brokerage/read = auto` (checking positions),
   `brokerage/trade = confirm` (placing orders).

3. **Accumulating company-specific knowledge** — product model numbers,
   internal pain points, preferred toolchains: `open`, so every agent
   session starts already knowing them.

## Why

Tiers let the friction budget be spent only where value-grade data lives.
"Not maximally locked down" becomes a reviewed, recorded design decision with
crisp boundaries per tier, instead of an accident of convenience. The rules
are mechanical (what may appear in MCP responses, what may appear in
generated files), so implementations can enforce them with tests rather than
judgment calls.

## Consequences

- `tier` is a mandatory schema field; migration tooling must assign a tier
  for every imported entry (defaulting to `standard` when unspecified).
- MCP and `agvt wire` implementations must enforce the exclusion rules with
  automated tests: `wire` output contains no `standard`/`locked` bodies; MCP
  responses contain no `locked` bodies or raw secret values.
- The audit log must distinguish `locked` reads from other reads.
- Tier changes (especially toward `open`) are Dossier writes and therefore
  audit-logged.
