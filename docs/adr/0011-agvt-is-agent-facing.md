# agvt is agent-facing instead of human-first

Status: Accepted

## Context

Agent Vault is primarily for Codex and Claude Code development sessions. The
operator is an agent that can run longer commands, inspect JSON output, and
follow repo instructions. Optimizing every command for direct human typing would
pull the design toward shorter but more ambiguous flows.

The important usability problem is not whether a person can comfortably operate
the CLI by hand. It is whether an agent can receive a safe instruction, discover
vault readiness without printing values, inject scoped secrets into a child
command, and report only non-secret metadata.

## Decision

Treat `agvt` as an agent-facing secure handoff tool, not a human-first password
manager CLI.

This means:

- Machine-readable and deterministic output is more important than short prose.
- Non-interactive diagnostics such as `agvt prepare`, `agvt keychain status`,
  `agvt ls --json`, and `agvt import-env --dry-run` are first-class flows.
- Longer explicit references such as `agvt://global/<item>/<field>` are
  acceptable when they reduce ambiguity or accidental cross-repo token use.
- Human interaction is acceptable for bootstrap or recovery only. Steady-state
  workflows should rely on Keychain, environment setup, repo instructions, and
  agent-readable readiness checks.
- Help text should teach safe agent workflows before optimizing for a person
  typing ad-hoc commands.

## Why

The security boundary depends on the agent reliably avoiding secret display and
choosing the correct vault. Agents can follow explicit, slightly longer commands
better than humans can, and explicitness makes chat transcripts, logs, and
review artifacts easier to audit without exposing values.

## Consequences

`agvt` can prioritize JSON, dry-runs, readiness checks, and redacted execution
over polished interactive prompts. Human-friendly aliases can still exist, but
they should not weaken vault selection, redaction, or bootstrap clarity.

If Keychain or passphrase state is missing, the preferred next step is an
agent-readable diagnostic that explains the missing capability without printing
secret material. A person may still need to approve or complete bootstrap, but
that is not the primary steady-state path.

## Verification Expectations

- Agent prompts can instruct `agvt` usage without including secret values.
- Readiness commands can report whether metadata, unlock, and run injection are
  available separately.
- Redacted `run`/`inject` flows remain the documented default for development
  agents.
