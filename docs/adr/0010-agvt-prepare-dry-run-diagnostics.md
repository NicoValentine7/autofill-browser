# agvt prepare is a dry-run secret readiness diagnostic

Status: Accepted

## Context

`agvt import-env` can move existing environment values into Agent Vault, and `agvt cloudflare create-token` can create a Cloudflare token when an explicit factory token and policy file are provided. Daily Codex and Claude Code work still needs a safer first step: detect what a repo needs without exposing values or mutating local state.

## Decision

Add `agvt prepare` as a dry-run diagnostic command. It reads `agvt.toml` when present, otherwise uses conservative repo and provider hints such as Wrangler config files and known preset env names. The command reports each required field as `present`, `importable`, `missing`, or `unchecked`.

`prepare` does not save secrets, rewrite env files, delete plaintext values, create provider tokens, or call Cloudflare APIs. Cloudflare token creation remains only in the explicit `agvt cloudflare create-token` flow from ADR 0008.

## Why

This gives development agents a safe, repeatable first move: inspect readiness, show the smallest next command, and avoid asking the user to paste secret values into chat or logs.

## Consequences

- `agvt.toml` becomes the repo-local manifest for secret readiness checks.
- `prepare` may read env files to identify importable env names, but it never prints their values.
- Locked Vaults are reported as `unchecked` unless a matching env value is importable.
- Agents may run `prepare --dry-run` autonomously, but human involvement is still required when a secret value must be supplied or a Cloudflare token should be created.

## Verification Expectations

- Tests cover manifest-based diagnostics, JSON output, Vault-present fields, and redaction by absence.
- README documents the manifest shape and the non-mutating boundary.
