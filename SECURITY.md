# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately via GitHub Security Advisories**:

1. Go to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
2. Include reproduction steps, affected commands/paths, and impact assessment.
3. Do **not** open a public issue for security problems, and do not include real secret values in any report.

You can expect an initial response within 7 days. Coordinated disclosure is preferred; we will credit reporters in the advisory unless you ask otherwise.

## Supported scope

| Component | Supported |
|---|---|
| `crates/agvt` (CLI, MCP server) — latest release and `main` | Yes |
| Other workspace apps (`apps/*`, `packages/*`) | Best effort |
| Forks and modified builds | No |

## Handling of secret values (principles)

`agvt` is designed so that secret values and locked-tier content never appear in stdout, MCP responses, audit logs, or generated fragments. Anything that violates these invariants is a security bug, even without an attacker:

- A command or MCP tool prints a raw secret value or a locked dossier body.
- The audit log (`audit.jsonl`) records a secret value.
- `agvt wire` output contains secret values or standard/locked dossier content.
- Encrypted-at-rest data (vault items, locked dossier bodies) is readable without the passphrase.

When reporting, demonstrating one of these invariant violations with dummy data is sufficient — never use production credentials.
