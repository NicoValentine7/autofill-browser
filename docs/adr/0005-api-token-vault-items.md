# API tokens are explicit copy-only Vault items

Status: Accepted

## Context

Autofill Browser already has a Zero-Knowledge Secure Vault for reusable sensitive values. The first implementation is field-bound: entries are keyed by hostname and field signature, and secure fields are filled only from a popup-triggered manual run.

API tokens are different. A reusable provider token or API key is useful to store like a 1Password item, but token-looking web form fields are also common for CSRF, OAuth, one-time challenges, and anti-abuse flows. Automatically learning or filling fields just because they contain `token` would be unsafe.

## Decision

Add `api-token` as a Secure Vault entry kind for manually created Vault items. These entries use a synthetic manual vault hostname and are copy-only from the popup. They are not associated with page field signatures and are not eligible for automatic learning or autofill.

The encrypted Vault Entry value stores the API token payload, including token, service URL, account name, and notes. The entry label remains plaintext metadata for list display and must not contain the secret value.

Keep generic token-looking form fields blocked. A user may store an API Token only by explicitly creating an API Token Vault item.

## Why

This gives the product a small 1Password-like foothold without weakening the existing autofill safety boundary. It keeps reusable API tokens in the client-encrypted Secure Vault while preserving the rule that ambiguous token fields from pages are not learned.

## Consequences

API token labels should not contain the secret value, because labels are list metadata. The copied token may still enter the system clipboard by explicit user action, so copy is treated as a user-triggered handoff rather than automatic fill.

Future secret item types, such as passwords, SSH keys, recovery codes, and secret notes, should follow the same explicit-item pattern unless a separate ADR accepts a different boundary.

## Verification Expectations

- `api-token` entries decrypt only with the local Vault Key.
- The local stored Secure Vault state does not contain the API token plaintext, service URL, account name, or notes.
- `token` and `api_token` web form fields remain blocked from automatic learning and autofill.
- Sync payloads continue to reject `secureVaultKey` and contain only encrypted Vault Entry values.
