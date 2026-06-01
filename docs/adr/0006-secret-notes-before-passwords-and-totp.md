# Secret Notes are the next Vault item type

Status: Accepted

## Context

The Secure Vault is being expanded from field-bound autofill values toward explicit 1Password-like Vault items. API Tokens are the first copy-only item type.

Passwords and TOTP Secrets are valuable future item types, but they need more product and security design before implementation. Passwords raise questions around generation, save prompts, phishing-resistant fill rules, breach checks, and username association. TOTP Secrets raise questions around QR parsing, generated code display, clock drift, export/import, and avoiding confusion with one-time verification codes.

## Decision

Implement Secret Notes as the next Vault item type before passwords or TOTP Secrets.

A Secret Note is manually created, copy-only, and stored as a client-encrypted Vault Entry value. It is never learned from page fields and is never autofilled automatically. It can cover arbitrary sensitive text while leaving specialized behavior for passwords and TOTP Secrets to later ADRs.

## Why

Secret Notes reuse the same explicit-item boundary as API Tokens and avoid expanding the page-classification surface. This gives the product a broader useful Vault surface with lower security risk than automatic password or TOTP handling.

## Consequences

The UI can share most of the API Token item patterns: label, encrypted note body, optional service URL/account context, copy, and delete. Labels remain plaintext list metadata and must not contain secrets.

Password and TOTP work remains intentionally deferred until the product has a more explicit unlock/fill model and clearer user-facing distinctions between reusable secrets and one-time challenge values.

## Verification Expectations

- Secret Note body and optional details are encrypted as Vault Entry values.
- Secret Notes do not appear in autofill candidate collection.
- Secret Note labels are treated as non-secret display metadata.
- Adding Secret Notes does not weaken existing blocks for password, token, OTP, or verification-code form fields.
