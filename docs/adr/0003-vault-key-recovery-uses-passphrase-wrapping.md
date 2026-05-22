# Vault Key recovery uses passphrase wrapping

Autofill Browser recovers a Vault Key on another device by storing a Vault Recovery Package in D1: the client wraps the Vault Key with a high-entropy client-generated Recovery Phrase using PBKDF2-SHA256 at 600k iterations and AES-GCM, then syncs only that encrypted package. The AES-GCM operation authenticates the recovery package metadata as AAD, including schema, algorithm, KDF params, salt, IV, keyId, and createdAt. Restore rejects tampered metadata and requires the unwrapped Vault Key keyId to match the package keyId.

This preserves the Zero-Knowledge Vault boundary because the Worker can authenticate and move the package, but it never receives the Recovery Phrase or plaintext Vault Key. The Worker rejects inbound sync payloads containing `secureVaultKey`; an admin scrub endpoint exists to remove legacy `secureVaultKey` material from current/history sync rows.
