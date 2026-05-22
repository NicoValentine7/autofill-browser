import { describe, expect, it } from "vitest"

import {
  createEmptySecureVault,
  createSecureVaultRecoveryPackage,
  decryptSecureVaultValues,
  ensureSecureVaultKeyCheck,
  generateSecureVaultRecoveryPhrase,
  recoverSecureVaultKey,
  MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH,
  upsertSecureVaultValue,
  validateSecureVaultKey,
  type SecureVaultKey
} from "../lib/secure-vault"

const vaultKey: SecureVaultKey = {
  schemaVersion: 1,
  keyId: "vault-key-1",
  algorithm: "AES-GCM",
  rawKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  createdAt: "2026-05-22T00:00:00.000Z"
}

describe("secure-vault recovery", () => {
  it("wraps and restores a vault key without exposing the raw key", async () => {
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()
    const vault = createEmptySecureVault()
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, recoveryPhrase, vault.vaultId)

    expect(recoveryPackage).toMatchObject({
      schemaVersion: 1,
      keyId: "vault-key-1",
      vaultId: vault.vaultId,
      algorithm: "PBKDF2-SHA256/AES-GCM"
    })
    expect(JSON.stringify(recoveryPackage)).not.toContain(vaultKey.rawKey)

    const recoveredKey = await recoverSecureVaultKey(recoveryPackage!, recoveryPhrase, vault)
    const wrongPassphraseKey = await recoverSecureVaultKey(recoveryPackage!, "wrong horse battery staple")

    expect(recoveredKey).toEqual(vaultKey)
    expect(wrongPassphraseKey).toBeNull()
  })

  it("rejects short recovery phrases", async () => {
    expect(await createSecureVaultRecoveryPackage(vaultKey, "short")).toBeNull()
  })

  it("rejects tampered recovery package metadata", async () => {
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()
    const vault = createEmptySecureVault()
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, recoveryPhrase, vault.vaultId)

    expect(await recoverSecureVaultKey({ ...recoveryPackage!, keyId: "other-key" }, recoveryPhrase)).toBeNull()
    expect(await recoverSecureVaultKey({ ...recoveryPackage!, iterations: 1 }, recoveryPhrase)).toBeNull()
    expect(await recoverSecureVaultKey({ ...recoveryPackage!, vaultId: "other-vault" }, recoveryPhrase, vault)).toBeNull()
  })

  it("creates a vault canary and refuses keys that do not match it", async () => {
    const vault = await upsertSecureVaultValue(createEmptySecureVault(), vaultKey, {
      hostname: "example.com",
      fieldSignature: "input|card",
      kind: "payment-card",
      value: "4111111111111111"
    })
    const wrongKey: SecureVaultKey = {
      ...vaultKey,
      keyId: "vault-key-2",
      rawKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    }

    expect(vault.activeKeyId).toBe("vault-key-1")
    expect(vault.keyCheck?.keyId).toBe("vault-key-1")
    expect(await validateSecureVaultKey(vault, vaultKey)).toBe(true)
    expect(await validateSecureVaultKey(vault, wrongKey)).toBe(false)
    expect(Object.values(await decryptSecureVaultValues(vault, vaultKey))).toEqual(["4111111111111111"])
    expect(await decryptSecureVaultValues(vault, wrongKey)).toEqual({})
  })

  it("rejects recovery packages for a different vault", async () => {
    const vault = await ensureSecureVaultKeyCheck(createEmptySecureVault(), vaultKey)
    const otherVault = createEmptySecureVault()
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, recoveryPhrase, otherVault.vaultId)

    expect(await recoverSecureVaultKey(recoveryPackage!, recoveryPhrase, vault)).toBeNull()
  })

  it("validates recovery against the current vault canary before saving a key", async () => {
    const vault = await ensureSecureVaultKeyCheck(createEmptySecureVault(), vaultKey)
    const wrongKey: SecureVaultKey = {
      ...vaultKey,
      keyId: "vault-key-2",
      rawKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    }
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()
    const recoveryPackage = await createSecureVaultRecoveryPackage(wrongKey, recoveryPhrase, vault.vaultId)

    expect(await recoverSecureVaultKey(recoveryPackage!, recoveryPhrase, vault)).toBeNull()
  })

  it("generates a high-entropy recovery phrase", () => {
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()

    expect(recoveryPhrase).toHaveLength(43)
    expect(recoveryPhrase.length).toBeGreaterThanOrEqual(MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH)
    expect(recoveryPhrase).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})
