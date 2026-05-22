import { describe, expect, it } from "vitest"

import {
  createSecureVaultRecoveryPackage,
  generateSecureVaultRecoveryPhrase,
  recoverSecureVaultKey,
  MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH,
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
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, recoveryPhrase)

    expect(recoveryPackage).toMatchObject({
      schemaVersion: 1,
      keyId: "vault-key-1",
      algorithm: "PBKDF2-SHA256/AES-GCM"
    })
    expect(JSON.stringify(recoveryPackage)).not.toContain(vaultKey.rawKey)

    const recoveredKey = await recoverSecureVaultKey(recoveryPackage!, recoveryPhrase)
    const wrongPassphraseKey = await recoverSecureVaultKey(recoveryPackage!, "wrong horse battery staple")

    expect(recoveredKey).toEqual(vaultKey)
    expect(wrongPassphraseKey).toBeNull()
  })

  it("rejects short recovery phrases", async () => {
    expect(await createSecureVaultRecoveryPackage(vaultKey, "short")).toBeNull()
  })

  it("rejects tampered recovery package metadata", async () => {
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, recoveryPhrase)

    expect(await recoverSecureVaultKey({ ...recoveryPackage!, keyId: "other-key" }, recoveryPhrase)).toBeNull()
    expect(await recoverSecureVaultKey({ ...recoveryPackage!, iterations: 1 }, recoveryPhrase)).toBeNull()
  })

  it("generates a high-entropy recovery phrase", () => {
    const recoveryPhrase = generateSecureVaultRecoveryPhrase()

    expect(recoveryPhrase).toHaveLength(43)
    expect(recoveryPhrase.length).toBeGreaterThanOrEqual(MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH)
    expect(recoveryPhrase).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})
