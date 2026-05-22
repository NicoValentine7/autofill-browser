import { DEFAULT_AUTOFILL_SETTINGS, createEmptyProfile } from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import { buildSyncedSnapshot, buildWorkerUrl } from "../lib/account-sync"
import { createEmptySecureVault } from "../lib/secure-vault"
import type { StorageSnapshot } from "../lib/storage"

const snapshot: StorageSnapshot = {
  profile: {
    ...createEmptyProfile(),
    fullName: "山田 太郎",
    email: "taro@example.com"
  },
  settings: DEFAULT_AUTOFILL_SETTINGS,
  domainPolicies: {
    "example.com": "whitelist"
  },
  fieldMemory: {},
  secureVault: createEmptySecureVault(),
  secureVaultRecovery: {
    schemaVersion: 1,
    keyId: "vault-key-1",
    algorithm: "PBKDF2-SHA256/AES-GCM",
    iterations: 250000,
    salt: "salt",
    iv: "iv",
    ciphertext: "wrapped-key",
    createdAt: "2026-05-22T00:00:00.000Z"
  },
  secureVaultValues: {},
  eventLog: [],
  accountSync: {
    deviceId: "device-a",
    lastRevision: 3
  }
}

describe("account-sync", () => {
  it("derives worker API URLs from the fixed cloud worker", () => {
    expect(buildWorkerUrl("/me")).toBe("https://autofill-browser-log-worker.y-elucidator.workers.dev/me")
    expect(buildWorkerUrl("/me/settings")).toBe(
      "https://autofill-browser-log-worker.y-elucidator.workers.dev/me/settings"
    )
    expect(buildWorkerUrl("/me/rules")).toBe("https://autofill-browser-log-worker.y-elucidator.workers.dev/me/rules")
  })

  it("keeps cloud transport config out of synced settings", () => {
    const syncedSnapshot = buildSyncedSnapshot(snapshot)

    expect(syncedSnapshot.profile.fullName).toBe("山田 太郎")
    expect(syncedSnapshot.domainPolicies).toMatchObject({
      "example.com": "whitelist"
    })
    expect(syncedSnapshot.settings).toMatchObject({
      enabled: true,
      observeDynamicForms: true,
      minMatchCount: 1
    })
    expect(syncedSnapshot.settings).not.toHaveProperty("cloudLogSync")
    expect(syncedSnapshot.secureVault?.entries).toEqual({})
    expect(syncedSnapshot.secureVaultRecovery?.ciphertext).toBe("wrapped-key")
    expect(syncedSnapshot).not.toHaveProperty("secureVaultKey")
    expect(syncedSnapshot).toMatchObject({
      baseRevision: 3,
      deviceId: "device-a",
      changedFields: ["profile", "settings", "domainPolicies", "secureVault", "secureVaultRecovery"]
    })
  })

  it("omits secure vault payload when secureVault was not changed", () => {
    const syncedSnapshot = buildSyncedSnapshot(snapshot, ["profile"])

    expect(syncedSnapshot).not.toHaveProperty("secureVault")
    expect(syncedSnapshot).not.toHaveProperty("secureVaultRecovery")
    expect(syncedSnapshot.changedFields).toEqual(["profile"])
  })

  it("includes recovery package when only secureVaultRecovery changed", () => {
    const syncedSnapshot = buildSyncedSnapshot(snapshot, ["secureVaultRecovery"])

    expect(syncedSnapshot).not.toHaveProperty("secureVault")
    expect(syncedSnapshot.secureVaultRecovery?.ciphertext).toBe("wrapped-key")
    expect(syncedSnapshot.changedFields).toEqual(["secureVaultRecovery"])
  })
})
