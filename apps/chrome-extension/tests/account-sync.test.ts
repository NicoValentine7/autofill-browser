import { DEFAULT_AUTOFILL_SETTINGS, createEmptyProfile } from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import { buildSyncedSnapshot, buildWorkerUrl } from "../lib/account-sync"
import type { StorageSnapshot } from "../lib/storage"

const snapshot: StorageSnapshot = {
  profile: {
    ...createEmptyProfile(),
    fullName: "山田 太郎",
    email: "taro@example.com"
  },
  settings: {
    ...DEFAULT_AUTOFILL_SETTINGS,
    cloudLogSync: {
      endpointUrl: "https://logs.example.com/logs",
      bearerToken: "secret-token",
      includeFieldValues: true
    }
  },
  domainPolicies: {
    "example.com": "whitelist"
  },
  fieldMemory: {},
  eventLog: [],
  accountSync: {}
}

describe("account-sync", () => {
  it("derives worker API URLs from the /logs endpoint", () => {
    expect(buildWorkerUrl("https://logs.example.com/logs", "/auth/me")).toBe("https://logs.example.com/auth/me")
    expect(buildWorkerUrl("https://logs.example.com/api/logs", "/sync/settings")).toBe(
      "https://logs.example.com/api/sync/settings"
    )
  })

  it("keeps endpoint and shared bearer token out of synced settings", () => {
    const syncedSnapshot = buildSyncedSnapshot(snapshot)

    expect(syncedSnapshot.profile.fullName).toBe("山田 太郎")
    expect(syncedSnapshot.domainPolicies).toMatchObject({
      "example.com": "whitelist"
    })
    expect(syncedSnapshot.settings.cloudLogSync).toMatchObject({
      endpointUrl: "",
      bearerToken: "",
      includeFieldValues: true
    })
  })
})
