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
  settings: DEFAULT_AUTOFILL_SETTINGS,
  domainPolicies: {
    "example.com": "whitelist"
  },
  fieldMemory: {},
  eventLog: [],
  accountSync: {}
}

describe("account-sync", () => {
  it("derives worker API URLs from the fixed cloud worker", () => {
    expect(buildWorkerUrl("/me")).toBe("https://autofill-browser-log-worker.y-elucidator.workers.dev/me")
    expect(buildWorkerUrl("/me/settings")).toBe(
      "https://autofill-browser-log-worker.y-elucidator.workers.dev/me/settings"
    )
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
  })
})
