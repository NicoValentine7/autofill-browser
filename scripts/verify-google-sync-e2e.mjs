#!/usr/bin/env node

import { spawnSync } from "node:child_process"

const WORKER_BASE_URL = process.env.WORKER_BASE_URL ?? "https://autofill-browser-log-worker.y-elucidator.workers.dev"
const GOOGLE_ACCESS_TOKEN = process.env.GOOGLE_ACCESS_TOKEN
const VERIFY_D1_RAW = process.env.VERIFY_D1_RAW === "1"

const requiredProfileKeys = [
  "familyName",
  "givenName",
  "fullName",
  "email",
  "phone",
  "organization",
  "postalCode",
  "prefecture",
  "city",
  "addressLine1",
  "addressLine2"
]

const createEmptyProfile = () => Object.fromEntries(requiredProfileKeys.map((key) => [key, ""]))

const createDefaultSnapshot = () => ({
  schemaVersion: 1,
  profile: createEmptyProfile(),
  settings: {
    enabled: true,
    observeDynamicForms: true,
    minMatchCount: 1
  },
  domainPolicies: {},
  updatedAt: new Date().toISOString(),
  revision: 0
})

const jsonFetch = async (pathname, init = {}) => {
  const response = await fetch(`${WORKER_BASE_URL}${pathname}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${GOOGLE_ACCESS_TOKEN}`,
      ...init.headers
    }
  })
  const body = await response.json().catch(() => null)

  if (!response.ok) {
    throw new Error(`${pathname} failed: ${response.status} ${JSON.stringify(body)}`)
  }

  return body
}

const buildPutSnapshot = (snapshot, patch, baseRevision, deviceId) => ({
  schemaVersion: 1,
  profile: {
    ...snapshot.profile,
    ...patch.profile
  },
  settings: {
    ...snapshot.settings,
    ...patch.settings
  },
  domainPolicies: {
    ...snapshot.domainPolicies,
    ...patch.domainPolicies
  },
  updatedAt: new Date().toISOString(),
  baseRevision,
  deviceId,
  changedFields: patch.changedFields
})

const restoreSnapshot = async (snapshot, baseRevision, deviceId) =>
  jsonFetch("/me/settings", {
    method: "PUT",
    body: JSON.stringify(
      buildPutSnapshot(
        snapshot,
        {
          profile: snapshot.profile,
          settings: snapshot.settings,
          domainPolicies: snapshot.domainPolicies,
          changedFields: ["profile", "settings", "domainPolicies"]
        },
        baseRevision,
        deviceId
      )
    )
  })

const assertD1RawIsEncrypted = (googleSub, marker) => {
  const escapedSub = googleSub.replaceAll("'", "''")
  const result = spawnSync(
    "npx",
    [
      "wrangler",
      "d1",
      "execute",
      "autofill-browser-logs",
      "--remote",
      "--command",
      `SELECT profile_json FROM user_sync_snapshots WHERE user_id IN (SELECT id FROM users WHERE google_sub = '${escapedSub}') LIMIT 1`
    ],
    {
      encoding: "utf8"
    }
  )

  if (result.status !== 0) {
    throw new Error(`wrangler d1 execute failed: ${result.stderr || result.stdout}`)
  }

  if (result.stdout.includes(marker)) {
    throw new Error("D1 raw profile_json contains the test marker; encryption check failed")
  }

  if (!result.stdout.includes("encrypted")) {
    throw new Error("D1 raw profile_json did not look encrypted")
  }
}

if (!GOOGLE_ACCESS_TOKEN) {
  console.error("GOOGLE_ACCESS_TOKEN is required")
  process.exit(2)
}

const marker = `codex-e2e-${Date.now()}`
const deviceId = `codex-e2e-${process.pid}-${Date.now()}`
let originalSnapshot = null
let latestRevision = 0

try {
  const me = await jsonFetch("/me")
  const pulled = await jsonFetch("/me/settings")
  originalSnapshot = pulled.snapshot ?? createDefaultSnapshot()
  latestRevision = originalSnapshot.revision ?? 0

  const testSnapshot = buildPutSnapshot(
    originalSnapshot,
    {
      profile: {
        addressLine2: marker
      },
      changedFields: ["profile"]
    },
    latestRevision,
    deviceId
  )
  const putResult = await jsonFetch("/me/settings", {
    method: "PUT",
    body: JSON.stringify(testSnapshot)
  })
  latestRevision = putResult.revision ?? latestRevision

  const restoredFromCloud = await jsonFetch("/me/settings")
  if (restoredFromCloud.snapshot?.profile?.addressLine2 !== marker) {
    throw new Error("GET /me/settings did not return the pushed marker")
  }

  const history = await jsonFetch("/me/settings/history?limit=5")
  if (!history.history?.some((row) => row.revision === latestRevision)) {
    throw new Error("GET /me/settings/history did not include the pushed revision")
  }

  if (VERIFY_D1_RAW) {
    assertD1RawIsEncrypted(me.user.sub, marker)
  }

  await restoreSnapshot(originalSnapshot, latestRevision, deviceId)
  console.log(
    JSON.stringify(
      {
        ok: true,
        email: me.user.email,
        pushedRevision: latestRevision,
        restored: true,
        d1RawChecked: VERIFY_D1_RAW
      },
      null,
      2
    )
  )
} catch (error) {
  if (originalSnapshot) {
    try {
      await restoreSnapshot(originalSnapshot, latestRevision, deviceId)
    } catch (restoreError) {
      console.error(`restore failed: ${restoreError instanceof Error ? restoreError.message : String(restoreError)}`)
    }
  }
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
