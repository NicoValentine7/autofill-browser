import { afterEach, describe, expect, it, vi } from "vitest"

import worker, { type D1Database, type D1PreparedStatement, type D1Result, type Env, type EventLogRow } from "../src/index"

type StoredLogRow = EventLogRow

type StoredUserRow = {
  id: string
  google_sub: string
  email: string
  name: string | null
  picture: string | null
  created_at: string
  updated_at: string
}

type StoredSyncSnapshotRow = {
  user_id: string
  schema_version: number
  profile_json: string
  settings_json: string
  domain_policies_json: string
  updated_at: string
  raw_json: string
  revision: number
  device_id: string | null
  changed_fields_json: string
  encryption_version: number
  secure_vault_json: string | null
}

type StoredSyncSnapshotHistoryRow = StoredSyncSnapshotRow & {
  id: string
  revision: number
  device_id: string | null
  changed_fields_json: string
  encryption_version: number
  action: string
  created_at: string
}

type StoredRemoteRulesRow = {
  key: string
  schema_version: number
  blocked_identity_tokens_json: string
  updated_at: string
}

type StoredAnalysisReportRow = {
  id: string
  scope_user_id: string | null
  window_started_at: string
  window_ended_at: string
  total_events: number
  field_filled_count: number
  correction_count: number
  risky_event_count: number
  top_hostnames_json: string
  top_profile_keys_json: string
  notes_json: string
  created_at: string
}

const event = {
  id: "event-1",
  type: "field_filled",
  timestamp: "2026-05-20T12:00:00.000Z",
  hostname: "example.com",
  url: "https://example.com/form",
  fieldSignature: "input|email",
  profileKey: "email",
  previousValue: "",
  nextValue: "taro@example.com",
  source: "popup",
  runId: "run-1",
  detail: "test"
}

class FakeStatement implements D1PreparedStatement {
  private values: Array<string | number | boolean | null> = []

  constructor(
    private readonly query: string,
    private readonly db: FakeD1Database
  ) {}

  bind(...values: Array<string | number | boolean | null>) {
    this.values = values
    return this
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    if (this.query.includes("INSERT OR REPLACE INTO event_logs")) {
      const row: StoredLogRow = {
        id: String(this.values[0]),
        user_id: this.values[1] === null ? null : String(this.values[1]),
        timestamp: String(this.values[2]),
        type: String(this.values[3]),
        hostname: String(this.values[4]),
        url: String(this.values[5]),
        field_signature: this.values[6] === null ? null : String(this.values[6]),
        profile_key: this.values[7] === null ? null : String(this.values[7]),
        previous_value: this.values[8] === null ? null : String(this.values[8]),
        next_value: this.values[9] === null ? null : String(this.values[9]),
        source: String(this.values[10]),
        run_id: this.values[11] === null ? null : String(this.values[11]),
        detail: this.values[12] === null ? null : String(this.values[12]),
        received_at: String(this.values[13]),
        raw_json: String(this.values[14])
      }
      const existingIndex = this.db.rows.findIndex((existingRow) => existingRow.id === row.id)
      if (existingIndex >= 0) {
        this.db.rows[existingIndex] = row
      } else {
        this.db.rows.push(row)
      }
    }

    if (this.query.includes("INSERT INTO users")) {
      this.db.users.push({
        id: String(this.values[0]),
        google_sub: String(this.values[1]),
        email: String(this.values[2]),
        name: this.values[3] === null ? null : String(this.values[3]),
        picture: this.values[4] === null ? null : String(this.values[4]),
        created_at: String(this.values[5]),
        updated_at: String(this.values[6])
      })
    }

    if (this.query.includes("UPDATE users")) {
      const user = this.db.users.find((row) => row.id === this.values[4])
      if (user) {
        user.email = String(this.values[0])
        user.name = this.values[1] === null ? null : String(this.values[1])
        user.picture = this.values[2] === null ? null : String(this.values[2])
        user.updated_at = String(this.values[3])
      }
    }

    if (this.query.includes("UPDATE user_sync_snapshots")) {
      const snapshot = this.db.snapshots.find((row) => row.user_id === this.values[1])
      if (snapshot) {
        snapshot.secure_vault_json = this.values[0] === null ? null : String(this.values[0])
      }
    }

    if (this.query.includes("UPDATE user_sync_snapshot_history")) {
      const snapshot = this.db.snapshotHistory.find((row) => row.id === this.values[1])
      if (snapshot) {
        snapshot.secure_vault_json = this.values[0] === null ? null : String(this.values[0])
      }
    }

    if (this.query.includes("INSERT OR REPLACE INTO user_sync_snapshots")) {
      const row: StoredSyncSnapshotRow = {
        user_id: String(this.values[0]),
        schema_version: Number(this.values[1]),
        profile_json: String(this.values[2]),
        settings_json: String(this.values[3]),
        domain_policies_json: String(this.values[4]),
        updated_at: String(this.values[5]),
        raw_json: String(this.values[6]),
        revision: Number(this.values[7] ?? 0),
        device_id: this.values[8] === null ? null : String(this.values[8]),
        changed_fields_json: String(this.values[9] ?? "[]"),
        encryption_version: Number(this.values[10] ?? 0),
        secure_vault_json: this.values[11] === null ? null : String(this.values[11])
      }
      const existingIndex = this.db.snapshots.findIndex((existingRow) => existingRow.user_id === row.user_id)
      if (existingIndex >= 0) {
        this.db.snapshots[existingIndex] = row
      } else {
        this.db.snapshots.push(row)
      }
    }

    if (this.query.includes("INSERT OR REPLACE INTO user_sync_snapshot_history")) {
      const row: StoredSyncSnapshotHistoryRow = {
        id: String(this.values[0]),
        user_id: String(this.values[1]),
        revision: Number(this.values[2]),
        schema_version: Number(this.values[3]),
        profile_json: String(this.values[4]),
        settings_json: String(this.values[5]),
        domain_policies_json: String(this.values[6]),
        updated_at: String(this.values[7]),
        device_id: this.values[8] === null ? null : String(this.values[8]),
        changed_fields_json: String(this.values[9] ?? "[]"),
        encryption_version: Number(this.values[10] ?? 0),
        secure_vault_json: this.values[11] === null ? null : String(this.values[11]),
        raw_json: String(this.values[12]),
        action: String(this.values[13]),
        created_at: String(this.values[14])
      }
      const existingIndex = this.db.snapshotHistory.findIndex((existingRow) => existingRow.id === row.id)
      if (existingIndex >= 0) {
        this.db.snapshotHistory[existingIndex] = row
      } else {
        this.db.snapshotHistory.push(row)
      }
    }

    if (this.query.includes("INSERT OR REPLACE INTO remote_rules")) {
      const row: StoredRemoteRulesRow = {
        key: String(this.values[0]),
        schema_version: Number(this.values[1]),
        blocked_identity_tokens_json: String(this.values[2]),
        updated_at: String(this.values[3])
      }
      const existingIndex = this.db.remoteRules.findIndex((existingRow) => existingRow.key === row.key)
      if (existingIndex >= 0) {
        this.db.remoteRules[existingIndex] = row
      } else {
        this.db.remoteRules.push(row)
      }
    }

    if (this.query.includes("INSERT OR REPLACE INTO log_analysis_reports")) {
      const row: StoredAnalysisReportRow = {
        id: String(this.values[0]),
        scope_user_id: this.values[1] === null ? null : String(this.values[1]),
        window_started_at: String(this.values[2]),
        window_ended_at: String(this.values[3]),
        total_events: Number(this.values[4]),
        field_filled_count: Number(this.values[5]),
        correction_count: Number(this.values[6]),
        risky_event_count: Number(this.values[7]),
        top_hostnames_json: String(this.values[8]),
        top_profile_keys_json: String(this.values[9]),
        notes_json: String(this.values[10]),
        created_at: String(this.values[11])
      }
      const existingIndex = this.db.analysisReports.findIndex((existingRow) => existingRow.id === row.id)
      if (existingIndex >= 0) {
        this.db.analysisReports[existingIndex] = row
      } else {
        this.db.analysisReports.push(row)
      }
    }

    return {
      success: true
    }
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    if (this.query.includes("FROM users")) {
      return {
        success: true,
        results: this.db.users.filter((row) => row.google_sub === this.values[0]) as T[]
      }
    }

    if (this.query.includes("FROM user_sync_snapshots")) {
      const hasUserFilter = this.query.includes("WHERE user_id = ?")
      return {
        success: true,
        results: this.db.snapshots.filter((row) => (hasUserFilter ? row.user_id === this.values[0] : true)) as T[]
      }
    }

    if (this.query.includes("FROM user_sync_snapshot_history")) {
      const hasRevisionFilter = this.query.includes("revision = ?")
      const hasUserFilter = this.query.includes("WHERE user_id = ?")
      const limitIndex = hasRevisionFilter ? null : hasUserFilter ? 1 : 0
      const userId = hasUserFilter ? String(this.values[0]) : null
      const revision = hasRevisionFilter ? Number(this.values[1]) : null
      const limit = limitIndex === null ? 1 : Number(this.values[limitIndex] ?? 50)
      const results = [...this.db.snapshotHistory]
        .filter((row) => (userId ? row.user_id === userId : true))
        .filter((row) => (revision ? row.revision === revision : true))
        .sort((left, right) => right.revision - left.revision || right.created_at.localeCompare(left.created_at))
        .slice(0, limit) as T[]

      return {
        success: true,
        results
      }
    }

    if (this.query.includes("FROM remote_rules")) {
      return {
        success: true,
        results: this.db.remoteRules.filter((row) => row.key === this.values[0]) as T[]
      }
    }

    if (this.query.includes("FROM log_analysis_reports")) {
      const hasUserFilter = this.query.includes("WHERE scope_user_id = ?")
      const limit = Number(this.values[hasUserFilter ? 1 : 0] ?? 50)
      const userId = hasUserFilter ? String(this.values[0]) : null
      const results = [...this.db.analysisReports]
        .filter((row) => (userId ? row.scope_user_id === userId : row.scope_user_id === null))
        .sort((left, right) => right.created_at.localeCompare(left.created_at))
        .slice(0, limit) as T[]

      return {
        success: true,
        results
      }
    }

    const hasUserFilter = this.query.includes("WHERE user_id = ?")
    const hasReceivedAtFilter = this.query.includes("received_at >= ?")
    const limitIndex = hasUserFilter && hasReceivedAtFilter ? 2 : hasUserFilter || hasReceivedAtFilter ? 1 : 0
    const limit = Number(this.values[limitIndex] ?? 50)
    const userId = hasUserFilter ? String(this.values[0]) : null
    const receivedAtMin = hasReceivedAtFilter ? String(this.values[hasUserFilter ? 1 : 0]) : null
    const results = [...this.db.rows]
      .filter((row) => (userId ? row.user_id === userId : true))
      .filter((row) => (receivedAtMin ? row.received_at >= receivedAtMin : true))
      .sort((left, right) => right.received_at.localeCompare(left.received_at) || right.timestamp.localeCompare(left.timestamp))
      .slice(0, limit) as T[]

    return {
      success: true,
      results
    }
  }
}

class FakeD1Database implements D1Database {
  readonly rows: StoredLogRow[] = []
  readonly users: StoredUserRow[] = []
  readonly snapshots: StoredSyncSnapshotRow[] = []
  readonly snapshotHistory: StoredSyncSnapshotHistoryRow[] = []
  readonly remoteRules: StoredRemoteRulesRow[] = []
  readonly analysisReports: StoredAnalysisReportRow[] = []

  prepare(query: string) {
    return new FakeStatement(query, this)
  }
}

const createEnv = (override: Partial<Env> = {}) => ({
  DB: new FakeD1Database(),
  CLOUD_LOG_INGEST_TOKEN: "secret-token",
  GOOGLE_OAUTH_CLIENT_ID: "google-client-id.apps.googleusercontent.com",
  CLOUD_DATA_ENCRYPTION_KEY: "unit-test-encryption-key",
  ...override
})

const authHeaders = {
  authorization: "Bearer secret-token",
  "content-type": "application/json"
}

const postLogs = (env: Env, payload: unknown, headers: Record<string, string> = authHeaders) =>
  worker.fetch(
    new Request("https://logs.example.com/admin/logs", {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    }),
    env
  )

const googleHeaders = {
  authorization: "Bearer google-token",
  "content-type": "application/json"
}

const mockGoogleTokenInfo = (override: Record<string, unknown> = {}) => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(
        JSON.stringify({
          aud: "google-client-id.apps.googleusercontent.com",
          sub: "google-sub-1",
          email: "taro@example.com",
          email_verified: "true",
          name: "Taro",
          picture: "https://example.com/avatar.png",
          ...override
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        }
      )
    )
  )
}

describe("log-worker", () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("returns 401 when the bearer token is missing or wrong", async () => {
    const env = createEnv()
    const payload = {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [event]
    }

    const missingTokenResponse = await postLogs(env, payload, {
      "content-type": "application/json"
    })
    const wrongTokenResponse = await postLogs(env, payload, {
      ...authHeaders,
      authorization: "Bearer wrong-token"
    })

    expect(missingTokenResponse.status).toBe(401)
    expect(wrongTokenResponse.status).toBe(401)
  })

  it("inserts POSTed logs into D1", async () => {
    const env = createEnv()
    const response = await postLogs(env, {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [event]
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({
      ok: true,
      inserted: 1
    })
    expect(env.DB.rows[0]).toMatchObject({
      id: "event-1",
      user_id: null,
      previous_value: expect.stringContaining('"encrypted":true'),
      next_value: expect.stringContaining('"encrypted":true')
    })
    expect(env.DB.rows[0]?.next_value).not.toContain("taro@example.com")
  })

  it("returns recent logs newest first", async () => {
    const env = createEnv()
    await postLogs(env, {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [
        {
          ...event,
          id: "event-old",
          timestamp: "2026-05-20T11:00:00.000Z"
        },
        {
          ...event,
          id: "event-new",
          timestamp: "2026-05-20T13:00:00.000Z"
        }
      ]
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/admin/logs?limit=1", {
        headers: {
          authorization: "Bearer secret-token"
        }
      }),
      env
    )
    const body = (await response.json()) as { logs: StoredLogRow[] }

    expect(response.status).toBe(200)
    expect(body.logs).toHaveLength(1)
    expect(body.logs[0]?.id).toBe("event-new")
  })

  it("returns 400 for malformed payloads", async () => {
    const env = createEnv()
    const response = await postLogs(env, {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [
        {
          id: "event-without-required-fields"
        }
      ]
    })

    expect(response.status).toBe(400)
  })

  it("authenticates Google tokens and returns the signed-in user", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()

    const response = await worker.fetch(
      new Request("https://logs.example.com/me", {
        headers: googleHeaders
      }),
      env
    )
    const body = (await response.json()) as { user: { sub: string; email: string } }

    expect(response.status).toBe(200)
    expect(body.user).toMatchObject({
      sub: "google-sub-1",
      email: "taro@example.com"
    })
    expect(env.DB.users).toHaveLength(1)
  })

  it("accepts Google client IDs from the comma-separated allowlist", async () => {
    const env = createEnv({
      GOOGLE_OAUTH_CLIENT_ID: "local-client.apps.googleusercontent.com",
      GOOGLE_OAUTH_CLIENT_IDS: "local-client.apps.googleusercontent.com,store-client.apps.googleusercontent.com"
    })
    mockGoogleTokenInfo({
      aud: "ignored-platform-client.apps.googleusercontent.com",
      azp: "store-client.apps.googleusercontent.com"
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/me", {
        headers: googleHeaders
      }),
      env
    )

    expect(response.status).toBe(200)
    expect(env.DB.users).toHaveLength(1)
  })

  it("rejects Google tokens with the wrong client id or unverified email", async () => {
    const wrongClientEnv = createEnv()
    mockGoogleTokenInfo({
      aud: "another-client.apps.googleusercontent.com"
    })
    const wrongClientResponse = await worker.fetch(
      new Request("https://logs.example.com/me", {
        headers: googleHeaders
      }),
      wrongClientEnv
    )

    vi.unstubAllGlobals()
    const unverifiedEnv = createEnv()
    mockGoogleTokenInfo({
      email_verified: "false"
    })
    const unverifiedResponse = await worker.fetch(
      new Request("https://logs.example.com/me", {
        headers: googleHeaders
      }),
      unverifiedEnv
    )

    expect(wrongClientResponse.status).toBe(401)
    expect(unverifiedResponse.status).toBe(401)
  })

  it("stores Google-authenticated logs with user_id and returns only that user's logs", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()

    await worker.fetch(
      new Request("https://logs.example.com/me/events", {
        method: "POST",
        headers: googleHeaders,
        body: JSON.stringify({
          schemaVersion: 1,
          source: "chrome-extension",
          emittedAt: "2026-05-20T12:00:01.000Z",
          events: [event]
        })
      }),
      env
    )
    env.DB.rows.push({
      ...env.DB.rows[0],
      id: "other-user-event",
      user_id: "other-user"
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/me/events?limit=50", {
        headers: googleHeaders
      }),
      env
    )
    const body = (await response.json()) as { logs: StoredLogRow[] }

    expect(env.DB.rows[0]?.user_id).toBe(env.DB.users[0]?.id)
    expect(body.logs.map((row) => row.id)).toEqual(["event-1"])
  })

  it("saves and restores sync settings per Google user", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const snapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "山田 太郎",
        email: "taro@example.com",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {
        "example.com": "whitelist"
      },
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["profile", "settings", "domainPolicies"]
    }

    const putResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )
    const getResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        headers: googleHeaders
      }),
      env
    )
    const body = (await getResponse.json()) as { snapshot: typeof snapshot & { revision: number } }

    expect(putResponse.status).toBe(200)
    expect(getResponse.status).toBe(200)
    expect(body.snapshot.profile.fullName).toBe("山田 太郎")
    expect(body.snapshot.revision).toBe(1)
    expect(body.snapshot.domainPolicies).toMatchObject({
      "example.com": "whitelist"
    })
    expect(env.DB.snapshots[0]?.profile_json).not.toContain("山田")
    expect(env.DB.snapshots[0]?.encryption_version).toBe(1)
    expect(env.DB.snapshotHistory).toHaveLength(1)
    expect(env.DB.snapshotHistory[0]?.action).toBe("save")
  })

  it("stores secure vault sync data encrypted and restores it", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const snapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "",
        email: "",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      secureVault: {
        schemaVersion: 1,
        encryptionVersion: 1,
        entries: {
          "example.com::field": {
            hostname: "example.com",
            fieldSignature: "field",
            kind: "payment-card",
            encryptedValue: {
              schemaVersion: 1,
              algorithm: "AES-GCM",
              iv: "iv",
              ciphertext: "client-side-card-ciphertext"
            },
            timesAutofilled: 0,
            timesCorrected: 0,
            timesLearned: 1,
            createdAt: "2026-05-21T00:00:00.000Z",
            updatedAt: "2026-05-21T00:00:00.000Z"
          }
        }
      },
      secureVaultRecovery: {
        schemaVersion: 1,
        keyId: "vault-key-1",
        algorithm: "PBKDF2-SHA256/AES-GCM",
        iterations: 250000,
        salt: "salt",
        iv: "iv",
        ciphertext: "wrapped-key-ciphertext",
        createdAt: "2026-05-22T00:00:00.000Z"
      },
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["secureVault"]
    }

    const putResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )
    const getResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        headers: googleHeaders
      }),
      env
    )
    const body = (await getResponse.json()) as { snapshot: typeof snapshot & { revision: number } }

    expect(putResponse.status).toBe(200)
    expect(getResponse.status).toBe(200)
    expect(body.snapshot).not.toHaveProperty("secureVaultKey")
    expect(body.snapshot.secureVault.entries["example.com::field"].kind).toBe("payment-card")
    expect(body.snapshot.secureVaultRecovery.ciphertext).toBe("wrapped-key-ciphertext")
    expect(env.DB.snapshots[0]?.secure_vault_json).toContain('"encrypted":true')
    expect(env.DB.snapshots[0]?.secure_vault_json).not.toContain("client-side-card-ciphertext")
    expect(env.DB.snapshots[0]?.secure_vault_json).not.toContain("wrapped-key-ciphertext")
    expect(env.DB.snapshots[0]?.raw_json).not.toContain("client-side-card-ciphertext")
    expect(env.DB.snapshots[0]?.raw_json).not.toContain("wrapped-key-ciphertext")
  })

  it("rejects sync payloads that still contain a plaintext secureVaultKey", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const snapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "",
        email: "",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      secureVaultKey: {
        rawKey: "legacy-raw-key"
      },
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["secureVault"]
    }

    const response = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )

    expect(response.status).toBe(400)
    expect(env.DB.snapshots).toHaveLength(0)
  })

  it("scrubs legacy secure vault keys from the current sync row on read", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const snapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "",
        email: "",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      secureVault: {
        schemaVersion: 1,
        encryptionVersion: 1,
        entries: {
          "example.com::field": {
            hostname: "example.com",
            fieldSignature: "field",
            kind: "payment-card",
            encryptedValue: {
              schemaVersion: 1,
              algorithm: "AES-GCM",
              iv: "iv",
              ciphertext: "client-side-card-ciphertext"
            },
            timesAutofilled: 0,
            timesCorrected: 0,
            timesLearned: 1,
            createdAt: "2026-05-21T00:00:00.000Z",
            updatedAt: "2026-05-21T00:00:00.000Z"
          }
        }
      },
      secureVaultRecovery: {
        schemaVersion: 1,
        keyId: "vault-key-1",
        algorithm: "PBKDF2-SHA256/AES-GCM",
        iterations: 250000,
        salt: "salt",
        iv: "iv",
        ciphertext: "wrapped-key-ciphertext",
        createdAt: "2026-05-22T00:00:00.000Z"
      },
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["secureVault"]
    }

    await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )
    env.DB.snapshots[0]!.secure_vault_json = JSON.stringify({
      secureVault: snapshot.secureVault,
      secureVaultRecovery: snapshot.secureVaultRecovery,
      secureVaultKey: {
        rawKey: "legacy-raw-key"
      }
    })
    env.DB.snapshotHistory[0]!.secure_vault_json = JSON.stringify({
      secureVault: snapshot.secureVault,
      secureVaultRecovery: snapshot.secureVaultRecovery,
      secureVaultKey: {
        rawKey: "legacy-history-raw-key"
      }
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        headers: googleHeaders
      }),
      env
    )
    const restoreResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings/history", {
        method: "POST",
        headers: googleHeaders,
        body: JSON.stringify({
          revision: 1
        })
      }),
      env
    )
    const body = (await response.json()) as { snapshot: typeof snapshot }

    expect(response.status).toBe(200)
    expect(restoreResponse.status).toBe(200)
    expect(body.snapshot).not.toHaveProperty("secureVaultKey")
    expect(body.snapshot.secureVaultRecovery.ciphertext).toBe("wrapped-key-ciphertext")
    expect(env.DB.snapshots[0]?.secure_vault_json).toContain('"encrypted":true')
    expect(env.DB.snapshots[0]?.secure_vault_json).not.toContain("legacy-raw-key")
    expect(env.DB.snapshotHistory[0]?.secure_vault_json).toContain('"encrypted":true')
    expect(env.DB.snapshotHistory[0]?.secure_vault_json).not.toContain("legacy-history-raw-key")
  })

  it("scrubs legacy secure vault keys across current and history rows from the admin endpoint", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const snapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "",
        email: "",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["profile"]
    }

    await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )
    env.DB.snapshots[0]!.secure_vault_json = JSON.stringify({
      secureVaultKey: {
        rawKey: "legacy-current-raw-key"
      }
    })
    env.DB.snapshotHistory[0]!.secure_vault_json = JSON.stringify({
      secureVaultKey: {
        rawKey: "legacy-history-raw-key"
      }
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/admin/sync-vault-scrub", {
        method: "POST",
        headers: authHeaders
      }),
      env
    )
    const body = (await response.json()) as { currentScrubbed: number; historyScrubbed: number }

    expect(response.status).toBe(200)
    expect(body.currentScrubbed).toBe(1)
    expect(body.historyScrubbed).toBe(1)
    expect(env.DB.snapshots[0]?.secure_vault_json).toBeNull()
    expect(env.DB.snapshotHistory[0]?.secure_vault_json).toBeNull()
  })

  it("merges disjoint sync changes and rejects overlapping stale changes", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const baseSnapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "山田 太郎",
        email: "taro@example.com",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["profile"]
    }

    await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(baseSnapshot)
      }),
      env
    )

    const mergedResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify({
          ...baseSnapshot,
          settings: {
            enabled: false,
            observeDynamicForms: true,
            minMatchCount: 1
          },
          baseRevision: 0,
          deviceId: "device-b",
          changedFields: ["settings"]
        })
      }),
      env
    )
    const mergedBody = (await mergedResponse.json()) as { merged: boolean; revision: number }

    const conflictingResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify({
          ...baseSnapshot,
          profile: {
            ...baseSnapshot.profile,
            fullName: "佐藤 花子"
          },
          baseRevision: 1,
          deviceId: "device-c",
          changedFields: ["settings"]
        })
      }),
      env
    )

    expect(mergedResponse.status).toBe(200)
    expect(mergedBody).toMatchObject({
      merged: true,
      revision: 2
    })
    expect(conflictingResponse.status).toBe(409)
  })

  it("lists sync history and restores a previous revision", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()
    const baseSnapshot = {
      schemaVersion: 1,
      profile: {
        familyName: "",
        givenName: "",
        fullName: "山田 太郎",
        email: "taro@example.com",
        phone: "",
        organization: "",
        postalCode: "",
        prefecture: "",
        city: "",
        addressLine1: "",
        addressLine2: ""
      },
      settings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      },
      domainPolicies: {},
      updatedAt: "2026-05-21T00:00:00.000Z",
      baseRevision: 0,
      deviceId: "device-a",
      changedFields: ["profile"]
    }

    await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(baseSnapshot)
      }),
      env
    )
    await worker.fetch(
      new Request("https://logs.example.com/me/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify({
          ...baseSnapshot,
          profile: {
            ...baseSnapshot.profile,
            fullName: "佐藤 花子"
          },
          baseRevision: 1,
          changedFields: ["profile"]
        })
      }),
      env
    )

    const historyResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings/history?limit=10", {
        headers: googleHeaders
      }),
      env
    )
    const restoreResponse = await worker.fetch(
      new Request("https://logs.example.com/me/settings/history", {
        method: "POST",
        headers: googleHeaders,
        body: JSON.stringify({
          revision: 1
        })
      }),
      env
    )
    const historyBody = (await historyResponse.json()) as { history: Array<{ revision: number; action: string }> }
    const restoreBody = (await restoreResponse.json()) as { snapshot: { profile: { fullName: string }; revision: number } }

    expect(historyResponse.status).toBe(200)
    expect(historyBody.history.map((row) => row.revision)).toEqual([2, 1])
    expect(restoreResponse.status).toBe(200)
    expect(restoreBody.snapshot.profile.fullName).toBe("山田 太郎")
    expect(restoreBody.snapshot.revision).toBe(3)
    expect(env.DB.snapshotHistory.at(-1)?.action).toBe("restore")
  })

  it("stores remote rules and returns log analysis reports", async () => {
    const env = createEnv()
    mockGoogleTokenInfo()

    const rulesResponse = await worker.fetch(
      new Request("https://logs.example.com/admin/rules", {
        method: "PUT",
        headers: authHeaders,
        body: JSON.stringify({
          blockedIdentityTokens: ["Customer Secret", "認証コード"]
        })
      }),
      env
    )
    const userRulesResponse = await worker.fetch(
      new Request("https://logs.example.com/me/rules", {
        headers: googleHeaders
      }),
      env
    )

    await worker.fetch(
      new Request("https://logs.example.com/me/events", {
        method: "POST",
        headers: googleHeaders,
        body: JSON.stringify({
          schemaVersion: 1,
          source: "chrome-extension",
          emittedAt: "2026-05-20T12:00:01.000Z",
          events: [
            {
              ...event,
              fieldSignature: "input|captcha-token",
              detail: "captcha-like"
            }
          ]
        })
      }),
      env
    )

    const analysisResponse = await worker.fetch(
      new Request("https://logs.example.com/me/log-analysis?limit=1", {
        headers: googleHeaders
      }),
      env
    )
    const rulesBody = (await userRulesResponse.json()) as { rules: { blockedIdentityTokens: string[] } }
    const analysisBody = (await analysisResponse.json()) as { reports: Array<{ riskyEventCount: number; topHostnames: unknown[] }> }

    expect(rulesResponse.status).toBe(200)
    expect(rulesBody.rules.blockedIdentityTokens).toContain("customer secret")
    expect(analysisResponse.status).toBe(200)
    expect(analysisBody.reports[0]?.riskyEventCount).toBe(1)
    expect(analysisBody.reports[0]?.topHostnames).toEqual([{ value: "example.com", count: 1 }])
  })

  it("runs scheduled global log analysis", async () => {
    const env = createEnv()
    await postLogs(env, {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [event]
    })

    const pending: Promise<unknown>[] = []
    worker.scheduled(
      {
        cron: "0 15 * * *",
        scheduledTime: Date.now()
      },
      env,
      {
        waitUntil: (promise) => {
          pending.push(promise)
        }
      }
    )
    await Promise.all(pending)

    expect(env.DB.analysisReports).toHaveLength(1)
    expect(env.DB.analysisReports[0]?.scope_user_id).toBeNull()
  })

  it("serves the admin dashboard and protects admin APIs", async () => {
    const env = createEnv()
    const dashboardResponse = await worker.fetch(new Request("https://logs.example.com/admin"), env)
    const unauthorizedResponse = await worker.fetch(new Request("https://logs.example.com/admin/sync-history"), env)

    expect(dashboardResponse.status).toBe(200)
    expect(dashboardResponse.headers.get("content-type")).toContain("text/html")
    expect(await dashboardResponse.text()).toContain("Autofill Browser Admin")
    expect(unauthorizedResponse.status).toBe(401)
  })

  it("serves the public privacy policy without authentication", async () => {
    const env = createEnv()
    const response = await worker.fetch(new Request("https://logs.example.com/privacy"), env)

    expect(response.status).toBe(200)
    expect(response.headers.get("content-type")).toContain("text/html")
    expect(await response.text()).toContain("Autofill Browser Privacy Policy")
  })
})
