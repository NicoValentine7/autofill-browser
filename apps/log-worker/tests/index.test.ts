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

    if (this.query.includes("INSERT OR REPLACE INTO user_sync_snapshots")) {
      const row: StoredSyncSnapshotRow = {
        user_id: String(this.values[0]),
        schema_version: Number(this.values[1]),
        profile_json: String(this.values[2]),
        settings_json: String(this.values[3]),
        domain_policies_json: String(this.values[4]),
        updated_at: String(this.values[5]),
        raw_json: String(this.values[6])
      }
      const existingIndex = this.db.snapshots.findIndex((existingRow) => existingRow.user_id === row.user_id)
      if (existingIndex >= 0) {
        this.db.snapshots[existingIndex] = row
      } else {
        this.db.snapshots.push(row)
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
      return {
        success: true,
        results: this.db.snapshots.filter((row) => row.user_id === this.values[0]) as T[]
      }
    }

    const hasUserFilter = this.query.includes("WHERE user_id = ?")
    const limit = Number(this.values[hasUserFilter ? 1 : 0] ?? 50)
    const userId = hasUserFilter ? String(this.values[0]) : null
    const results = [...this.db.rows]
      .filter((row) => (userId ? row.user_id === userId : true))
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

  prepare(query: string) {
    return new FakeStatement(query, this)
  }
}

const createEnv = () => ({
  DB: new FakeD1Database(),
  CLOUD_LOG_INGEST_TOKEN: "secret-token",
  GOOGLE_OAUTH_CLIENT_ID: "google-client-id.apps.googleusercontent.com"
})

const authHeaders = {
  authorization: "Bearer secret-token",
  "content-type": "application/json"
}

const postLogs = (env: Env, payload: unknown, headers: Record<string, string> = authHeaders) =>
  worker.fetch(
    new Request("https://logs.example.com/logs", {
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
      next_value: "taro@example.com",
      previous_value: ""
    })
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
      new Request("https://logs.example.com/logs?limit=1", {
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
      new Request("https://logs.example.com/auth/me", {
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

  it("rejects Google tokens with the wrong client id or unverified email", async () => {
    const wrongClientEnv = createEnv()
    mockGoogleTokenInfo({
      aud: "another-client.apps.googleusercontent.com"
    })
    const wrongClientResponse = await worker.fetch(
      new Request("https://logs.example.com/auth/me", {
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
      new Request("https://logs.example.com/auth/me", {
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

    await postLogs(env, {
      schemaVersion: 1,
      source: "chrome-extension",
      emittedAt: "2026-05-20T12:00:01.000Z",
      events: [event]
    }, googleHeaders)
    env.DB.rows.push({
      ...env.DB.rows[0],
      id: "other-user-event",
      user_id: "other-user"
    })

    const response = await worker.fetch(
      new Request("https://logs.example.com/logs?limit=50", {
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
        minMatchCount: 1,
        cloudLogSync: {
          endpointUrl: "",
          bearerToken: "",
          includeFieldValues: true
        }
      },
      domainPolicies: {
        "example.com": "whitelist"
      },
      updatedAt: "2026-05-21T00:00:00.000Z"
    }

    const putResponse = await worker.fetch(
      new Request("https://logs.example.com/sync/settings", {
        method: "PUT",
        headers: googleHeaders,
        body: JSON.stringify(snapshot)
      }),
      env
    )
    const getResponse = await worker.fetch(
      new Request("https://logs.example.com/sync/settings", {
        headers: googleHeaders
      }),
      env
    )
    const body = (await getResponse.json()) as { snapshot: typeof snapshot }

    expect(putResponse.status).toBe(200)
    expect(getResponse.status).toBe(200)
    expect(body.snapshot.profile.fullName).toBe("山田 太郎")
    expect(body.snapshot.domainPolicies).toMatchObject({
      "example.com": "whitelist"
    })
  })
})
