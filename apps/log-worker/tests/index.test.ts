import { describe, expect, it } from "vitest"

import worker, { type D1Database, type D1PreparedStatement, type D1Result, type Env, type EventLogRow } from "../src/index"

type StoredLogRow = EventLogRow

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
    private readonly rows: StoredLogRow[]
  ) {}

  bind(...values: Array<string | number | boolean | null>) {
    this.values = values
    return this
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    if (this.query.includes("INSERT OR REPLACE INTO event_logs")) {
      const row: StoredLogRow = {
        id: String(this.values[0]),
        timestamp: String(this.values[1]),
        type: String(this.values[2]),
        hostname: String(this.values[3]),
        url: String(this.values[4]),
        field_signature: this.values[5] === null ? null : String(this.values[5]),
        profile_key: this.values[6] === null ? null : String(this.values[6]),
        previous_value: this.values[7] === null ? null : String(this.values[7]),
        next_value: this.values[8] === null ? null : String(this.values[8]),
        source: String(this.values[9]),
        run_id: this.values[10] === null ? null : String(this.values[10]),
        detail: this.values[11] === null ? null : String(this.values[11]),
        received_at: String(this.values[12]),
        raw_json: String(this.values[13])
      }
      const existingIndex = this.rows.findIndex((existingRow) => existingRow.id === row.id)
      if (existingIndex >= 0) {
        this.rows[existingIndex] = row
      } else {
        this.rows.push(row)
      }
    }

    return {
      success: true
    }
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const limit = Number(this.values[0] ?? 50)
    const results = [...this.rows]
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

  prepare(query: string) {
    return new FakeStatement(query, this.rows)
  }
}

const createEnv = () => ({
  DB: new FakeD1Database(),
  CLOUD_LOG_INGEST_TOKEN: "secret-token"
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

describe("log-worker", () => {
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
})
