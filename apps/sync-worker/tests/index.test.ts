import { describe, expect, it } from "vitest"

import worker, {
  containsForbiddenProperty,
  type D1Database,
  type D1PreparedStatement,
  type D1Result,
  type Env,
  type SyncSnapshotRow
} from "../src/index"

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
const SECRET_MARKER = "plaintext-vault-token-marker"

const base64 = (input: string | Uint8Array): string => Buffer.from(input).toString("base64")

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
    if (this.query.includes("INSERT OR REPLACE INTO sync_snapshots")) {
      const row: SyncSnapshotRow = {
        account_id: String(this.values[0]),
        schema_version: Number(this.values[1]),
        key_id: String(this.values[2]),
        snapshot_json: String(this.values[3]),
        recovery_json: String(this.values[4]),
        created_at: String(this.values[5]),
        updated_at: String(this.values[6])
      }
      const existingIndex = this.db.snapshots.findIndex((existingRow) => existingRow.account_id === row.account_id)
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
    if (this.query.includes("FROM sync_snapshots")) {
      return {
        success: true,
        results: this.db.snapshots.filter((row) => row.account_id === this.values[0]) as T[]
      }
    }
    return {
      success: true,
      results: []
    }
  }
}

class FakeD1Database implements D1Database {
  readonly snapshots: SyncSnapshotRow[] = []

  prepare(query: string) {
    return new FakeStatement(query, this)
  }
}

const createEnv = (override: Partial<Env> = {}): Env & { DB: FakeD1Database } => ({
  DB: new FakeD1Database(),
  SYNC_AUTH_TOKEN: "sync-shared-token",
  ...override
})

const authHeaders = {
  authorization: "Bearer sync-shared-token",
  "content-type": "application/json"
}

const validPayload = () => ({
  schemaVersion: 1,
  syncId: ACCOUNT_ID,
  keyId: "sync-key-0011aabb",
  createdAt: "1750000000",
  snapshot: {
    schemaVersion: 1,
    algorithm: "AES-GCM",
    iv: base64("iv-12-bytes!"),
    ciphertext: base64("opaque-client-side-aes-gcm-ciphertext-bytes")
  },
  recovery: {
    schemaVersion: 1,
    keyId: "sync-key-0011aabb",
    syncId: ACCOUNT_ID,
    algorithm: "PBKDF2-SHA256/AES-GCM",
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: 600000,
      salt: base64("sixteen-b-salt!!")
    },
    iv: base64("iv-12-bytes!"),
    ciphertext: base64("wrapped-vault-key-ciphertext-bytes"),
    createdAt: "1750000000"
  }
})

const putSnapshot = (env: Env, payload: unknown, headers: Record<string, string> = authHeaders, accountId = ACCOUNT_ID) =>
  worker.fetch(
    new Request(`https://sync.example.com/v1/snapshots/${accountId}`, {
      method: "PUT",
      headers,
      body: JSON.stringify(payload)
    }),
    env
  )

const getSnapshot = (env: Env, accountId = ACCOUNT_ID, headers: Record<string, string> = authHeaders) =>
  worker.fetch(
    new Request(`https://sync.example.com/v1/snapshots/${accountId}`, {
      headers
    }),
    env
  )

describe("sync-worker", () => {
  it("rejects requests without or with a wrong bearer token", async () => {
    const env = createEnv()
    const missing = await putSnapshot(env, validPayload(), { "content-type": "application/json" })
    const wrong = await putSnapshot(env, validPayload(), {
      ...authHeaders,
      authorization: "Bearer wrong-token"
    })

    expect(missing.status).toBe(401)
    expect(wrong.status).toBe(401)
    expect(env.DB.snapshots).toHaveLength(0)
  })

  it("fails closed when no auth token is configured", async () => {
    const env = createEnv({ SYNC_AUTH_TOKEN: undefined })
    const response = await putSnapshot(env, validPayload())

    expect(response.status).toBe(503)
    expect(env.DB.snapshots).toHaveLength(0)
  })

  it("stores an encrypted snapshot and returns it on GET", async () => {
    const env = createEnv()
    const payload = validPayload()

    const putResponse = await putSnapshot(env, payload)
    const getResponse = await getSnapshot(env)
    const body = (await getResponse.json()) as typeof payload & { updatedAt: string }

    expect(putResponse.status).toBe(200)
    expect(getResponse.status).toBe(200)
    expect(body.schemaVersion).toBe(1)
    expect(body.syncId).toBe(ACCOUNT_ID)
    expect(body.keyId).toBe(payload.keyId)
    expect(body.snapshot).toEqual(payload.snapshot)
    expect(body.recovery).toEqual(payload.recovery)
    expect(env.DB.snapshots).toHaveLength(1)
  })

  it("returns 404 for a sync id that has no snapshot", async () => {
    const env = createEnv()
    const response = await getSnapshot(env, "ffffffffffffffffffffffffffffffff")

    expect(response.status).toBe(404)
  })

  it("rejects malformed payloads and invalid sync ids", async () => {
    const env = createEnv()

    const wrongSchema = await putSnapshot(env, { ...validPayload(), schemaVersion: 2 })
    const wrongAlgorithm = await putSnapshot(env, {
      ...validPayload(),
      snapshot: { ...validPayload().snapshot, algorithm: "ROT13" }
    })
    const nonBase64 = await putSnapshot(env, {
      ...validPayload(),
      snapshot: { ...validPayload().snapshot, ciphertext: "not base64 at all!!!" }
    })
    const mismatchedSyncId = await putSnapshot(env, { ...validPayload(), syncId: "other-sync-id-01" })
    const weakKdf = await putSnapshot(env, {
      ...validPayload(),
      recovery: { ...validPayload().recovery, kdf: { name: "PBKDF2-SHA256", iterations: 1000, salt: base64("sixteen-b-salt!!") } }
    })
    const badAccountId = await putSnapshot(env, validPayload(), authHeaders, "UPPER_CASE_ID")

    expect(wrongSchema.status).toBe(400)
    expect(wrongAlgorithm.status).toBe(400)
    expect(nonBase64.status).toBe(400)
    expect(mismatchedSyncId.status).toBe(400)
    expect(weakKdf.status).toBe(400)
    expect(badAccountId.status).toBe(400)
    expect(env.DB.snapshots).toHaveLength(0)
  })

  it("rejects payloads carrying plaintext key material property names", async () => {
    const env = createEnv()

    const withVaultKey = await putSnapshot(env, { ...validPayload(), vaultKey: SECRET_MARKER })
    const withPhrase = await putSnapshot(env, { ...validPayload(), recoveryPhrase: SECRET_MARKER })
    const withNestedKey = await putSnapshot(env, {
      ...validPayload(),
      recovery: { ...validPayload().recovery, key: SECRET_MARKER }
    })
    const withContent = await putSnapshot(env, {
      ...validPayload(),
      snapshot: { ...validPayload().snapshot, content: SECRET_MARKER }
    })

    expect(withVaultKey.status).toBe(400)
    expect(withPhrase.status).toBe(400)
    expect(withNestedKey.status).toBe(400)
    expect(withContent.status).toBe(400)
    expect(env.DB.snapshots).toHaveLength(0)
    expect(containsForbiddenProperty({ nested: [{ deep: { passphrase: "x" } }] })).toBe(true)
    expect(containsForbiddenProperty(validPayload())).toBe(false)
  })

  it("stores only the whitelisted envelope fields — a full dump holds no plaintext", async () => {
    const env = createEnv()
    // A hostile or buggy client adds extra properties that pass the forbidden
    // key check; the server must drop them instead of persisting them.
    await putSnapshot(env, { ...validPayload(), note: SECRET_MARKER, extra: { detail: SECRET_MARKER } })

    expect(env.DB.snapshots).toHaveLength(1)
    const dump = JSON.stringify(env.DB.snapshots)
    expect(dump).not.toContain(SECRET_MARKER)
    // The dump contains exactly the envelope columns; ciphertext stays base64.
    const row = env.DB.snapshots[0]!
    expect(Object.keys(JSON.parse(row.snapshot_json)).sort()).toEqual(["algorithm", "ciphertext", "iv", "schemaVersion"])
    expect(Object.keys(JSON.parse(row.recovery_json)).sort()).toEqual([
      "algorithm",
      "ciphertext",
      "createdAt",
      "iv",
      "kdf",
      "keyId",
      "schemaVersion",
      "syncId"
    ])
  })

  it("rejects non-snapshot routes and unsupported methods", async () => {
    const env = createEnv()
    const notFound = await worker.fetch(new Request("https://sync.example.com/admin"), env)
    const wrongMethod = await worker.fetch(
      new Request(`https://sync.example.com/v1/snapshots/${ACCOUNT_ID}`, {
        method: "DELETE",
        headers: authHeaders
      }),
      env
    )

    expect(notFound.status).toBe(404)
    expect(wrongMethod.status).toBe(405)
  })
})
