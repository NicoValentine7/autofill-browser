// Zero-knowledge sync worker (Agent Home U7, ADR 0002/0003).
//
// This Worker stores and returns encrypted snapshot envelopes for the agvt
// CLI. It is deliberately incapable of decrypting anything:
// - the snapshot is AES-GCM ciphertext encrypted client-side with the Vault
//   Key, which is never sent here (ADR 0002);
// - the recovery package is the Vault Key wrapped client-side with the
//   Recovery Phrase (PBKDF2-SHA256 + AES-GCM); the phrase is never sent
//   here (ADR 0003);
// - inbound payloads carrying suspicious plaintext-material property names
//   (key, content, passphrase, recoveryPhrase, ...) are rejected outright,
//   mirroring the log-worker's `secureVaultKey` rejection.

type D1Value = string | number | boolean | null

export type D1Result<T = Record<string, unknown>> = {
  results?: T[]
  success: boolean
  meta?: unknown
}

export type D1PreparedStatement = {
  bind(...values: D1Value[]): D1PreparedStatement
  run<T = Record<string, unknown>>(): Promise<D1Result<T>>
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>
}

export type D1Database = {
  prepare(query: string): D1PreparedStatement
}

export type Env = {
  DB: D1Database
  SYNC_AUTH_TOKEN?: string
}

export type SyncSnapshotRow = {
  account_id: string
  schema_version: number
  key_id: string
  snapshot_json: string
  recovery_json: string
  created_at: string
  updated_at: string
}

const SCHEMA_VERSION = 1
const ACCOUNT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{7,63}$/
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/
const MAX_BODY_BYTES = 4 * 1024 * 1024

// Exact (lowercased) property names that must never appear anywhere in an
// inbound payload: their presence means the client is leaking plaintext
// material the server must not hold (zero-knowledge boundary).
const FORBIDDEN_PROPERTY_NAMES = new Set([
  "key",
  "vaultkey",
  "securevaultkey",
  "recoveryphrase",
  "phrase",
  "passphrase",
  "plaintext",
  "content",
  "body",
  "secret",
  "password",
  "token"
])

const jsonResponse = (status: number, payload: unknown): Response =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8"
    }
  })

const timingSafeEqualString = (left: string, right: string): boolean => {
  const encoder = new TextEncoder()
  const leftBytes = encoder.encode(left)
  const rightBytes = encoder.encode(right)
  if (leftBytes.length !== rightBytes.length) {
    return false
  }
  let difference = 0
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0)
  }
  return difference === 0
}

const authorize = (request: Request, env: Env): Response | null => {
  const expected = env.SYNC_AUTH_TOKEN
  if (!expected) {
    // Fail closed: an unconfigured worker must not accept or serve snapshots.
    return jsonResponse(503, { error: "sync worker auth is not configured" })
  }
  const header = request.headers.get("authorization") ?? ""
  if (!header.startsWith("Bearer ") || !timingSafeEqualString(header.slice(7), expected)) {
    return jsonResponse(401, { error: "unauthorized" })
  }
  return null
}

export const containsForbiddenProperty = (value: unknown, depth = 0): boolean => {
  if (depth > 8 || value === null || typeof value !== "object") {
    return false
  }
  if (Array.isArray(value)) {
    return value.some((entry) => containsForbiddenProperty(entry, depth + 1))
  }
  for (const [propertyName, propertyValue] of Object.entries(value)) {
    if (FORBIDDEN_PROPERTY_NAMES.has(propertyName.toLowerCase())) {
      return true
    }
    if (containsForbiddenProperty(propertyValue, depth + 1)) {
      return true
    }
  }
  return false
}

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && value.length > 0

const isBase64 = (value: unknown): value is string => isNonEmptyString(value) && BASE64_PATTERN.test(value)

type SnapshotEnvelope = {
  schemaVersion: number
  algorithm: string
  iv: string
  ciphertext: string
}

type RecoveryPackage = {
  schemaVersion: number
  keyId: string
  syncId: string
  algorithm: string
  kdf: { name: string; iterations: number; salt: string }
  iv: string
  ciphertext: string
  createdAt: string
}

type PutSnapshotPayload = {
  schemaVersion: number
  syncId: string
  keyId: string
  createdAt: string
  snapshot: SnapshotEnvelope
  recovery: RecoveryPackage
}

const validateEnvelope = (value: unknown): value is SnapshotEnvelope => {
  if (value === null || typeof value !== "object") {
    return false
  }
  const envelope = value as Record<string, unknown>
  return (
    envelope.schemaVersion === SCHEMA_VERSION &&
    envelope.algorithm === "AES-GCM" &&
    isBase64(envelope.iv) &&
    isBase64(envelope.ciphertext)
  )
}

const validateRecovery = (value: unknown, syncId: string): value is RecoveryPackage => {
  if (value === null || typeof value !== "object") {
    return false
  }
  const recovery = value as Record<string, unknown>
  const kdf = recovery.kdf as Record<string, unknown> | undefined
  return (
    recovery.schemaVersion === SCHEMA_VERSION &&
    isNonEmptyString(recovery.keyId) &&
    recovery.syncId === syncId &&
    recovery.algorithm === "PBKDF2-SHA256/AES-GCM" &&
    kdf !== undefined &&
    kdf !== null &&
    typeof kdf === "object" &&
    kdf.name === "PBKDF2-SHA256" &&
    typeof kdf.iterations === "number" &&
    kdf.iterations >= 250_000 &&
    kdf.iterations <= 5_000_000 &&
    isBase64(kdf.salt) &&
    isBase64(recovery.iv) &&
    isBase64(recovery.ciphertext) &&
    isNonEmptyString(recovery.createdAt)
  )
}

const validatePutPayload = (value: unknown, accountId: string): value is PutSnapshotPayload => {
  if (value === null || typeof value !== "object") {
    return false
  }
  const payload = value as Record<string, unknown>
  return (
    payload.schemaVersion === SCHEMA_VERSION &&
    payload.syncId === accountId &&
    isNonEmptyString(payload.keyId) &&
    isNonEmptyString(payload.createdAt) &&
    validateEnvelope(payload.snapshot) &&
    validateRecovery(payload.recovery, accountId)
  )
}

const handlePutSnapshot = async (request: Request, env: Env, accountId: string): Promise<Response> => {
  const raw = await request.text()
  if (raw.length > MAX_BODY_BYTES) {
    return jsonResponse(413, { error: "payload too large" })
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return jsonResponse(400, { error: "payload is not valid JSON" })
  }
  if (containsForbiddenProperty(parsed)) {
    // Never store payloads that carry plaintext key material property names.
    return jsonResponse(400, { error: "payload contains forbidden plaintext-material properties" })
  }
  if (!validatePutPayload(parsed, accountId)) {
    return jsonResponse(400, { error: "payload is not a valid encrypted snapshot envelope" })
  }
  const payload = parsed
  const now = new Date().toISOString()
  // Whitelist re-serialization: only the validated envelope fields are ever
  // persisted; unknown extra properties in the request are dropped here.
  const snapshotJson = JSON.stringify({
    schemaVersion: payload.snapshot.schemaVersion,
    algorithm: payload.snapshot.algorithm,
    iv: payload.snapshot.iv,
    ciphertext: payload.snapshot.ciphertext
  })
  const recoveryJson = JSON.stringify({
    schemaVersion: payload.recovery.schemaVersion,
    keyId: payload.recovery.keyId,
    syncId: payload.recovery.syncId,
    algorithm: payload.recovery.algorithm,
    kdf: {
      name: payload.recovery.kdf.name,
      iterations: payload.recovery.kdf.iterations,
      salt: payload.recovery.kdf.salt
    },
    iv: payload.recovery.iv,
    ciphertext: payload.recovery.ciphertext,
    createdAt: payload.recovery.createdAt
  })
  const result = await env.DB.prepare(
    `INSERT OR REPLACE INTO sync_snapshots
       (account_id, schema_version, key_id, snapshot_json, recovery_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(accountId, payload.schemaVersion, payload.keyId, snapshotJson, recoveryJson, payload.createdAt, now)
    .run()
  if (!result.success) {
    return jsonResponse(500, { error: "failed to store the snapshot" })
  }
  return jsonResponse(200, { ok: true, syncId: accountId, updatedAt: now })
}

const handleGetSnapshot = async (env: Env, accountId: string): Promise<Response> => {
  const result = await env.DB.prepare(
    `SELECT account_id, schema_version, key_id, snapshot_json, recovery_json, created_at, updated_at
       FROM sync_snapshots WHERE account_id = ?`
  )
    .bind(accountId)
    .all<SyncSnapshotRow>()
  const row = result.results?.[0]
  if (!row) {
    return jsonResponse(404, { error: "no snapshot exists for this sync id" })
  }
  return jsonResponse(200, {
    schemaVersion: row.schema_version,
    syncId: row.account_id,
    keyId: row.key_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    snapshot: JSON.parse(row.snapshot_json),
    recovery: JSON.parse(row.recovery_json)
  })
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    const match = url.pathname.match(/^\/v1\/snapshots\/([^/]+)$/)
    if (!match) {
      return jsonResponse(404, { error: "not found" })
    }
    const unauthorized = authorize(request, env)
    if (unauthorized) {
      return unauthorized
    }
    const accountId = match[1] ?? ""
    if (!ACCOUNT_ID_PATTERN.test(accountId)) {
      return jsonResponse(400, { error: "invalid sync id" })
    }
    if (request.method === "PUT") {
      return handlePutSnapshot(request, env, accountId)
    }
    if (request.method === "GET") {
      return handleGetSnapshot(env, accountId)
    }
    return jsonResponse(405, { error: "method not allowed" })
  }
}
