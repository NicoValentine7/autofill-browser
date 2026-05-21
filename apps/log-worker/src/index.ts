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
  CLOUD_LOG_INGEST_TOKEN: string
}

type EventLogEntry = {
  id: string
  type: string
  timestamp: string
  hostname: string
  url: string
  fieldSignature?: string
  profileKey?: string
  previousValue?: string
  nextValue?: string
  source: string
  runId?: string
  detail?: string
}

type CloudLogPayload = {
  schemaVersion: 1
  source: "chrome-extension"
  emittedAt: string
  events: EventLogEntry[]
}

export type EventLogRow = {
  id: string
  timestamp: string
  type: string
  hostname: string
  url: string
  field_signature: string | null
  profile_key: string | null
  previous_value: string | null
  next_value: string | null
  source: string
  run_id: string | null
  detail: string | null
  received_at: string
  raw_json: string
}

const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type"
}

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: {
      ...jsonHeaders,
      ...init.headers
    }
  })

const textEncoder = new TextEncoder()

const digestToken = async (value: string) => crypto.subtle.digest("SHA-256", textEncoder.encode(value))

const constantTimeEqual = (left: ArrayBuffer, right: ArrayBuffer) => {
  const leftBytes = new Uint8Array(left)
  const rightBytes = new Uint8Array(right)
  let diff = leftBytes.length ^ rightBytes.length
  const maxLength = Math.max(leftBytes.length, rightBytes.length)

  for (let index = 0; index < maxLength; index += 1) {
    diff |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0)
  }

  return diff === 0
}

const isAuthorized = async (request: Request, env: Env) => {
  const expectedToken = env.CLOUD_LOG_INGEST_TOKEN?.trim()
  const authorization = request.headers.get("authorization") ?? ""
  const actualToken = authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() ?? ""

  if (!expectedToken || !actualToken) {
    return false
  }

  const [expectedDigest, actualDigest] = await Promise.all([digestToken(expectedToken), digestToken(actualToken)])
  return constantTimeEqual(expectedDigest, actualDigest)
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const isString = (value: unknown): value is string => typeof value === "string"

const optionalString = (value: unknown) => value === undefined || isString(value)

const isEventLogEntry = (value: unknown): value is EventLogEntry => {
  if (!isRecord(value)) {
    return false
  }

  return (
    isString(value.id) &&
    isString(value.type) &&
    isString(value.timestamp) &&
    isString(value.hostname) &&
    isString(value.url) &&
    isString(value.source) &&
    optionalString(value.fieldSignature) &&
    optionalString(value.profileKey) &&
    optionalString(value.previousValue) &&
    optionalString(value.nextValue) &&
    optionalString(value.runId) &&
    optionalString(value.detail)
  )
}

const isCloudLogPayload = (value: unknown): value is CloudLogPayload => {
  if (!isRecord(value)) {
    return false
  }

  return value.schemaVersion === 1 && value.source === "chrome-extension" && Array.isArray(value.events)
}

const parseLogPayload = async (request: Request) => {
  let body: unknown

  try {
    body = await request.json()
  } catch (_error) {
    return null
  }

  if (!isCloudLogPayload(body)) {
    return null
  }

  if (body.events.length === 0 || body.events.some((event) => !isEventLogEntry(event))) {
    return null
  }

  return body
}

const insertLogEvent = (env: Env, event: EventLogEntry, receivedAt: string) =>
  env.DB.prepare(
    `INSERT OR REPLACE INTO event_logs (
      id,
      timestamp,
      type,
      hostname,
      url,
      field_signature,
      profile_key,
      previous_value,
      next_value,
      source,
      run_id,
      detail,
      received_at,
      raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      event.id,
      event.timestamp,
      event.type,
      event.hostname,
      event.url,
      event.fieldSignature ?? null,
      event.profileKey ?? null,
      event.previousValue ?? null,
      event.nextValue ?? null,
      event.source,
      event.runId ?? null,
      event.detail ?? null,
      receivedAt,
      JSON.stringify(event)
    )
    .run()

const handlePostLogs = async (request: Request, env: Env) => {
  const payload = await parseLogPayload(request)

  if (!payload) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  const receivedAt = new Date().toISOString()

  for (const event of payload.events) {
    await insertLogEvent(env, event, receivedAt)
  }

  return json({
    ok: true,
    inserted: payload.events.length
  })
}

const normalizeLimit = (url: URL) => {
  const rawLimit = Number(url.searchParams.get("limit") ?? "50")
  if (!Number.isFinite(rawLimit)) {
    return 50
  }

  return Math.min(200, Math.max(1, Math.floor(rawLimit)))
}

const handleGetLogs = async (request: Request, env: Env) => {
  const url = new URL(request.url)
  const limit = normalizeLimit(url)
  const result = await env.DB.prepare(
    `SELECT
      id,
      timestamp,
      type,
      hostname,
      url,
      field_signature,
      profile_key,
      previous_value,
      next_value,
      source,
      run_id,
      detail,
      received_at,
      raw_json
    FROM event_logs
    ORDER BY received_at DESC, timestamp DESC
    LIMIT ?`
  )
    .bind(limit)
    .all<EventLogRow>()

  return json({
    logs: result.results ?? []
  })
}

const handleRequest = async (request: Request, env: Env) => {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: jsonHeaders
    })
  }

  const url = new URL(request.url)
  if (url.pathname !== "/logs") {
    return json({ error: "not found" }, { status: 404 })
  }

  if (!(await isAuthorized(request, env))) {
    return json({ error: "unauthorized" }, { status: 401 })
  }

  if (request.method === "POST") {
    return handlePostLogs(request, env)
  }

  if (request.method === "GET") {
    return handleGetLogs(request, env)
  }

  return json({ error: "method not allowed" }, { status: 405 })
}

export default {
  fetch(request: Request, env: Env) {
    return handleRequest(request, env)
  }
}
