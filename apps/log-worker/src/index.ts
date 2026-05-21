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
  CLOUD_LOG_INGEST_TOKEN?: string
  GOOGLE_OAUTH_CLIENT_ID?: string
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
  user_id: string | null
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

type UserRow = {
  id: string
  google_sub: string
  email: string
  name: string | null
  picture: string | null
  created_at: string
  updated_at: string
}

type AuthUser = {
  id: string
  googleSub: string
  email: string
  name?: string
  picture?: string
}

type AuthContext =
  | {
      type: "shared-token"
    }
  | {
      type: "google"
      user: AuthUser
    }

type SyncedSnapshot = {
  schemaVersion: 1
  profile: Record<string, string>
  settings: {
    enabled: boolean
    observeDynamicForms: boolean
    minMatchCount: number
  }
  domainPolicies: Record<string, "default" | "whitelist" | "blacklist">
  updatedAt: string
}

type SyncSnapshotRow = {
  user_id: string
  schema_version: number
  profile_json: string
  settings_json: string
  domain_policies_json: string
  updated_at: string
  raw_json: string
}

type GoogleTokenInfo = {
  aud?: unknown
  azp?: unknown
  sub?: unknown
  email?: unknown
  email_verified?: unknown
  name?: unknown
  picture?: unknown
}

const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
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

const getBearerToken = (request: Request) => {
  const authorization = request.headers.get("authorization") ?? ""
  return authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() ?? ""
}

const isSharedTokenAuthorized = async (actualToken: string, env: Env) => {
  const expectedToken = env.CLOUD_LOG_INGEST_TOKEN?.trim()

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
] as const

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

const toOptionalString = (value: unknown) => (typeof value === "string" && value.trim() ? value.trim() : undefined)

const isVerifiedEmail = (value: unknown) => value === true || value === "true"

const verifyGoogleToken = async (token: string, env: Env): Promise<Omit<AuthUser, "id"> | null> => {
  const expectedClientId = env.GOOGLE_OAUTH_CLIENT_ID?.trim()
  if (!token || !expectedClientId) {
    return null
  }

  let response: Response
  try {
    response = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`)
  } catch (_error) {
    return null
  }

  if (!response.ok) {
    return null
  }

  const tokenInfo = (await response.json()) as GoogleTokenInfo
  const aud = toOptionalString(tokenInfo.aud)
  const azp = toOptionalString(tokenInfo.azp)
  const googleSub = toOptionalString(tokenInfo.sub)
  const email = toOptionalString(tokenInfo.email)

  if (!googleSub || !email || !isVerifiedEmail(tokenInfo.email_verified)) {
    return null
  }

  if (aud !== expectedClientId && azp !== expectedClientId) {
    return null
  }

  return {
    googleSub,
    email,
    name: toOptionalString(tokenInfo.name),
    picture: toOptionalString(tokenInfo.picture)
  }
}

const upsertGoogleUser = async (env: Env, googleUser: Omit<AuthUser, "id">): Promise<AuthUser> => {
  const now = new Date().toISOString()
  const existing = await env.DB.prepare(
    `SELECT id, google_sub, email, name, picture, created_at, updated_at
     FROM users
     WHERE google_sub = ?
     LIMIT 1`
  )
    .bind(googleUser.googleSub)
    .all<UserRow>()
  const existingUser = existing.results?.[0]

  if (existingUser) {
    await env.DB.prepare(
      `UPDATE users
       SET email = ?, name = ?, picture = ?, updated_at = ?
       WHERE id = ?`
    )
      .bind(googleUser.email, googleUser.name ?? null, googleUser.picture ?? null, now, existingUser.id)
      .run()

    return {
      id: existingUser.id,
      googleSub: existingUser.google_sub,
      email: googleUser.email,
      name: googleUser.name,
      picture: googleUser.picture
    }
  }

  const id = crypto.randomUUID()
  await env.DB.prepare(
    `INSERT INTO users (id, google_sub, email, name, picture, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, googleUser.googleSub, googleUser.email, googleUser.name ?? null, googleUser.picture ?? null, now, now)
    .run()

  return {
    id,
    ...googleUser
  }
}

const authenticateRequest = async (request: Request, env: Env): Promise<AuthContext | null> => {
  const token = getBearerToken(request)

  if (await isSharedTokenAuthorized(token, env)) {
    return {
      type: "shared-token"
    }
  }

  const googleUser = await verifyGoogleToken(token, env)
  if (!googleUser) {
    return null
  }

  return {
    type: "google",
    user: await upsertGoogleUser(env, googleUser)
  }
}

const authenticateGoogleRequest = async (request: Request, env: Env): Promise<AuthContext | null> => {
  const token = getBearerToken(request)
  const googleUser = await verifyGoogleToken(token, env)

  if (!googleUser) {
    return null
  }

  return {
    type: "google",
    user: await upsertGoogleUser(env, googleUser)
  }
}

const authenticateAdminRequest = async (request: Request, env: Env): Promise<AuthContext | null> => {
  const token = getBearerToken(request)

  if (!(await isSharedTokenAuthorized(token, env))) {
    return null
  }

  return {
    type: "shared-token"
  }
}

const insertLogEvent = (env: Env, event: EventLogEntry, receivedAt: string, userId: string | null) =>
  env.DB.prepare(
    `INSERT OR REPLACE INTO event_logs (
      id,
      user_id,
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
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      event.id,
      userId,
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

const handlePostLogs = async (request: Request, env: Env, auth: AuthContext) => {
  const payload = await parseLogPayload(request)

  if (!payload) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  const receivedAt = new Date().toISOString()
  const userId = auth.type === "google" ? auth.user.id : null

  for (const event of payload.events) {
    await insertLogEvent(env, event, receivedAt, userId)
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

const handleGetLogs = async (request: Request, env: Env, auth: AuthContext) => {
  const url = new URL(request.url)
  const limit = normalizeLimit(url)
  const statement =
    auth.type === "google"
      ? env.DB.prepare(
          `SELECT
            id,
            user_id,
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
          WHERE user_id = ?
          ORDER BY received_at DESC, timestamp DESC
          LIMIT ?`
        ).bind(auth.user.id, limit)
      : env.DB.prepare(
    `SELECT
      id,
      user_id,
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
        ).bind(limit)
  const result = await statement.all<EventLogRow>()

  return json({
    logs: result.results ?? []
  })
}

const formatUserResponse = (user: AuthUser) => ({
  user: {
    sub: user.googleSub,
    email: user.email,
    name: user.name,
    picture: user.picture,
    signedInAt: new Date().toISOString()
  }
})

const isSyncedSnapshot = (value: unknown): value is SyncedSnapshot => {
  if (!isRecord(value) || value.schemaVersion !== 1 || !isRecord(value.profile) || !isRecord(value.settings)) {
    return false
  }

  const profile = value.profile
  const settings = value.settings
  const domainPolicies = value.domainPolicies

  return (
    requiredProfileKeys.every((key) => isString(profile[key])) &&
    typeof settings.enabled === "boolean" &&
    typeof settings.observeDynamicForms === "boolean" &&
    typeof settings.minMatchCount === "number" &&
    Number.isFinite(settings.minMatchCount) &&
    isRecord(domainPolicies) &&
    Object.values(domainPolicies).every((policy) => policy === "default" || policy === "whitelist" || policy === "blacklist") &&
    optionalString(value.updatedAt)
  )
}

const parseSyncPayload = async (request: Request) => {
  let body: unknown
  try {
    body = await request.json()
  } catch (_error) {
    return null
  }

  return isSyncedSnapshot(body) ? body : null
}

const handleGetAuthMe = (auth: AuthContext) => {
  if (auth.type !== "google") {
    return json({ error: "google auth required" }, { status: 403 })
  }

  return json(formatUserResponse(auth.user))
}

const handlePutSyncSettings = async (request: Request, env: Env, auth: AuthContext) => {
  if (auth.type !== "google") {
    return json({ error: "google auth required" }, { status: 403 })
  }

  const payload = await parseSyncPayload(request)
  if (!payload) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  const updatedAt = payload.updatedAt || new Date().toISOString()
  await env.DB.prepare(
    `INSERT OR REPLACE INTO user_sync_snapshots (
      user_id,
      schema_version,
      profile_json,
      settings_json,
      domain_policies_json,
      updated_at,
      raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      auth.user.id,
      payload.schemaVersion,
      JSON.stringify(payload.profile),
      JSON.stringify(payload.settings),
      JSON.stringify(payload.domainPolicies),
      updatedAt,
      JSON.stringify({
        ...payload,
        updatedAt
      })
    )
    .run()

  return json({
    ok: true,
    updatedAt
  })
}

const handleGetSyncSettings = async (env: Env, auth: AuthContext) => {
  if (auth.type !== "google") {
    return json({ error: "google auth required" }, { status: 403 })
  }

  const result = await env.DB.prepare(
    `SELECT user_id, schema_version, profile_json, settings_json, domain_policies_json, updated_at, raw_json
     FROM user_sync_snapshots
     WHERE user_id = ?
     LIMIT 1`
  )
    .bind(auth.user.id)
    .all<SyncSnapshotRow>()
  const row = result.results?.[0]

  if (!row) {
    return json({
      snapshot: null
    })
  }

  return json({
    snapshot: {
      schemaVersion: 1,
      profile: JSON.parse(row.profile_json),
      settings: JSON.parse(row.settings_json),
      domainPolicies: JSON.parse(row.domain_policies_json),
      updatedAt: row.updated_at
    }
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
  const googleRoutes = new Set(["/me", "/me/settings", "/me/events", "/auth/me", "/sync/settings"])
  const adminRoutes = new Set(["/admin/logs"])
  const legacyRoutes = new Set(["/logs"])

  if (![...googleRoutes, ...adminRoutes, ...legacyRoutes].includes(url.pathname)) {
    return json({ error: "not found" }, { status: 404 })
  }

  if (url.pathname === "/admin/logs") {
    const auth = await authenticateAdminRequest(request, env)
    if (!auth) {
      return json({ error: "unauthorized" }, { status: 401 })
    }

    if (request.method === "POST") {
      return handlePostLogs(request, env, auth)
    }

    if (request.method === "GET") {
      return handleGetLogs(request, env, auth)
    }

    return json({ error: "method not allowed" }, { status: 405 })
  }

  if (url.pathname === "/logs") {
    const auth = await authenticateRequest(request, env)
    if (!auth) {
      return json({ error: "unauthorized" }, { status: 401 })
    }

    if (request.method === "POST") {
      return handlePostLogs(request, env, auth)
    }

    if (request.method === "GET") {
      return handleGetLogs(request, env, auth)
    }

    return json({ error: "method not allowed" }, { status: 405 })
  }

  const auth = await authenticateGoogleRequest(request, env)
  if (!auth) {
    return json({ error: "unauthorized" }, { status: 401 })
  }

  if ((url.pathname === "/me" || url.pathname === "/auth/me") && request.method === "GET") {
    return handleGetAuthMe(auth)
  }

  if ((url.pathname === "/me/settings" || url.pathname === "/sync/settings") && request.method === "PUT") {
    return handlePutSyncSettings(request, env, auth)
  }

  if ((url.pathname === "/me/settings" || url.pathname === "/sync/settings") && request.method === "GET") {
    return handleGetSyncSettings(env, auth)
  }

  if (url.pathname === "/me/events" && request.method === "POST") {
    return handlePostLogs(request, env, auth)
  }

  if (url.pathname === "/me/events" && request.method === "GET") {
    return handleGetLogs(request, env, auth)
  }

  return json({ error: "method not allowed" }, { status: 405 })
}

export default {
  fetch(request: Request, env: Env) {
    return handleRequest(request, env)
  }
}
