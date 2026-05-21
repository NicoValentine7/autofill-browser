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
  CLOUD_DATA_ENCRYPTION_KEY?: string
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

type SyncField = "profile" | "settings" | "domainPolicies"

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
  revision?: number
  baseRevision?: number
  deviceId?: string
  changedFields?: SyncField[]
}

type SyncSnapshotRow = {
  user_id: string
  schema_version: number
  profile_json: string
  settings_json: string
  domain_policies_json: string
  updated_at: string
  raw_json: string
  revision?: number | null
  device_id?: string | null
  changed_fields_json?: string | null
  encryption_version?: number | null
}

type RemoteRules = {
  schemaVersion: 1
  blockedIdentityTokens: string[]
  updatedAt: string
}

type RemoteRulesRow = {
  key: string
  schema_version: number
  blocked_identity_tokens_json: string
  updated_at: string
}

type LogAnalysisReport = {
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
const textDecoder = new TextDecoder()

const SYNC_FIELDS = ["profile", "settings", "domainPolicies"] as const

const DEFAULT_REMOTE_BLOCKED_IDENTITY_TOKENS = [
  "security code",
  "secure code",
  "verify code",
  "verification number",
  "auth code",
  "認証コード",
  "確認コード"
]

const RISKY_LOG_TOKENS = [
  "captcha",
  "recaptcha",
  "h-captcha",
  "apbct",
  "honeypot",
  "csrf",
  "token",
  "otp",
  "one-time-code",
  "verification",
  "password",
  "username"
]

const digestToken = async (value: string) => crypto.subtle.digest("SHA-256", textEncoder.encode(value))

const bytesToBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

const base64ToBytes = (value: string) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0))

const getEncryptionSecret = (env: Env) => env.CLOUD_DATA_ENCRYPTION_KEY?.trim() ?? ""

const getEncryptionKey = async (env: Env) => {
  const secret = getEncryptionSecret(env)
  if (!secret) {
    return null
  }

  return crypto.subtle.importKey("raw", await digestToken(secret), "AES-GCM", false, ["encrypt", "decrypt"])
}

const isEncryptedEnvelope = (value: unknown): value is { encrypted: true; version: 1; alg: "AES-GCM"; iv: string; data: string } =>
  isRecord(value) &&
  value.encrypted === true &&
  value.version === 1 &&
  value.alg === "AES-GCM" &&
  isString(value.iv) &&
  isString(value.data)

const encryptText = async (env: Env, value: string) => {
  const key = await getEncryptionKey(env)
  if (!key) {
    return null
  }

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    textEncoder.encode(value)
  )

  return JSON.stringify({
    encrypted: true,
    version: 1,
    alg: "AES-GCM",
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  })
}

const decryptText = async (env: Env, storedValue: string) => {
  let parsed: unknown
  try {
    parsed = JSON.parse(storedValue)
  } catch (_error) {
    return storedValue
  }

  if (!isEncryptedEnvelope(parsed)) {
    return storedValue
  }

  const key = await getEncryptionKey(env)
  if (!key) {
    return null
  }

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(parsed.iv)
      },
      key,
      base64ToBytes(parsed.data)
    )
    return textDecoder.decode(decrypted)
  } catch (_error) {
    return null
  }
}

const encryptJson = async (env: Env, value: unknown) => encryptText(env, JSON.stringify(value))

const decryptJson = async <T>(env: Env, storedValue: string): Promise<T | null> => {
  const decrypted = await decryptText(env, storedValue)
  if (!decrypted) {
    return null
  }

  try {
    return JSON.parse(decrypted) as T
  } catch (_error) {
    return null
  }
}

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

const encryptRequiredText = async (env: Env, value: string) => {
  const encrypted = await encryptText(env, value)
  if (!encrypted) {
    throw new Error("encryption key is not configured")
  }
  return encrypted
}

const encryptOptionalText = async (env: Env, value: string | undefined) =>
  typeof value === "string" ? encryptRequiredText(env, value) : null

const decryptOptionalText = async (env: Env, value: string | null) => {
  if (value === null) {
    return null
  }

  return decryptText(env, value)
}

const insertLogEvent = async (env: Env, event: EventLogEntry, receivedAt: string, userId: string | null) => {
  const previousValue = await encryptOptionalText(env, event.previousValue)
  const nextValue = await encryptOptionalText(env, event.nextValue)
  const rawEvent = {
    ...event,
    previousValue: typeof event.previousValue === "string" ? "[encrypted]" : undefined,
    nextValue: typeof event.nextValue === "string" ? "[encrypted]" : undefined
  }

  return env.DB.prepare(
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
      previousValue,
      nextValue,
      event.source,
      event.runId ?? null,
      event.detail ?? null,
      receivedAt,
      JSON.stringify(rawEvent)
    )
    .run()
}

const handlePostLogs = async (request: Request, env: Env, auth: AuthContext) => {
  const payload = await parseLogPayload(request)

  if (!payload) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  const receivedAt = new Date().toISOString()
  const userId = auth.type === "google" ? auth.user.id : null

  try {
    for (const event of payload.events) {
      await insertLogEvent(env, event, receivedAt, userId)
    }
  } catch (_error) {
    return json({ error: "encryption key is not configured" }, { status: 500 })
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

const formatLogRow = async (env: Env, row: EventLogRow): Promise<EventLogRow> => ({
  ...row,
  previous_value: await decryptOptionalText(env, row.previous_value),
  next_value: await decryptOptionalText(env, row.next_value)
})

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
  const logs = await Promise.all((result.results ?? []).map((row) => formatLogRow(env, row)))

  return json({
    logs
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
    optionalString(value.updatedAt) &&
    optionalString(value.deviceId) &&
    (value.revision === undefined || (typeof value.revision === "number" && Number.isFinite(value.revision))) &&
    (value.baseRevision === undefined || (typeof value.baseRevision === "number" && Number.isFinite(value.baseRevision))) &&
    (value.changedFields === undefined ||
      (Array.isArray(value.changedFields) && value.changedFields.every((field) => SYNC_FIELDS.includes(field as SyncField))))
  )
}

const normalizeRevision = (value: unknown) => (typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0)

const normalizeChangedFields = (fields: unknown): SyncField[] => {
  if (!Array.isArray(fields)) {
    return [...SYNC_FIELDS]
  }

  const normalized = fields.filter((field): field is SyncField => SYNC_FIELDS.includes(field as SyncField))
  return normalized.length > 0 ? [...new Set(normalized)] : [...SYNC_FIELDS]
}

const parseChangedFieldsJson = (value: string | null | undefined) => {
  try {
    return normalizeChangedFields(value ? JSON.parse(value) : undefined)
  } catch (_error) {
    return [...SYNC_FIELDS]
  }
}

const getSyncSnapshotRow = async (env: Env, userId: string) => {
  const result = await env.DB.prepare(
    `SELECT
       user_id,
       schema_version,
       profile_json,
       settings_json,
       domain_policies_json,
       updated_at,
       raw_json,
       revision,
       device_id,
       changed_fields_json,
       encryption_version
     FROM user_sync_snapshots
     WHERE user_id = ?
     LIMIT 1`
  )
    .bind(userId)
    .all<SyncSnapshotRow>()

  return result.results?.[0] ?? null
}

const decodeSyncSnapshotRow = async (env: Env, row: SyncSnapshotRow): Promise<SyncedSnapshot | null> => {
  const profile = await decryptJson<Record<string, string>>(env, row.profile_json)
  if (!profile) {
    return null
  }

  return {
    schemaVersion: 1,
    profile,
    settings: JSON.parse(row.settings_json),
    domainPolicies: JSON.parse(row.domain_policies_json),
    updatedAt: row.updated_at,
    revision: normalizeRevision(row.revision),
    deviceId: row.device_id ?? undefined,
    changedFields: parseChangedFieldsJson(row.changed_fields_json)
  }
}

const mergeSnapshots = (remoteSnapshot: SyncedSnapshot, localSnapshot: SyncedSnapshot, changedFields: SyncField[]): SyncedSnapshot => ({
  ...remoteSnapshot,
  profile: changedFields.includes("profile") ? localSnapshot.profile : remoteSnapshot.profile,
  settings: changedFields.includes("settings") ? localSnapshot.settings : remoteSnapshot.settings,
  domainPolicies: changedFields.includes("domainPolicies") ? localSnapshot.domainPolicies : remoteSnapshot.domainPolicies,
  updatedAt: localSnapshot.updatedAt || new Date().toISOString(),
  deviceId: localSnapshot.deviceId,
  changedFields
})

const storeSyncSnapshot = async (
  env: Env,
  userId: string,
  payload: SyncedSnapshot,
  updatedAt: string,
  revision: number,
  changedFields: SyncField[]
) => {
  const encryptedProfile = await encryptJson(env, payload.profile)
  if (!encryptedProfile) {
    return false
  }

  await env.DB.prepare(
    `INSERT OR REPLACE INTO user_sync_snapshots (
      user_id,
      schema_version,
      profile_json,
      settings_json,
      domain_policies_json,
      updated_at,
      raw_json,
      revision,
      device_id,
      changed_fields_json,
      encryption_version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      userId,
      payload.schemaVersion,
      encryptedProfile,
      JSON.stringify(payload.settings),
      JSON.stringify(payload.domainPolicies),
      updatedAt,
      JSON.stringify({
        schemaVersion: payload.schemaVersion,
        profileEncrypted: true,
        settings: payload.settings,
        domainPolicies: payload.domainPolicies,
        updatedAt,
        revision,
        deviceId: payload.deviceId,
        changedFields
      }),
      revision,
      payload.deviceId ?? null,
      JSON.stringify(changedFields),
      1
    )
    .run()

  return true
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

  const existingRow = await getSyncSnapshotRow(env, auth.user.id)
  const existingRevision = normalizeRevision(existingRow?.revision)
  const baseRevision = normalizeRevision(payload.baseRevision)
  const changedFields = normalizeChangedFields(payload.changedFields)
  const updatedAt = payload.updatedAt || new Date().toISOString()
  let snapshotToStore = payload
  let merged = false

  if (existingRow && baseRevision < existingRevision && payload.deviceId !== existingRow.device_id) {
    const remoteSnapshot = await decodeSyncSnapshotRow(env, existingRow)
    if (!remoteSnapshot) {
      return json({ error: "could not decrypt current snapshot" }, { status: 500 })
    }

    const remoteChangedFields = parseChangedFieldsJson(existingRow.changed_fields_json)
    const hasOverlappingChange = changedFields.some((field) => remoteChangedFields.includes(field))

    if (hasOverlappingChange) {
      return json(
        {
          error: "sync conflict",
          snapshot: remoteSnapshot,
          revision: existingRevision
        },
        { status: 409 }
      )
    }

    snapshotToStore = mergeSnapshots(remoteSnapshot, payload, changedFields)
    merged = true
  }

  const revision = existingRevision + 1
  const stored = await storeSyncSnapshot(env, auth.user.id, snapshotToStore, updatedAt, revision, changedFields)
  if (!stored) {
    return json({ error: "encryption key is not configured" }, { status: 500 })
  }

  return json({
    ok: true,
    updatedAt,
    revision,
    merged
  })
}

const handleGetSyncSettings = async (env: Env, auth: AuthContext) => {
  if (auth.type !== "google") {
    return json({ error: "google auth required" }, { status: 403 })
  }

  const row = await getSyncSnapshotRow(env, auth.user.id)

  if (!row) {
    return json({
      snapshot: null
    })
  }

  const snapshot = await decodeSyncSnapshotRow(env, row)
  if (!snapshot) {
    return json({ error: "could not decrypt current snapshot" }, { status: 500 })
  }

  return json({
    snapshot
  })
}

const normalizeRemoteRuleTokens = (value: unknown) => {
  if (!Array.isArray(value)) {
    return [...DEFAULT_REMOTE_BLOCKED_IDENTITY_TOKENS]
  }

  const tokens = value
    .filter(isString)
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean)

  return [...new Set(tokens)]
}

const getRemoteRules = async (env: Env): Promise<RemoteRules> => {
  const result = await env.DB.prepare(
    `SELECT key, schema_version, blocked_identity_tokens_json, updated_at
     FROM remote_rules
     WHERE key = ?
     LIMIT 1`
  )
    .bind("global")
    .all<RemoteRulesRow>()
  const row = result.results?.[0]

  if (!row) {
    return {
      schemaVersion: 1,
      blockedIdentityTokens: normalizeRemoteRuleTokens(DEFAULT_REMOTE_BLOCKED_IDENTITY_TOKENS),
      updatedAt: "1970-01-01T00:00:00.000Z"
    }
  }

  return {
    schemaVersion: 1,
    blockedIdentityTokens: normalizeRemoteRuleTokens(JSON.parse(row.blocked_identity_tokens_json)),
    updatedAt: row.updated_at
  }
}

const handleGetRemoteRules = async (env: Env) => json({ rules: await getRemoteRules(env) })

const handlePutAdminRules = async (request: Request, env: Env) => {
  let body: unknown
  try {
    body = await request.json()
  } catch (_error) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  if (!isRecord(body)) {
    return json({ error: "malformed payload" }, { status: 400 })
  }

  const blockedIdentityTokens = normalizeRemoteRuleTokens(body.blockedIdentityTokens)
  const updatedAt = optionalString(body.updatedAt) && body.updatedAt ? body.updatedAt : new Date().toISOString()

  await env.DB.prepare(
    `INSERT OR REPLACE INTO remote_rules (
      key,
      schema_version,
      blocked_identity_tokens_json,
      updated_at
    ) VALUES (?, ?, ?, ?)`
  )
    .bind("global", 1, JSON.stringify(blockedIdentityTokens), updatedAt)
    .run()

  return json({
    ok: true,
    rules: {
      schemaVersion: 1,
      blockedIdentityTokens,
      updatedAt
    }
  })
}

const countBy = (values: string[]) => {
  const counts = new Map<string, number>()
  for (const value of values) {
    const trimmed = value.trim()
    if (trimmed) {
      counts.set(trimmed, (counts.get(trimmed) ?? 0) + 1)
    }
  }

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 5)
    .map(([value, count]) => ({ value, count }))
}

const selectLogsForAnalysis = async (env: Env, userId: string | null, windowStartedAt: string) => {
  const statement = userId
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
        WHERE user_id = ? AND received_at >= ?
        ORDER BY received_at DESC, timestamp DESC
        LIMIT ?`
      ).bind(userId, windowStartedAt, 1000)
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
        WHERE received_at >= ?
        ORDER BY received_at DESC, timestamp DESC
        LIMIT ?`
      ).bind(windowStartedAt, 1000)

  const result = await statement.all<EventLogRow>()
  return result.results ?? []
}

const isRiskyLogRow = (row: EventLogRow) => {
  const identity = [row.field_signature, row.profile_key, row.detail, row.raw_json].filter(Boolean).join(" ").toLowerCase()
  return RISKY_LOG_TOKENS.some((token) => identity.includes(token))
}

const buildAnalysisNotes = (rows: EventLogRow[], riskyEventCount: number, correctionCount: number) => {
  const notes: string[] = []
  if (riskyEventCount > 0) {
    notes.push("risky-field-like events were seen")
  }
  if (correctionCount > 0) {
    notes.push("user corrections were seen")
  }
  if (rows.length === 0) {
    notes.push("no events in the analysis window")
  }
  return notes
}

const storeAnalysisReport = async (env: Env, report: LogAnalysisReport) => {
  await env.DB.prepare(
    `INSERT OR REPLACE INTO log_analysis_reports (
      id,
      scope_user_id,
      window_started_at,
      window_ended_at,
      total_events,
      field_filled_count,
      correction_count,
      risky_event_count,
      top_hostnames_json,
      top_profile_keys_json,
      notes_json,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      report.id,
      report.scope_user_id,
      report.window_started_at,
      report.window_ended_at,
      report.total_events,
      report.field_filled_count,
      report.correction_count,
      report.risky_event_count,
      report.top_hostnames_json,
      report.top_profile_keys_json,
      report.notes_json,
      report.created_at
    )
    .run()
}

const runLogAnalysis = async (env: Env, userId: string | null = null) => {
  const windowEndedAt = new Date().toISOString()
  const windowStartedAt = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  const rows = await selectLogsForAnalysis(env, userId, windowStartedAt)
  const fieldFilledCount = rows.filter((row) => row.type === "field_filled").length
  const correctionCount = rows.filter((row) => row.type === "field_corrected_by_user").length
  const riskyEventCount = rows.filter(isRiskyLogRow).length
  const report: LogAnalysisReport = {
    id: `${userId ?? "global"}:${windowEndedAt.slice(0, 10)}`,
    scope_user_id: userId,
    window_started_at: windowStartedAt,
    window_ended_at: windowEndedAt,
    total_events: rows.length,
    field_filled_count: fieldFilledCount,
    correction_count: correctionCount,
    risky_event_count: riskyEventCount,
    top_hostnames_json: JSON.stringify(countBy(rows.map((row) => row.hostname))),
    top_profile_keys_json: JSON.stringify(countBy(rows.map((row) => row.profile_key ?? ""))),
    notes_json: JSON.stringify(buildAnalysisNotes(rows, riskyEventCount, correctionCount)),
    created_at: windowEndedAt
  }

  await storeAnalysisReport(env, report)
  return report
}

const getAnalysisReports = async (env: Env, userId: string | null, limit: number) => {
  const statement = userId
    ? env.DB.prepare(
        `SELECT
          id,
          scope_user_id,
          window_started_at,
          window_ended_at,
          total_events,
          field_filled_count,
          correction_count,
          risky_event_count,
          top_hostnames_json,
          top_profile_keys_json,
          notes_json,
          created_at
        FROM log_analysis_reports
        WHERE scope_user_id = ?
        ORDER BY created_at DESC
        LIMIT ?`
      ).bind(userId, limit)
    : env.DB.prepare(
        `SELECT
          id,
          scope_user_id,
          window_started_at,
          window_ended_at,
          total_events,
          field_filled_count,
          correction_count,
          risky_event_count,
          top_hostnames_json,
          top_profile_keys_json,
          notes_json,
          created_at
        FROM log_analysis_reports
        WHERE scope_user_id IS NULL
        ORDER BY created_at DESC
        LIMIT ?`
      ).bind(limit)

  const result = await statement.all<LogAnalysisReport>()
  return result.results ?? []
}

const formatAnalysisReport = (report: LogAnalysisReport) => ({
  id: report.id,
  scopeUserId: report.scope_user_id,
  windowStartedAt: report.window_started_at,
  windowEndedAt: report.window_ended_at,
  totalEvents: report.total_events,
  fieldFilledCount: report.field_filled_count,
  correctionCount: report.correction_count,
  riskyEventCount: report.risky_event_count,
  topHostnames: JSON.parse(report.top_hostnames_json),
  topProfileKeys: JSON.parse(report.top_profile_keys_json),
  notes: JSON.parse(report.notes_json),
  createdAt: report.created_at
})

const handleGetLogAnalysis = async (request: Request, env: Env, auth: AuthContext) => {
  const url = new URL(request.url)
  const limit = normalizeLimit(url)
  const userId = auth.type === "google" ? auth.user.id : null

  await runLogAnalysis(env, userId)
  const reports = await getAnalysisReports(env, userId, limit)

  return json({
    reports: reports.map(formatAnalysisReport)
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
  const googleRoutes = new Set(["/me", "/me/settings", "/me/events", "/me/rules", "/me/log-analysis", "/auth/me", "/sync/settings"])
  const adminRoutes = new Set(["/admin/logs", "/admin/rules", "/admin/log-analysis"])
  const legacyRoutes = new Set(["/logs"])

  if (![...googleRoutes, ...adminRoutes, ...legacyRoutes].includes(url.pathname)) {
    return json({ error: "not found" }, { status: 404 })
  }

  if (adminRoutes.has(url.pathname)) {
    const auth = await authenticateAdminRequest(request, env)
    if (!auth) {
      return json({ error: "unauthorized" }, { status: 401 })
    }

    if (url.pathname === "/admin/logs" && request.method === "POST") {
      return handlePostLogs(request, env, auth)
    }

    if (url.pathname === "/admin/logs" && request.method === "GET") {
      return handleGetLogs(request, env, auth)
    }

    if (url.pathname === "/admin/rules" && request.method === "PUT") {
      return handlePutAdminRules(request, env)
    }

    if (url.pathname === "/admin/rules" && request.method === "GET") {
      return handleGetRemoteRules(env)
    }

    if (url.pathname === "/admin/log-analysis" && request.method === "GET") {
      return handleGetLogAnalysis(request, env, auth)
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

  if (url.pathname === "/me/rules" && request.method === "GET") {
    return handleGetRemoteRules(env)
  }

  if (url.pathname === "/me/log-analysis" && request.method === "GET") {
    return handleGetLogAnalysis(request, env, auth)
  }

  return json({ error: "method not allowed" }, { status: 405 })
}

export default {
  fetch(request: Request, env: Env) {
    return handleRequest(request, env)
  },
  scheduled(_controller: { cron?: string; scheduledTime?: number }, env: Env, ctx: { waitUntil(promise: Promise<unknown>): void }) {
    ctx.waitUntil(runLogAnalysis(env))
  }
}
