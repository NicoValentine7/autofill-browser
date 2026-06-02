import {
  DEFAULT_PROFILE,
  DEFAULT_AUTOFILL_SETTINGS,
  PROFILE_KEYS,
  buildFieldMemoryKey,
  createEmptyProfile,
  type AutofillEventSource,
  type AutofillSettings,
  type DomainPolicy,
  type EventLogEntry,
  type FieldMemoryEntry,
  type StoredProfile
} from "@autofill-browser/autofill-core"

import { sendCloudLogSyncMessage } from "./messages"
import {
  createSecureVaultKey,
  deleteSecureVaultValue,
  decryptSecureVaultValues,
  ensureSecureVaultKeyCheck,
  normalizeSecureVaultRecoveryPackage,
  normalizeSecureVaultKey,
  normalizeSecureVaultState,
  upsertSecureVaultValue,
  type SecureVaultKey,
  type SecureVaultRecoveryPackage,
  type SecureVaultState,
  type SecureVaultValueDelete,
  type SecureVaultValueUpdate
} from "./secure-vault"

const STORAGE_KEYS = {
  profile: "autofillProfile",
  settings: "autofillSettings",
  domainPolicies: "autofillDomainPolicies",
  fieldMemory: "autofillFieldMemory",
  secureVault: "autofillSecureVault",
  secureVaultKey: "autofillSecureVaultKey",
  secureVaultRecovery: "autofillSecureVaultRecovery",
  eventLog: "autofillEventLog",
  googleAuthUser: "autofillGoogleAuthUser",
  accountSync: "autofillAccountSync",
  remoteRules: "autofillRemoteRules"
} as const

const PERSISTED_STORAGE_KEYS = Object.values(STORAGE_KEYS)

const EVENT_LOG_LIMIT = 1000

export type GoogleAuthUser = {
  sub: string
  email: string
  name?: string
  picture?: string
  signedInAt: string
}

export type AccountSyncState = {
  deviceId?: string
  lastRevision?: number
  lastPulledAt?: string
  lastPushedAt?: string
  lastRemoteUpdatedAt?: string
}

export type RemoteAutofillRules = {
  schemaVersion: 1
  blockedIdentityTokens: string[]
  updatedAt: string
}

export type StorageSnapshot = {
  profile: StoredProfile
  settings: AutofillSettings
  domainPolicies: Record<string, DomainPolicy>
  fieldMemory: Record<string, FieldMemoryEntry>
  secureVault: SecureVaultState
  secureVaultKey?: SecureVaultKey
  secureVaultRecovery?: SecureVaultRecoveryPackage
  secureVaultValues: Record<string, string>
  eventLog: EventLogEntry[]
  googleAuthUser?: GoogleAuthUser
  accountSync: AccountSyncState
  remoteRules?: RemoteAutofillRules
}

export type EventContext = {
  hostname?: string
  url?: string
}

export type NewEventLogEntry = Omit<EventLogEntry, "id" | "timestamp">

type StorageUpdate = {
  profile?: StoredProfile
  settings?: Partial<AutofillSettings>
  domainPolicies?: Record<string, DomainPolicy>
  fieldMemoryUpdates?: FieldMemoryEntry[]
  fieldMemoryDeletes?: Array<{ hostname: string; fieldSignature: string }>
  secureVaultUpdates?: SecureVaultValueUpdate[]
  secureVaultDeletes?: SecureVaultValueDelete[]
  secureVault?: SecureVaultState
  secureVaultKey?: SecureVaultKey | null
  secureVaultRecovery?: SecureVaultRecoveryPackage | null
  eventEntries?: NewEventLogEntry[]
  googleAuthUser?: GoogleAuthUser | null
  accountSync?: Partial<AccountSyncState>
  remoteRules?: RemoteAutofillRules
}

const createEventId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`

const splitFullName = (fullName: string) => {
  const trimmed = fullName.trim()
  if (!trimmed) {
    return {
      familyName: "",
      givenName: ""
    }
  }

  const spaced = trimmed.split(/\s+/).filter(Boolean)
  if (spaced.length >= 2) {
    return {
      familyName: spaced[0],
      givenName: spaced.slice(1).join(" ")
    }
  }

  const compact = trimmed.replace(/\s+/g, "")
  const isJapaneseLike = /^[\p{sc=Han}\p{sc=Hiragana}\p{sc=Katakana}々ー]+$/u.test(compact)

  if (!isJapaneseLike) {
    return {
      familyName: "",
      givenName: ""
    }
  }

  if (compact.length === 2) {
    return {
      familyName: compact.charAt(0),
      givenName: compact.charAt(1)
    }
  }

  if (compact.length >= 3) {
    return {
      familyName: compact.slice(0, 2),
      givenName: compact.slice(2)
    }
  }

  return {
    familyName: "",
    givenName: ""
  }
}

const deriveCityFromAddressLine1 = (addressLine1: string) => {
  const trimmed = addressLine1.trim()
  if (!trimmed) {
    return ""
  }

  const matched = trimmed.match(/^(.+?)(\d[\d０-９\-−ー丁目番地].*)$/u)
  if (matched?.[1]) {
    return matched[1].trim()
  }

  return ""
}

const hydrateDerivedProfileValues = (profile: StoredProfile): StoredProfile => {
  const next = { ...profile }
  const splitName = splitFullName(next.fullName)

  if (!next.familyName && splitName.familyName) {
    next.familyName = splitName.familyName
  }

  if (!next.givenName && splitName.givenName) {
    next.givenName = splitName.givenName
  }

  if (!next.city) {
    next.city = deriveCityFromAddressLine1(next.addressLine1)
  }

  return next
}

const normalizeProfile = (profile?: Partial<StoredProfile>, fallbackProfile: StoredProfile = createEmptyProfile()): StoredProfile => {
  const next = { ...fallbackProfile }

  for (const key of PROFILE_KEYS) {
    next[key] = profile?.[key]?.trim() ?? ""
  }

  return hydrateDerivedProfileValues(next)
}

const normalizeSettings = (settings?: Partial<AutofillSettings>): AutofillSettings => ({
  enabled: settings?.enabled ?? DEFAULT_AUTOFILL_SETTINGS.enabled,
  observeDynamicForms: settings?.observeDynamicForms ?? DEFAULT_AUTOFILL_SETTINGS.observeDynamicForms,
  minMatchCount:
    settings?.minMatchCount && settings.minMatchCount > 0
      ? Math.max(1, Math.floor(settings.minMatchCount))
      : DEFAULT_AUTOFILL_SETTINGS.minMatchCount
})

const normalizeGoogleAuthUser = (user?: Partial<GoogleAuthUser> | null): GoogleAuthUser | undefined => {
  const sub = user?.sub?.trim()
  const email = user?.email?.trim()

  if (!sub || !email) {
    return undefined
  }

  return {
    sub,
    email,
    name: user?.name?.trim() || undefined,
    picture: user?.picture?.trim() || undefined,
    signedInAt: user?.signedInAt?.trim() || new Date().toISOString()
  }
}

const normalizeAccountSyncState = (state?: Partial<AccountSyncState>): AccountSyncState => ({
  deviceId: state?.deviceId?.trim() || createEventId(),
  lastRevision:
    typeof state?.lastRevision === "number" && Number.isFinite(state.lastRevision)
      ? Math.max(0, Math.floor(state.lastRevision))
      : 0,
  lastPulledAt: state?.lastPulledAt?.trim() || undefined,
  lastPushedAt: state?.lastPushedAt?.trim() || undefined,
  lastRemoteUpdatedAt: state?.lastRemoteUpdatedAt?.trim() || undefined
})

const normalizeRemoteRules = (rules?: Partial<RemoteAutofillRules>): RemoteAutofillRules => ({
  schemaVersion: 1,
  blockedIdentityTokens: Array.isArray(rules?.blockedIdentityTokens)
    ? [...new Set(rules.blockedIdentityTokens.map((token) => token.trim().toLowerCase()).filter(Boolean))]
    : [],
  updatedAt: rules?.updatedAt?.trim() || "1970-01-01T00:00:00.000Z"
})

const redactSettingsPatch = (settings: Partial<AutofillSettings>) => JSON.stringify(settings)

const normalizeEventEntries = (entries: NewEventLogEntry[]) =>
  entries.map(
    (entry): EventLogEntry => ({
      ...entry,
      id: createEventId(),
      timestamp: new Date().toISOString()
    })
  )

const sortAndTrimEvents = (entries: EventLogEntry[]) =>
  entries
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
    .slice(0, EVENT_LOG_LIMIT)

export const createUnavailableStorageSnapshot = (): StorageSnapshot => ({
  profile: createEmptyProfile(),
  settings: {
    ...DEFAULT_AUTOFILL_SETTINGS,
    enabled: false,
    observeDynamicForms: false
  },
  domainPolicies: {},
  fieldMemory: {},
  secureVault: normalizeSecureVaultState(),
  secureVaultValues: {},
  eventLog: [],
  accountSync: normalizeAccountSyncState()
})

const getSessionStorageArea = () => chrome.storage.session

const getSessionSecureVaultKey = async () => {
  try {
    const stored = await getSessionStorageArea().get(STORAGE_KEYS.secureVaultKey)
    return normalizeSecureVaultKey(stored[STORAGE_KEYS.secureVaultKey] as Partial<SecureVaultKey> | undefined)
  } catch (_error) {
    return undefined
  }
}

const saveSessionSecureVaultKey = async (secureVaultKey?: SecureVaultKey | null) => {
  try {
    await getSessionStorageArea().set({
      [STORAGE_KEYS.secureVaultKey]: secureVaultKey ?? null
    })
    return true
  } catch (_error) {
    return false
  }
}

const clearPersistedSecureVaultKey = async () => {
  await chrome.storage.local.set({
    [STORAGE_KEYS.secureVaultKey]: null
  })
}

export const getFieldMemoryKey = (hostname: string, fieldSignature: string) => buildFieldMemoryKey(hostname, fieldSignature)

export const getStorageSnapshot = async (): Promise<StorageSnapshot> => {
  const stored = await chrome.storage.local.get(PERSISTED_STORAGE_KEYS)
  const rawProfile = stored[STORAGE_KEYS.profile] as Partial<StoredProfile> | undefined
  const normalizedStoredProfile = normalizeProfile(rawProfile)
  const shouldSeedDefaultProfile = !rawProfile || !Object.values(normalizedStoredProfile).some((value) => value.trim().length > 0)
  const secureVault = normalizeSecureVaultState(stored[STORAGE_KEYS.secureVault] as Partial<SecureVaultState> | undefined)
  const persistedSecureVaultKey = normalizeSecureVaultKey(stored[STORAGE_KEYS.secureVaultKey] as Partial<SecureVaultKey> | undefined)
  let secureVaultKey = await getSessionSecureVaultKey()
  if (!secureVaultKey && persistedSecureVaultKey) {
    secureVaultKey = persistedSecureVaultKey
    if (await saveSessionSecureVaultKey(secureVaultKey)) {
      await clearPersistedSecureVaultKey()
    }
  }
  const secureVaultRecovery = normalizeSecureVaultRecoveryPackage(
    stored[STORAGE_KEYS.secureVaultRecovery] as Partial<SecureVaultRecoveryPackage> | undefined
  )

  return {
    profile: shouldSeedDefaultProfile ? { ...DEFAULT_PROFILE } : normalizedStoredProfile,
    settings: normalizeSettings(stored[STORAGE_KEYS.settings] as Partial<AutofillSettings> | undefined),
    domainPolicies: (stored[STORAGE_KEYS.domainPolicies] as Record<string, DomainPolicy> | undefined) ?? {},
    fieldMemory: (stored[STORAGE_KEYS.fieldMemory] as Record<string, FieldMemoryEntry> | undefined) ?? {},
    secureVault,
    secureVaultKey,
    secureVaultRecovery,
    secureVaultValues: await decryptSecureVaultValues(secureVault, secureVaultKey),
    eventLog: sortAndTrimEvents((stored[STORAGE_KEYS.eventLog] as EventLogEntry[] | undefined) ?? []),
    googleAuthUser: normalizeGoogleAuthUser(stored[STORAGE_KEYS.googleAuthUser] as Partial<GoogleAuthUser> | undefined),
    accountSync: normalizeAccountSyncState(stored[STORAGE_KEYS.accountSync] as Partial<AccountSyncState> | undefined),
    remoteRules: normalizeRemoteRules(stored[STORAGE_KEYS.remoteRules] as Partial<RemoteAutofillRules> | undefined)
  }
}

export const commitStorageChanges = async (update: StorageUpdate): Promise<StorageSnapshot> => {
  const current = await getStorageSnapshot()
  const hasGoogleAuthUserUpdate = Object.prototype.hasOwnProperty.call(update, "googleAuthUser")
  const hasSecureVaultUpdate = Object.prototype.hasOwnProperty.call(update, "secureVault")
  const hasSecureVaultKeyUpdate = Object.prototype.hasOwnProperty.call(update, "secureVaultKey")
  const hasSecureVaultRecoveryUpdate = Object.prototype.hasOwnProperty.call(update, "secureVaultRecovery")
  const hasSecureVaultValueUpdates = Boolean(update.secureVaultUpdates?.length)
  const hasSecureVaultDeletes = Boolean(update.secureVaultDeletes?.length)
  const next: StorageSnapshot = {
    profile: update.profile ? normalizeProfile(update.profile) : current.profile,
    settings: update.settings ? normalizeSettings({ ...current.settings, ...update.settings }) : current.settings,
    domainPolicies: update.domainPolicies ? { ...update.domainPolicies } : current.domainPolicies,
    fieldMemory: { ...current.fieldMemory },
    secureVault: update.secureVault ? normalizeSecureVaultState(update.secureVault) : current.secureVault,
    secureVaultKey: hasSecureVaultKeyUpdate ? normalizeSecureVaultKey(update.secureVaultKey) : current.secureVaultKey,
    secureVaultRecovery: hasSecureVaultRecoveryUpdate
      ? normalizeSecureVaultRecoveryPackage(update.secureVaultRecovery)
      : current.secureVaultRecovery,
    secureVaultValues: current.secureVaultValues,
    eventLog: current.eventLog,
    googleAuthUser: hasGoogleAuthUserUpdate ? normalizeGoogleAuthUser(update.googleAuthUser) : current.googleAuthUser,
    accountSync: update.accountSync ? normalizeAccountSyncState({ ...current.accountSync, ...update.accountSync }) : current.accountSync,
    remoteRules: update.remoteRules ? normalizeRemoteRules(update.remoteRules) : current.remoteRules
  }

  if (update.fieldMemoryUpdates) {
    for (const entry of update.fieldMemoryUpdates) {
      next.fieldMemory[getFieldMemoryKey(entry.hostname, entry.fieldSignature)] = entry
    }
  }

  if (update.fieldMemoryDeletes) {
    for (const entry of update.fieldMemoryDeletes) {
      delete next.fieldMemory[getFieldMemoryKey(entry.hostname, entry.fieldSignature)]
    }
  }

  if (update.secureVaultDeletes) {
    for (const secureVaultDelete of update.secureVaultDeletes) {
      next.secureVault = deleteSecureVaultValue(next.secureVault, secureVaultDelete)
    }
  }

  if (hasSecureVaultValueUpdates) {
    next.secureVaultKey = next.secureVaultKey ?? createSecureVaultKey()
    for (const secureVaultUpdate of update.secureVaultUpdates ?? []) {
      next.secureVault = await upsertSecureVaultValue(next.secureVault, next.secureVaultKey, secureVaultUpdate)
    }
  }

  if (
    next.secureVaultKey &&
    (hasSecureVaultUpdate || hasSecureVaultKeyUpdate || hasSecureVaultValueUpdates)
  ) {
    next.secureVault = await ensureSecureVaultKeyCheck(next.secureVault, next.secureVaultKey)
  }

  if (hasSecureVaultUpdate || hasSecureVaultKeyUpdate || hasSecureVaultValueUpdates || hasSecureVaultDeletes) {
    next.secureVaultValues = await decryptSecureVaultValues(next.secureVault, next.secureVaultKey)
  }

  const normalizedEventEntries =
    update.eventEntries && update.eventEntries.length > 0 ? normalizeEventEntries(update.eventEntries) : []

  if (normalizedEventEntries.length > 0) {
    next.eventLog = sortAndTrimEvents([...normalizedEventEntries, ...current.eventLog])
  }

  const shouldStoreSecureVaultKeyInSession = hasSecureVaultKeyUpdate || (update.secureVaultUpdates && update.secureVaultUpdates.length > 0)
  const storedSecureVaultKeyInSession = shouldStoreSecureVaultKeyInSession ? await saveSessionSecureVaultKey(next.secureVaultKey) : false

  await chrome.storage.local.set({
    [STORAGE_KEYS.profile]: next.profile,
    [STORAGE_KEYS.settings]: next.settings,
    [STORAGE_KEYS.domainPolicies]: next.domainPolicies,
    [STORAGE_KEYS.fieldMemory]: next.fieldMemory,
    [STORAGE_KEYS.secureVault]: next.secureVault,
    [STORAGE_KEYS.secureVaultKey]: shouldStoreSecureVaultKeyInSession && !storedSecureVaultKeyInSession ? (next.secureVaultKey ?? null) : null,
    [STORAGE_KEYS.secureVaultRecovery]: next.secureVaultRecovery ?? null,
    [STORAGE_KEYS.eventLog]: next.eventLog,
    [STORAGE_KEYS.googleAuthUser]: next.googleAuthUser ?? null,
    [STORAGE_KEYS.accountSync]: next.accountSync,
    [STORAGE_KEYS.remoteRules]: next.remoteRules
  })

  if (normalizedEventEntries.length > 0) {
    void sendCloudLogSyncMessage(normalizedEventEntries, Boolean(next.googleAuthUser))
  }

  return next
}

export const saveProfile = async (
  profile: StoredProfile,
  source: AutofillEventSource,
  context: EventContext = {}
) =>
  commitStorageChanges({
    profile,
    eventEntries: [
      {
        type: "profile_updated",
        hostname: context.hostname ?? "",
        url: context.url ?? "",
        source,
        detail: `configured:${Object.values(profile).filter(Boolean).length}`
      }
    ]
  })

export const saveSettings = async (
  settings: Partial<AutofillSettings>,
  source: AutofillEventSource,
  context: EventContext = {}
) =>
  commitStorageChanges({
    settings,
    eventEntries: [
      {
        type: "setting_changed",
        hostname: context.hostname ?? "",
        url: context.url ?? "",
        source,
        detail: redactSettingsPatch(settings)
      }
    ]
  })

export const saveDomainPolicy = async (
  hostname: string,
  policy: DomainPolicy,
  source: AutofillEventSource,
  currentDomainPolicies: Record<string, DomainPolicy>,
  context: EventContext = {}
) =>
  commitStorageChanges({
    domainPolicies: {
      ...currentDomainPolicies,
      [hostname]: policy
    },
    eventEntries: [
      {
        type: "domain_policy_changed",
        hostname,
        url: context.url ?? "",
        source,
        detail: policy
      }
    ]
  })

export const appendEventEntries = async (eventEntries: NewEventLogEntry[]) =>
  commitStorageChanges({
    eventEntries
  })

export const saveGoogleAuthUser = async (googleAuthUser: GoogleAuthUser) =>
  commitStorageChanges({
    googleAuthUser
  })

export const clearGoogleAuthUser = async () =>
  commitStorageChanges({
    googleAuthUser: null
  })

export const saveAccountSyncState = async (accountSync: Partial<AccountSyncState>) =>
  commitStorageChanges({
    accountSync
  })

export const saveRemoteRules = async (remoteRules: RemoteAutofillRules) =>
  commitStorageChanges({
    remoteRules
  })

export const saveSecureVaultRecoveryPackage = async (secureVaultRecovery: SecureVaultRecoveryPackage) =>
  commitStorageChanges({
    secureVaultRecovery
  })

export const saveSecureVaultKey = async (secureVaultKey: SecureVaultKey) =>
  commitStorageChanges({
    secureVaultKey
  })

export const applySyncedSnapshot = async (
  syncedSnapshot: Pick<StorageSnapshot, "profile" | "settings" | "domainPolicies"> & {
    secureVault?: SecureVaultState
    secureVaultRecovery?: SecureVaultRecoveryPackage
    updatedAt?: string
    revision?: number
  },
  remoteUpdatedAt?: string
) =>
  commitStorageChanges({
    profile: syncedSnapshot.profile,
    settings: syncedSnapshot.settings,
    domainPolicies: syncedSnapshot.domainPolicies,
    ...(syncedSnapshot.secureVault ? { secureVault: syncedSnapshot.secureVault } : {}),
    ...(syncedSnapshot.secureVaultRecovery ? { secureVaultRecovery: syncedSnapshot.secureVaultRecovery } : {}),
    accountSync: {
      lastPulledAt: new Date().toISOString(),
      lastRemoteUpdatedAt: remoteUpdatedAt ?? syncedSnapshot.updatedAt,
      lastRevision: syncedSnapshot.revision ?? 0
    }
  })
