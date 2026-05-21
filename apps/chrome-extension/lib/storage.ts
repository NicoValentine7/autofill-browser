import {
  DEFAULT_PROFILE,
  DEFAULT_AUTOFILL_SETTINGS,
  PROFILE_KEYS,
  buildFieldMemoryKey,
  createEmptyProfile,
  type AutofillEventSource,
  type AutofillSettings,
  type CloudLogSyncSettings,
  type DomainPolicy,
  type EventLogEntry,
  type FieldMemoryEntry,
  type StoredProfile
} from "@autofill-browser/autofill-core"

import { sendCloudLogSyncMessage } from "./messages"

const STORAGE_KEYS = {
  profile: "autofillProfile",
  settings: "autofillSettings",
  domainPolicies: "autofillDomainPolicies",
  fieldMemory: "autofillFieldMemory",
  eventLog: "autofillEventLog",
  googleAuthUser: "autofillGoogleAuthUser",
  accountSync: "autofillAccountSync"
} as const

const EVENT_LOG_LIMIT = 1000
export const DEFAULT_CHROME_CLOUD_LOG_ENDPOINT_URL = "https://autofill-browser-log-worker.y-elucidator.workers.dev/logs"

export type GoogleAuthUser = {
  sub: string
  email: string
  name?: string
  picture?: string
  signedInAt: string
}

export type AccountSyncState = {
  lastPulledAt?: string
  lastPushedAt?: string
  lastRemoteUpdatedAt?: string
}

export type StorageSnapshot = {
  profile: StoredProfile
  settings: AutofillSettings
  domainPolicies: Record<string, DomainPolicy>
  fieldMemory: Record<string, FieldMemoryEntry>
  eventLog: EventLogEntry[]
  googleAuthUser?: GoogleAuthUser
  accountSync: AccountSyncState
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
  eventEntries?: NewEventLogEntry[]
  googleAuthUser?: GoogleAuthUser | null
  accountSync?: AccountSyncState
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

const normalizeCloudLogSyncSettings = (settings?: Partial<CloudLogSyncSettings>): CloudLogSyncSettings => {
  const endpointUrl = settings?.endpointUrl?.trim() || DEFAULT_CHROME_CLOUD_LOG_ENDPOINT_URL

  return {
    endpointUrl,
    bearerToken: settings?.bearerToken?.trim() ?? DEFAULT_AUTOFILL_SETTINGS.cloudLogSync.bearerToken,
    includeFieldValues: settings?.includeFieldValues ?? DEFAULT_AUTOFILL_SETTINGS.cloudLogSync.includeFieldValues
  }
}

const normalizeSettings = (settings?: Partial<AutofillSettings>): AutofillSettings => ({
  enabled: settings?.enabled ?? DEFAULT_AUTOFILL_SETTINGS.enabled,
  observeDynamicForms: settings?.observeDynamicForms ?? DEFAULT_AUTOFILL_SETTINGS.observeDynamicForms,
  minMatchCount:
    settings?.minMatchCount && settings.minMatchCount > 0
      ? Math.max(1, Math.floor(settings.minMatchCount))
      : DEFAULT_AUTOFILL_SETTINGS.minMatchCount,
  cloudLogSync: normalizeCloudLogSyncSettings(settings?.cloudLogSync)
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
  lastPulledAt: state?.lastPulledAt?.trim() || undefined,
  lastPushedAt: state?.lastPushedAt?.trim() || undefined,
  lastRemoteUpdatedAt: state?.lastRemoteUpdatedAt?.trim() || undefined
})

const redactSettingsPatch = (settings: Partial<AutofillSettings>) => {
  const redactedSettings: Partial<AutofillSettings> = {
    ...settings
  }

  if (settings.cloudLogSync) {
    redactedSettings.cloudLogSync = {
      ...settings.cloudLogSync,
      bearerToken: settings.cloudLogSync.bearerToken ? "[configured]" : ""
    }
  }

  return JSON.stringify(redactedSettings)
}

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

export const getFieldMemoryKey = (hostname: string, fieldSignature: string) => buildFieldMemoryKey(hostname, fieldSignature)

export const getStorageSnapshot = async (): Promise<StorageSnapshot> => {
  const stored = await chrome.storage.local.get(Object.values(STORAGE_KEYS))
  const rawProfile = stored[STORAGE_KEYS.profile] as Partial<StoredProfile> | undefined
  const normalizedStoredProfile = normalizeProfile(rawProfile)
  const shouldSeedDefaultProfile = !rawProfile || !Object.values(normalizedStoredProfile).some((value) => value.trim().length > 0)

  return {
    profile: shouldSeedDefaultProfile ? { ...DEFAULT_PROFILE } : normalizedStoredProfile,
    settings: normalizeSettings(stored[STORAGE_KEYS.settings] as Partial<AutofillSettings> | undefined),
    domainPolicies: (stored[STORAGE_KEYS.domainPolicies] as Record<string, DomainPolicy> | undefined) ?? {},
    fieldMemory: (stored[STORAGE_KEYS.fieldMemory] as Record<string, FieldMemoryEntry> | undefined) ?? {},
    eventLog: sortAndTrimEvents((stored[STORAGE_KEYS.eventLog] as EventLogEntry[] | undefined) ?? []),
    googleAuthUser: normalizeGoogleAuthUser(stored[STORAGE_KEYS.googleAuthUser] as Partial<GoogleAuthUser> | undefined),
    accountSync: normalizeAccountSyncState(stored[STORAGE_KEYS.accountSync] as Partial<AccountSyncState> | undefined)
  }
}

export const commitStorageChanges = async (update: StorageUpdate): Promise<StorageSnapshot> => {
  const current = await getStorageSnapshot()
  const hasGoogleAuthUserUpdate = Object.prototype.hasOwnProperty.call(update, "googleAuthUser")
  const next: StorageSnapshot = {
    profile: update.profile ? normalizeProfile(update.profile) : current.profile,
    settings: update.settings ? normalizeSettings({ ...current.settings, ...update.settings }) : current.settings,
    domainPolicies: update.domainPolicies ? { ...update.domainPolicies } : current.domainPolicies,
    fieldMemory: { ...current.fieldMemory },
    eventLog: current.eventLog,
    googleAuthUser: hasGoogleAuthUserUpdate ? normalizeGoogleAuthUser(update.googleAuthUser) : current.googleAuthUser,
    accountSync: update.accountSync ? normalizeAccountSyncState({ ...current.accountSync, ...update.accountSync }) : current.accountSync
  }

  if (update.fieldMemoryUpdates) {
    for (const entry of update.fieldMemoryUpdates) {
      next.fieldMemory[getFieldMemoryKey(entry.hostname, entry.fieldSignature)] = entry
    }
  }

  const normalizedEventEntries =
    update.eventEntries && update.eventEntries.length > 0 ? normalizeEventEntries(update.eventEntries) : []

  if (normalizedEventEntries.length > 0) {
    next.eventLog = sortAndTrimEvents([...normalizedEventEntries, ...current.eventLog])
  }

  await chrome.storage.local.set({
    [STORAGE_KEYS.profile]: next.profile,
    [STORAGE_KEYS.settings]: next.settings,
    [STORAGE_KEYS.domainPolicies]: next.domainPolicies,
    [STORAGE_KEYS.fieldMemory]: next.fieldMemory,
    [STORAGE_KEYS.eventLog]: next.eventLog,
    [STORAGE_KEYS.googleAuthUser]: next.googleAuthUser ?? null,
    [STORAGE_KEYS.accountSync]: next.accountSync
  })

  if (normalizedEventEntries.length > 0) {
    void sendCloudLogSyncMessage(normalizedEventEntries, next.settings.cloudLogSync, Boolean(next.googleAuthUser))
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

export const saveAccountSyncState = async (accountSync: AccountSyncState) =>
  commitStorageChanges({
    accountSync
  })

export const applySyncedSnapshot = async (
  syncedSnapshot: Pick<StorageSnapshot, "profile" | "settings" | "domainPolicies">,
  remoteUpdatedAt?: string
) => {
  const current = await getStorageSnapshot()
  return commitStorageChanges({
    profile: syncedSnapshot.profile,
    settings: {
      ...syncedSnapshot.settings,
      cloudLogSync: {
        ...syncedSnapshot.settings.cloudLogSync,
        endpointUrl: current.settings.cloudLogSync.endpointUrl,
        bearerToken: current.settings.cloudLogSync.bearerToken
      }
    },
    domainPolicies: syncedSnapshot.domainPolicies,
    accountSync: {
      lastPulledAt: new Date().toISOString(),
      lastRemoteUpdatedAt: remoteUpdatedAt
    }
  })
}
