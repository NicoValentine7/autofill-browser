import type { AutofillSettings, DomainPolicy, StoredProfile } from "@autofill-browser/autofill-core"

import { buildCloudWorkerUrl } from "./cloud-config"
import { normalizeGoogleAuthUser } from "./google-auth"
import type { SecureVaultRecoveryPackage, SecureVaultState } from "./secure-vault"
import type { GoogleAuthUser, RemoteAutofillRules, StorageSnapshot } from "./storage"

export type SyncField = "profile" | "settings" | "domainPolicies" | "secureVault"

const ALL_SYNC_FIELDS: SyncField[] = ["profile", "settings", "domainPolicies", "secureVault"]

export type SyncedSnapshot = {
  schemaVersion: 1
  profile: StoredProfile
  settings: AutofillSettings
  domainPolicies: Record<string, DomainPolicy>
  secureVault?: SecureVaultState
  secureVaultRecovery?: SecureVaultRecoveryPackage
  updatedAt: string
  revision?: number
  baseRevision?: number
  deviceId?: string
  changedFields?: SyncField[]
}

type AuthMeResponse = {
  user?: Partial<GoogleAuthUser>
}

type SyncSettingsResponse = {
  snapshot?: SyncedSnapshot | null
}

type SyncSaveResponse = {
  ok?: boolean
  updatedAt?: string
  revision?: number
  merged?: boolean
  snapshot?: SyncedSnapshot
  error?: string
}

type RemoteRulesResponse = {
  rules?: Partial<RemoteAutofillRules> | null
}

const jsonHeaders = {
  "content-type": "application/json"
}

export const buildWorkerUrl = (pathname: "/me" | "/me/settings" | "/me/rules") => buildCloudWorkerUrl(pathname)

const authedJsonFetch = async <T>(
  pathname: "/me" | "/me/settings" | "/me/rules",
  googleAccessToken: string,
  init: RequestInit = {}
) => {
  const url = buildWorkerUrl(pathname)

  const response = await fetch(url, {
    ...init,
    headers: {
      ...jsonHeaders,
      ...init.headers,
      authorization: `Bearer ${googleAccessToken}`
    }
  })

  if (!response.ok && response.status !== 409) {
    return {
      status: response.status,
      body: null
    }
  }

  return {
    status: response.status,
    body: (await response.json()) as T
  }
}

export const buildSyncedSnapshot = (snapshot: StorageSnapshot, changedFields: SyncField[] = ALL_SYNC_FIELDS): SyncedSnapshot => {
  const shouldSyncSecureVault = changedFields.includes("secureVault")

  return {
    schemaVersion: 1,
    profile: snapshot.profile,
    settings: snapshot.settings,
    domainPolicies: snapshot.domainPolicies,
    ...(shouldSyncSecureVault
      ? {
          secureVault: snapshot.secureVault,
          ...(snapshot.secureVaultRecovery ? { secureVaultRecovery: snapshot.secureVaultRecovery } : {})
        }
      : {}),
    updatedAt: new Date().toISOString(),
    baseRevision: snapshot.accountSync.lastRevision ?? 0,
    deviceId: snapshot.accountSync.deviceId,
    changedFields
  }
}

export const fetchSignedInUser = async (googleAccessToken: string) => {
  const response = await authedJsonFetch<AuthMeResponse>("/me", googleAccessToken)
  return response.body?.user ? normalizeGoogleAuthUser(response.body.user) : null
}

export const pushSyncedSnapshot = async (
  googleAccessToken: string,
  snapshot: StorageSnapshot,
  changedFields: SyncField[] = ALL_SYNC_FIELDS
) => {
  const response = await authedJsonFetch<SyncSaveResponse>("/me/settings", googleAccessToken, {
    method: "PUT",
    body: JSON.stringify(buildSyncedSnapshot(snapshot, changedFields))
  })
  const body = response.body

  if (response.status === 409 && body?.snapshot) {
    return {
      conflict: true as const,
      snapshot: body.snapshot
    }
  }

  if (!body?.ok || !body.updatedAt) {
    return null
  }

  return {
    ok: true as const,
    updatedAt: body.updatedAt,
    revision: body.revision ?? snapshot.accountSync.lastRevision ?? 0,
    merged: Boolean(body.merged)
  }
}

export const pullSyncedSnapshot = async (googleAccessToken: string) => {
  const response = await authedJsonFetch<SyncSettingsResponse>("/me/settings", googleAccessToken)
  return response.body?.snapshot ?? null
}

export const fetchRemoteRules = async (googleAccessToken: string): Promise<RemoteAutofillRules | null> => {
  const response = await authedJsonFetch<RemoteRulesResponse>("/me/rules", googleAccessToken)
  const rules = response.body?.rules

  if (!rules?.blockedIdentityTokens || !rules.updatedAt) {
    return null
  }

  return {
    schemaVersion: 1,
    blockedIdentityTokens: rules.blockedIdentityTokens.map((token) => token.trim().toLowerCase()).filter(Boolean),
    updatedAt: rules.updatedAt
  }
}
