import type { AutofillSettings, DomainPolicy, StoredProfile } from "@autofill-browser/autofill-core"

import { buildCloudWorkerUrl } from "./cloud-config"
import { normalizeGoogleAuthUser } from "./google-auth"
import type { GoogleAuthUser, StorageSnapshot } from "./storage"

export type SyncedSnapshot = {
  schemaVersion: 1
  profile: StoredProfile
  settings: AutofillSettings
  domainPolicies: Record<string, DomainPolicy>
  updatedAt: string
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
}

const jsonHeaders = {
  "content-type": "application/json"
}

export const buildWorkerUrl = (pathname: "/me" | "/me/settings") => buildCloudWorkerUrl(pathname)

const authedJsonFetch = async <T>(
  pathname: "/me" | "/me/settings",
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

  if (!response.ok) {
    return null
  }

  return (await response.json()) as T
}

export const buildSyncedSnapshot = (snapshot: StorageSnapshot): SyncedSnapshot => ({
  schemaVersion: 1,
  profile: snapshot.profile,
  settings: snapshot.settings,
  domainPolicies: snapshot.domainPolicies,
  updatedAt: new Date().toISOString()
})

export const fetchSignedInUser = async (googleAccessToken: string) => {
  const body = await authedJsonFetch<AuthMeResponse>("/me", googleAccessToken)
  return body?.user ? normalizeGoogleAuthUser(body.user) : null
}

export const pushSyncedSnapshot = async (googleAccessToken: string, snapshot: StorageSnapshot) => {
  const body = await authedJsonFetch<SyncSaveResponse>("/me/settings", googleAccessToken, {
    method: "PUT",
    body: JSON.stringify(buildSyncedSnapshot(snapshot))
  })

  if (!body?.ok) {
    return null
  }

  return body.updatedAt ?? new Date().toISOString()
}

export const pullSyncedSnapshot = async (googleAccessToken: string) => {
  const body = await authedJsonFetch<SyncSettingsResponse>("/me/settings", googleAccessToken)
  return body?.snapshot ?? null
}
