import type { AutofillSettings, DomainPolicy, StoredProfile } from "@autofill-browser/autofill-core"

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

export const buildWorkerUrl = (endpointUrl: string, pathname: "/auth/me" | "/sync/settings") => {
  const trimmedEndpoint = endpointUrl.trim()

  if (!trimmedEndpoint) {
    return null
  }

  try {
    const url = new URL(trimmedEndpoint)
    if (url.protocol !== "https:") {
      return null
    }

    const pathWithoutTrailingSlash = url.pathname.replace(/\/+$/u, "")
    const basePath = pathWithoutTrailingSlash.endsWith("/logs")
      ? pathWithoutTrailingSlash.slice(0, -"/logs".length)
      : pathWithoutTrailingSlash
    url.pathname = `${basePath}${pathname}` || pathname
    url.search = ""
    url.hash = ""
    return url.toString()
  } catch (_error) {
    return null
  }
}

const authedJsonFetch = async <T>(
  endpointUrl: string,
  pathname: "/auth/me" | "/sync/settings",
  googleAccessToken: string,
  init: RequestInit = {}
) => {
  const url = buildWorkerUrl(endpointUrl, pathname)

  if (!url) {
    return null
  }

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
  settings: {
    ...snapshot.settings,
    cloudLogSync: {
      endpointUrl: "",
      bearerToken: "",
      includeFieldValues: snapshot.settings.cloudLogSync.includeFieldValues
    }
  },
  domainPolicies: snapshot.domainPolicies,
  updatedAt: new Date().toISOString()
})

export const fetchSignedInUser = async (endpointUrl: string, googleAccessToken: string) => {
  const body = await authedJsonFetch<AuthMeResponse>(endpointUrl, "/auth/me", googleAccessToken)
  return body?.user ? normalizeGoogleAuthUser(body.user) : null
}

export const pushSyncedSnapshot = async (endpointUrl: string, googleAccessToken: string, snapshot: StorageSnapshot) => {
  const body = await authedJsonFetch<SyncSaveResponse>(endpointUrl, "/sync/settings", googleAccessToken, {
    method: "PUT",
    body: JSON.stringify(buildSyncedSnapshot(snapshot))
  })

  if (!body?.ok) {
    return null
  }

  return body.updatedAt ?? new Date().toISOString()
}

export const pullSyncedSnapshot = async (endpointUrl: string, googleAccessToken: string) => {
  const body = await authedJsonFetch<SyncSettingsResponse>(endpointUrl, "/sync/settings", googleAccessToken)
  return body?.snapshot ?? null
}
