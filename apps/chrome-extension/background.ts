import { sendEventLogEntriesToCloud } from "~lib/cloud-log-sync"
import { getGoogleAccessToken } from "~lib/google-auth"
import type { ExtensionMessage } from "~lib/messages"
import type { EventLogEntry } from "@autofill-browser/autofill-core"

const PENDING_CLOUD_LOG_EVENTS_KEY = "autofillPendingCloudLogEvents"
const ACCOUNT_SYNC_KEY = "autofillAccountSync"
const PENDING_CLOUD_LOG_LIMIT = 200

type StorageAreaWithAccessLevel = {
  setAccessLevel?: (options: { accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" | "TRUSTED_CONTEXTS" }) => Promise<void>
}

type AccountSyncState = {
  deviceId?: string
}

const setStorageAccessLevel = async (
  storageArea: StorageAreaWithAccessLevel | undefined,
  accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" | "TRUSTED_CONTEXTS"
) => {
  try {
    await storageArea?.setAccessLevel?.({
      accessLevel
    })
  } catch (_error) {
    // Older Chrome versions may not expose setAccessLevel on every storage area.
  }
}

const configureStorageAccessLevels = async () => {
  // Content scripts currently perform the actual field fill and must read the
  // in-memory Vault Key until storage access is brokered through the service worker.
  await setStorageAccessLevel(chrome.storage.session, "TRUSTED_AND_UNTRUSTED_CONTEXTS")
}

const getPendingCloudLogEvents = async () => {
  const stored = await chrome.storage.local.get(PENDING_CLOUD_LOG_EVENTS_KEY)
  return ((stored[PENDING_CLOUD_LOG_EVENTS_KEY] as EventLogEntry[] | undefined) ?? []).filter(Boolean)
}

const savePendingCloudLogEvents = async (events: EventLogEntry[]) => {
  await chrome.storage.local.set({
    [PENDING_CLOUD_LOG_EVENTS_KEY]: events.slice(-PENDING_CLOUD_LOG_LIMIT)
  })
}

const getInstallationId = async () => {
  const stored = await chrome.storage.local.get(ACCOUNT_SYNC_KEY)
  const accountSync = stored[ACCOUNT_SYNC_KEY] as AccountSyncState | undefined
  return accountSync?.deviceId?.trim() || null
}

const flushCloudLogEvents = async (events: EventLogEntry[] = []) => {
  const googleAccessToken = await getGoogleAccessToken(false)
  const installationId = await getInstallationId()
  const pendingEvents = await getPendingCloudLogEvents()
  const eventsToSend = [...pendingEvents, ...events].slice(-PENDING_CLOUD_LOG_LIMIT)

  if (eventsToSend.length === 0) {
    return
  }

  if (!googleAccessToken) {
    await savePendingCloudLogEvents(eventsToSend)
    return
  }

  const sent = await sendEventLogEntriesToCloud(eventsToSend, fetch, googleAccessToken, {
    installationId
  })
  await savePendingCloudLogEvents(sent ? [] : eventsToSend)
}

chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
  if (message.type !== "SYNC_EVENT_LOGS_TO_CLOUD") {
    return
  }

  void flushCloudLogEvents(message.preferGoogleAuth ? message.events : [])
})

void configureStorageAccessLevels()

chrome.runtime.onInstalled?.addListener(() => {
  void configureStorageAccessLevels()
})

chrome.runtime.onStartup?.addListener(() => {
  void configureStorageAccessLevels()
  void flushCloudLogEvents()
})
