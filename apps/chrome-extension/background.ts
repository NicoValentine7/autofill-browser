import { sendEventLogEntriesToCloud } from "~lib/cloud-log-sync"
import { getGoogleAccessToken } from "~lib/google-auth"
import type { ExtensionMessage } from "~lib/messages"
import type { EventLogEntry } from "@autofill-browser/autofill-core"

const PENDING_CLOUD_LOG_EVENTS_KEY = "autofillPendingCloudLogEvents"
const PENDING_CLOUD_LOG_LIMIT = 200

const getPendingCloudLogEvents = async () => {
  const stored = await chrome.storage.local.get(PENDING_CLOUD_LOG_EVENTS_KEY)
  return ((stored[PENDING_CLOUD_LOG_EVENTS_KEY] as EventLogEntry[] | undefined) ?? []).filter(Boolean)
}

const savePendingCloudLogEvents = async (events: EventLogEntry[]) => {
  await chrome.storage.local.set({
    [PENDING_CLOUD_LOG_EVENTS_KEY]: events.slice(-PENDING_CLOUD_LOG_LIMIT)
  })
}

const flushCloudLogEvents = async (events: EventLogEntry[] = []) => {
  const googleAccessToken = await getGoogleAccessToken(false)
  const pendingEvents = await getPendingCloudLogEvents()
  const eventsToSend = [...pendingEvents, ...events].slice(-PENDING_CLOUD_LOG_LIMIT)

  if (eventsToSend.length === 0) {
    return
  }

  if (!googleAccessToken) {
    await savePendingCloudLogEvents(eventsToSend)
    return
  }

  const sent = await sendEventLogEntriesToCloud(eventsToSend, fetch, googleAccessToken)
  await savePendingCloudLogEvents(sent ? [] : eventsToSend)
}

chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
  if (message.type !== "SYNC_EVENT_LOGS_TO_CLOUD") {
    return
  }

  void flushCloudLogEvents(message.preferGoogleAuth ? message.events : [])
})

chrome.runtime.onStartup?.addListener(() => {
  void flushCloudLogEvents()
})
