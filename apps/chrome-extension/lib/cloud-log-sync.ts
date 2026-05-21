import type { CloudLogSyncSettings, EventLogEntry } from "@autofill-browser/autofill-core"

export type CloudLogPayload = {
  schemaVersion: 1
  source: "chrome-extension"
  emittedAt: string
  events: EventLogEntry[]
}

type FetchLike = typeof fetch

const sanitizeUrlForCloud = (url: string) => {
  if (!url) {
    return ""
  }

  try {
    const parsedUrl = new URL(url)
    parsedUrl.username = ""
    parsedUrl.password = ""
    parsedUrl.search = ""
    parsedUrl.hash = ""
    return parsedUrl.toString()
  } catch (_error) {
    return ""
  }
}

export const buildCloudLogPayload = (
  events: EventLogEntry[],
  settings: Pick<CloudLogSyncSettings, "includeFieldValues">
): CloudLogPayload => ({
  schemaVersion: 1,
  source: "chrome-extension",
  emittedAt: new Date().toISOString(),
  events: events.map((event) => {
    const sanitizedEvent = {
      ...event,
      url: sanitizeUrlForCloud(event.url)
    }

    if (!settings.includeFieldValues) {
      delete sanitizedEvent.previousValue
      delete sanitizedEvent.nextValue
    }

    return sanitizedEvent
  })
})

export const sendEventLogEntriesToCloud = async (
  events: EventLogEntry[],
  settings: CloudLogSyncSettings,
  fetchImpl: FetchLike = fetch
) => {
  const endpointUrl = settings.endpointUrl.trim()

  if (events.length === 0 || !endpointUrl.startsWith("https://")) {
    return false
  }

  const headers: Record<string, string> = {
    "content-type": "application/json"
  }
  const bearerToken = settings.bearerToken.trim()

  if (bearerToken) {
    headers.authorization = `Bearer ${bearerToken}`
  }

  try {
    const response = await fetchImpl(endpointUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(buildCloudLogPayload(events, settings)),
      keepalive: true
    })

    return response.ok
  } catch (_error) {
    return false
  }
}
