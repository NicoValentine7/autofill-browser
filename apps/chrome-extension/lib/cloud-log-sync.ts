import type { EventLogEntry } from "@autofill-browser/autofill-core"

import { CLOUD_LOG_INCLUDE_FIELD_VALUES, buildCloudWorkerUrl } from "./cloud-config"

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
  options: { includeFieldValues?: boolean } = {}
): CloudLogPayload => ({
  schemaVersion: 1,
  source: "chrome-extension",
  emittedAt: new Date().toISOString(),
  events: events.map((event) => {
    const sanitizedEvent = {
      ...event,
      url: sanitizeUrlForCloud(event.url)
    }

    if (!(options.includeFieldValues ?? CLOUD_LOG_INCLUDE_FIELD_VALUES)) {
      delete sanitizedEvent.previousValue
      delete sanitizedEvent.nextValue
    }

    return sanitizedEvent
  })
})

export const sendEventLogEntriesToCloud = async (
  events: EventLogEntry[],
  fetchImpl: FetchLike = fetch,
  googleAccessToken?: string | null
) => {
  const endpointUrl = buildCloudWorkerUrl("/me/events")

  if (events.length === 0) {
    return false
  }

  const headers: Record<string, string> = {
    "content-type": "application/json"
  }
  const bearerToken = googleAccessToken?.trim()

  if (!bearerToken) {
    return false
  }

  if (bearerToken) {
    headers.authorization = `Bearer ${bearerToken}`
  }

  try {
    const response = await fetchImpl(endpointUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(buildCloudLogPayload(events)),
      keepalive: true
    })

    return response.ok
  } catch (_error) {
    return false
  }
}
