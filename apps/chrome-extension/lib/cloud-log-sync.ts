import type { EventLogEntry } from "@autofill-browser/autofill-core"

import { CLOUD_LOG_INCLUDE_FIELD_VALUES, buildCloudWorkerUrl, buildProductOperationLogWorkerUrl } from "./cloud-config"

export type CloudLogPayload = {
  schemaVersion: 1
  source: "chrome-extension"
  emittedAt: string
  events: EventLogEntry[]
}

type FetchLike = typeof fetch

export type ProductOperationEvent = {
  event_id: string
  schema_version: 1
  occurred_at: string
  received_at: string
  product: "autofill-browser"
  environment: "prod"
  app_version: string
  platform: "chrome-extension"
  installation_id: string | null
  user_id_hash: null
  session_id: string | null
  event_name: "autofill.applied"
  event_type: "product"
  severity: "info"
  outcome: "success"
  reason_code: null
  trace_id: null
  span_id: null
  consent_state: "analytics_opt_in"
  payload: {
    field_count: number
    field_category_counts: Record<string, number>
    form_category: "unknown"
    browser: "chrome"
    extension_context: EventLogEntry["source"]
  }
}

type ProductOperationLogOptions = {
  appVersion?: string
  installationId?: string | null
  endpointUrl?: string
  authorizationToken?: string | null
}

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

export const buildProductOperationEvents = (
  events: EventLogEntry[],
  options: ProductOperationLogOptions = {}
): ProductOperationEvent[] => {
  const receivedAt = new Date().toISOString()

  return events.flatMap((event) => {
    if (event.type !== "field_filled") {
      return []
    }

    const fieldCategory = event.profileKey ?? "unknown"

    return [
      {
        event_id: `${event.id}:product-operation`,
        schema_version: 1,
        occurred_at: event.timestamp,
        received_at: receivedAt,
        product: "autofill-browser",
        environment: "prod",
        app_version: options.appVersion ?? "0.1.0",
        platform: "chrome-extension",
        installation_id: options.installationId?.trim() || null,
        user_id_hash: null,
        session_id: event.runId ?? null,
        event_name: "autofill.applied",
        event_type: "product",
        severity: "info",
        outcome: "success",
        reason_code: null,
        trace_id: null,
        span_id: null,
        consent_state: "analytics_opt_in",
        payload: {
          field_count: 1,
          field_category_counts: {
            [fieldCategory]: 1
          },
          form_category: "unknown",
          browser: "chrome",
          extension_context: event.source
        }
      }
    ]
  })
}

export const sendProductOperationEventsToCloud = async (
  events: EventLogEntry[],
  fetchImpl: FetchLike = fetch,
  options: ProductOperationLogOptions = {}
) => {
  const endpointUrl = options.endpointUrl ?? buildProductOperationLogWorkerUrl("/events")

  if (!endpointUrl) {
    return true
  }

  const productEvents = buildProductOperationEvents(events, options)

  if (productEvents.length === 0) {
    return true
  }

  const headers: Record<string, string> = {
    "content-type": "application/json"
  }
  const authorizationToken = options.authorizationToken?.trim()

  if (authorizationToken) {
    headers.authorization = `Bearer ${authorizationToken}`
  }

  try {
    const responses = await Promise.all(
      productEvents.map((event) =>
        fetchImpl(endpointUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(event),
          keepalive: true
        })
      )
    )

    return responses.every((response) => response.ok)
  } catch (_error) {
    return false
  }
}

export const sendEventLogEntriesToCloud = async (
  events: EventLogEntry[],
  fetchImpl: FetchLike = fetch,
  googleAccessToken?: string | null,
  options: ProductOperationLogOptions = {}
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

    if (!response.ok) {
      return false
    }

    return sendProductOperationEventsToCloud(events, fetchImpl, {
      ...options,
      authorizationToken: googleAccessToken
    })
  } catch (_error) {
    return false
  }
}
