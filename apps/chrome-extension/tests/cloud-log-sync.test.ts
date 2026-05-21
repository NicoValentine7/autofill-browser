import type { EventLogEntry } from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import { buildCloudLogPayload, sendEventLogEntriesToCloud } from "../lib/cloud-log-sync"

const event: EventLogEntry = {
  id: "event-1",
  type: "field_filled",
  timestamp: "2026-05-20T00:00:00.000Z",
  hostname: "example.com",
  url: "https://example.com/form?token=secret#hash",
  fieldSignature: "input|email",
  profileKey: "email",
  previousValue: "",
  nextValue: "taro@example.com",
  source: "popup",
  runId: "run-1"
}

describe("cloud-log-sync", () => {
  it("includes field values and redacts URL secrets by default", () => {
    const payload = buildCloudLogPayload([event])

    expect(payload.events[0]).toMatchObject({
      id: "event-1",
      url: "https://example.com/form",
      previousValue: "",
      nextValue: "taro@example.com"
    })
  })

  it("can redact field values when explicitly disabled", () => {
    const payload = buildCloudLogPayload([event], {
      includeFieldValues: false
    })

    expect(payload.events[0]?.previousValue).toBeUndefined()
    expect(payload.events[0]?.nextValue).toBeUndefined()
  })

  it("posts event logs to the cloud-native user endpoint with Google auth", async () => {
    const requests: Array<{ input: RequestInfo | URL; init?: RequestInit }> = []
    const fetchImpl = (async (input, init) => {
      requests.push({ input, init })
      return new Response(null, { status: 202 })
    }) satisfies typeof fetch

    const result = await sendEventLogEntriesToCloud([event], fetchImpl, "google-access-token")

    expect(result).toBe(true)
    expect(requests[0]?.input).toBe("https://autofill-browser-log-worker.y-elucidator.workers.dev/me/events")
    expect(requests[0]?.init?.method).toBe("POST")
    expect(requests[0]?.init?.headers).toMatchObject({
      authorization: "Bearer google-access-token",
      "content-type": "application/json"
    })
  })

  it("does not send logs when auth or events are missing", async () => {
    const requests: Array<RequestInfo | URL> = []
    const fetchImpl = (async (input) => {
      requests.push(input)
      return new Response(null, { status: 202 })
    }) satisfies typeof fetch
    const emptyEventsResult = await sendEventLogEntriesToCloud([], fetchImpl, "google-access-token")
    const missingAuthResult = await sendEventLogEntriesToCloud([event], fetchImpl)

    expect(emptyEventsResult).toBe(false)
    expect(missingAuthResult).toBe(false)
    expect(requests).toHaveLength(0)
  })
})
