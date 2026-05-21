import type { CloudLogSyncSettings, EventLogEntry } from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import { buildCloudLogPayload, sendEventLogEntriesToCloud } from "../lib/cloud-log-sync"

const baseSettings: CloudLogSyncSettings = {
  endpointUrl: "https://logs.example.com/autofill",
  bearerToken: "secret-token",
  includeFieldValues: true
}

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
    const payload = buildCloudLogPayload([event], baseSettings)

    expect(payload.events[0]).toMatchObject({
      id: "event-1",
      url: "https://example.com/form",
      previousValue: "",
      nextValue: "taro@example.com"
    })
  })

  it("can redact field values when explicitly disabled", () => {
    const payload = buildCloudLogPayload([event], {
      ...baseSettings,
      includeFieldValues: false
    })

    expect(payload.events[0]?.previousValue).toBeUndefined()
    expect(payload.events[0]?.nextValue).toBeUndefined()
  })

  it("posts event logs to an HTTPS endpoint with bearer auth", async () => {
    const requests: Array<{ input: RequestInfo | URL; init?: RequestInit }> = []
    const fetchImpl = (async (input, init) => {
      requests.push({ input, init })
      return new Response(null, { status: 202 })
    }) satisfies typeof fetch

    const result = await sendEventLogEntriesToCloud([event], baseSettings, fetchImpl)

    expect(result).toBe(true)
    expect(requests[0]?.input).toBe(baseSettings.endpointUrl)
    expect(requests[0]?.init?.method).toBe("POST")
    expect(requests[0]?.init?.headers).toMatchObject({
      authorization: "Bearer secret-token",
      "content-type": "application/json"
    })
  })

  it("does not send logs when the endpoint is blank or not HTTPS", async () => {
    const requests: Array<RequestInfo | URL> = []
    const fetchImpl = (async (input) => {
      requests.push(input)
      return new Response(null, { status: 202 })
    }) satisfies typeof fetch

    const blankEndpointResult = await sendEventLogEntriesToCloud(
      [event],
      {
        ...baseSettings,
        endpointUrl: ""
      },
      fetchImpl
    )
    const insecureResult = await sendEventLogEntriesToCloud(
      [event],
      {
        ...baseSettings,
        endpointUrl: "http://logs.example.com/autofill"
      },
      fetchImpl
    )

    expect(blankEndpointResult).toBe(false)
    expect(insecureResult).toBe(false)
    expect(requests).toHaveLength(0)
  })
})
