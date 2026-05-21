import { createElement } from "react"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { PROFILE_KEYS, createEmptyProfile, type EventLogEntry } from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import PopupApp from "../lib/popup-app"
import { createChromeMock } from "./helpers/mock-chrome"

const createEvent = (index: number): EventLogEntry => ({
  id: `event-${index}`,
  type: "setting_changed",
  timestamp: new Date(Date.now() - index * 1000).toISOString(),
  hostname: "example.com",
  url: "https://example.com/form",
  source: "popup-ui",
  detail: `event-${index}`
})

const emptyProfile = Object.fromEntries(PROFILE_KEYS.map((key) => [key, ""])) as ReturnType<typeof createEmptyProfile>

describe("PopupApp", () => {
  it("shows the profile editor when storage is empty", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const fullNameInput = await screen.findByLabelText("氏名")
    expect((fullNameInput as HTMLInputElement).value).toBe("")
    expect(screen.getByText("まずプロフィールを登録")).toBeTruthy()
  })

  it("saves profile updates and shows the regular view", async () => {
    const mock = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    const fullNameInput = await screen.findByLabelText("氏名")
    const emailInput = screen.getByLabelText("メール")

    await user.clear(fullNameInput)
    await user.clear(emailInput)
    await user.type(fullNameInput, "山田 太郎")
    await user.type(emailInput, "taro@example.com")
    await user.click(screen.getByRole("button", { name: "プロフィールを保存" }))

    await waitFor(() => {
      expect(mock.storageData.autofillProfile).toMatchObject({
        fullName: "山田 太郎",
        email: "taro@example.com"
      })
    })

    const eventLog = mock.storageData.autofillEventLog as EventLogEntry[]
    expect(eventLog[0]?.type).toBe("profile_updated")
  })

  it("updates settings and current domain policy", async () => {
    const mock = createChromeMock(
      {
        autofillProfile: {
          ...createEmptyProfile(),
          fullName: "山田 太郎"
        }
      },
      {
        id: 1,
        url: "https://example.com/form"
      }
    )
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.click(await screen.findByLabelText("自動入力を有効化"))
    await user.selectOptions(screen.getByLabelText("ドメイン制御"), "blacklist")

    await waitFor(() => {
      expect(mock.storageData.autofillSettings).toMatchObject({
        enabled: false
      })
      expect(mock.storageData.autofillDomainPolicies).toMatchObject({
        "example.com": "blacklist"
      })
    })
  })

  it("saves cloud log settings and redacts the bearer token from event details", async () => {
    const mock = createChromeMock(
      {
        autofillProfile: {
          ...createEmptyProfile(),
          fullName: "山田 太郎"
        }
      },
      {
        id: 1,
        url: "https://example.com/form"
      }
    )
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText("Endpoint URL"), "https://logs.example.com/autofill")
    await user.type(screen.getByLabelText("Bearer token"), "secret-token")
    await user.click(screen.getByRole("button", { name: "クラウドログ設定を保存" }))

    await waitFor(() => {
      expect(mock.storageData.autofillSettings).toMatchObject({
        cloudLogSync: {
          endpointUrl: "https://logs.example.com/autofill",
          bearerToken: "secret-token",
          includeFieldValues: true
        }
      })
    })

    const eventLog = mock.storageData.autofillEventLog as EventLogEntry[]
    expect(eventLog[0]?.detail).toContain("[configured]")
    expect(eventLog[0]?.detail).not.toContain("secret-token")
    expect(mock.runtimeMessages[0]).toMatchObject({
      type: "SYNC_EVENT_LOGS_TO_CLOUD"
    })
  })

  it("renders only the latest 20 event log entries", async () => {
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      },
      autofillEventLog: Array.from({ length: 25 }, (_, index) => createEvent(index))
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const items = await screen.findAllByRole("listitem")
    expect(items).toHaveLength(20)
    expect(screen.queryByText(/event-24/)).toBeNull()
  })
})
