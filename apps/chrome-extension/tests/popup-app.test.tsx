import { createElement } from "react"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { DEFAULT_AUTOFILL_SETTINGS, PROFILE_KEYS, createEmptyProfile, type EventLogEntry } from "@autofill-browser/autofill-core"
import { afterEach, describe, expect, it, vi } from "vitest"

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
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("shows the profile editor when storage is empty", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const fullNameInput = await screen.findByLabelText("氏名")
    expect((fullNameInput as HTMLInputElement).value).toBe("")
    expect(screen.getByText("まずプロフィールを登録")).toBeTruthy()
    expect(screen.queryByText("詳細設定")).toBeNull()
    expect(screen.queryByText("Worker URL")).toBeNull()
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

  it("signs in with Google and pushes the local snapshot when cloud is empty", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        requests.push({ url, init })

        if (url.endsWith("/me")) {
          return new Response(
            JSON.stringify({
              user: {
                sub: "google-sub-1",
                email: "taro@example.com",
                signedInAt: "2026-05-21T00:00:00.000Z"
              }
            }),
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          )
        }

        if (url.endsWith("/me/settings") && init?.method !== "PUT") {
          return new Response(
            JSON.stringify({
              snapshot: null
            }),
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          )
        }

        return new Response(
          JSON.stringify({
            ok: true,
            updatedAt: "2026-05-21T00:00:01.000Z"
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        )
      })
    )
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.click(await screen.findByRole("button", { name: "Googleでログイン" }))

    await waitFor(() => {
      expect(mock.storageData.autofillGoogleAuthUser).toMatchObject({
        email: "taro@example.com"
      })
    })
    expect(requests.some((request) => request.url === "https://autofill-browser-log-worker.y-elucidator.workers.dev/me")).toBe(true)
    expect(requests.some((request) => request.url === "https://autofill-browser-log-worker.y-elucidator.workers.dev/me/settings" && request.init?.method === "PUT")).toBe(
      true
    )
    expect(mock.storageData.autofillAccountSync).toMatchObject({
      lastRemoteUpdatedAt: "2026-05-21T00:00:01.000Z"
    })
  })

  it("automatically restores a newer cloud snapshot for signed-in users", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            snapshot: {
              schemaVersion: 1,
              profile: {
                ...createEmptyProfile(),
                fullName: "クラウド 太郎",
                email: "cloud@example.com"
              },
              settings: {
                ...DEFAULT_AUTOFILL_SETTINGS,
                enabled: false
              },
              domainPolicies: {
                "example.com": "blacklist"
              },
              updatedAt: "2026-05-21T00:00:02.000Z"
            }
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        )
      )
    )
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "ローカル 太郎"
      },
      autofillSettings: DEFAULT_AUTOFILL_SETTINGS,
      autofillGoogleAuthUser: {
        sub: "google-sub-1",
        email: "taro@example.com",
        signedInAt: "2026-05-21T00:00:00.000Z"
      },
      autofillAccountSync: {
        lastRemoteUpdatedAt: "2026-05-21T00:00:01.000Z"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    await waitFor(() => {
      expect(mock.storageData.autofillProfile).toMatchObject({
        fullName: "クラウド 太郎",
        email: "cloud@example.com"
      })
      expect(mock.storageData.autofillDomainPolicies).toMatchObject({
        "example.com": "blacklist"
      })
    })
    expect(mock.storageData.autofillSettings).toMatchObject({
      enabled: false
    })
    expect(screen.queryByRole("button", { name: "クラウドへ保存" })).toBeNull()
    expect(screen.queryByRole("button", { name: "クラウドから復元" })).toBeNull()
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
    expect(screen.queryByText(/event-0/)).toBeNull()
    expect(screen.queryByText(/event-24/)).toBeNull()
  })
})
