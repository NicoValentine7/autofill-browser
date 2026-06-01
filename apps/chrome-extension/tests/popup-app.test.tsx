import { createElement } from "react"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { DEFAULT_AUTOFILL_SETTINGS, PROFILE_KEYS, createEmptyProfile, type EventLogEntry } from "@autofill-browser/autofill-core"
import { afterEach, describe, expect, it, vi } from "vitest"

import PopupApp from "../lib/popup-app"
import {
  MANUAL_SECURE_VAULT_HOSTNAME,
  createSecureVaultRecoveryPackage,
  parseSecureVaultApiTokenItemPayload,
  type SecureVaultKey
} from "../lib/secure-vault"
import { getStorageSnapshot } from "../lib/storage"
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

const vaultKey: SecureVaultKey = {
  schemaVersion: 1,
  keyId: "vault-key-1",
  algorithm: "AES-GCM",
  rawKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  createdAt: "2026-05-22T00:00:00.000Z"
}

const secondVaultKey: SecureVaultKey = {
  ...vaultKey,
  keyId: "vault-key-2",
  rawKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
}

describe("PopupApp", () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: undefined,
      configurable: true
    })
  })

  it("migrates a legacy persisted Secure Vault key into session storage", async () => {
    const mock = createChromeMock({
      autofillSecureVaultKey: vaultKey
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    const snapshot = await getStorageSnapshot()

    expect(snapshot.secureVaultKey).toEqual(vaultKey)
    expect(mock.sessionStorageData.autofillSecureVaultKey).toEqual(vaultKey)
    expect(mock.storageData.autofillSecureVaultKey).toBeNull()
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
    const putRequest = requests.find((request) => request.url.endsWith("/me/settings") && request.init?.method === "PUT")
    expect(String(putRequest?.init?.body)).not.toContain("secureVault")
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

  it("saves a wrapped Secure Vault recovery package without syncing the raw key", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        requests.push({ url, init })

        if (url.endsWith("/me/settings") && init?.method !== "PUT") {
          return new Response(JSON.stringify({ snapshot: null }), {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          })
        }

        return new Response(JSON.stringify({ ok: true, updatedAt: "2026-05-22T00:00:00.000Z" }), {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        })
      })
    )
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      },
      autofillSecureVaultKey: vaultKey,
      autofillGoogleAuthUser: {
        sub: "google-sub-1",
        email: "taro@example.com",
        signedInAt: "2026-05-21T00:00:00.000Z"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    const recoveryPhraseInput = (await screen.findByLabelText("回復フレーズ")) as HTMLInputElement
    await user.click(screen.getByRole("button", { name: "生成" }))
    const recoveryPhrase = recoveryPhraseInput.value
    await user.click(screen.getByRole("button", { name: "回復フレーズを保存" }))

    await waitFor(() => {
      expect(mock.storageData.autofillSecureVaultRecovery).toMatchObject({
        keyId: "vault-key-1",
        algorithm: "PBKDF2-SHA256/AES-GCM"
      })
    })
    const putRequest = requests.find((request) => request.url.endsWith("/me/settings") && request.init?.method === "PUT")
    expect(putRequest).toBeTruthy()
    expect(recoveryPhrase).toHaveLength(43)
    expect(String(putRequest?.init?.body)).not.toContain(vaultKey.rawKey)
    expect(String(putRequest?.init?.body)).not.toContain("secureVaultKey")
    expect(String(putRequest?.init?.body)).not.toContain(recoveryPhrase)
  })

  it("restores the local Secure Vault key from a recovery phrase", async () => {
    const recoveryPackage = await createSecureVaultRecoveryPackage(vaultKey, "correct horse battery staple")
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      },
      autofillSecureVaultRecovery: recoveryPackage
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText("回復フレーズ"), "correct horse battery staple")
    await user.click(screen.getByRole("button", { name: "Vault Keyを復元" }))

    await waitFor(() => {
      expect(mock.sessionStorageData.autofillSecureVaultKey).toEqual(vaultKey)
      expect(mock.storageData.autofillSecureVaultKey).toBeNull()
    })
  })

  it("saves manually entered API tokens into Secure Vault without storing plaintext locally", async () => {
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText("API token名"), "GitHub production")
    await user.type(screen.getByLabelText("サービスURL"), "https://api.github.com")
    await user.type(screen.getByLabelText("アカウント"), "deploy-bot")
    await user.type(screen.getByLabelText("API token"), "ghp_test_secret")
    await user.type(screen.getByLabelText("メモ"), "repo deploy scope")
    await user.click(screen.getByRole("button", { name: "API tokenを保存" }))

    await waitFor(async () => {
      const snapshot = await getStorageSnapshot()
      const [entry] = Object.values(snapshot.secureVault.entries).filter((candidate) => candidate.kind === "api-token")
      expect(entry).toMatchObject({
        hostname: MANUAL_SECURE_VAULT_HOSTNAME,
        label: "GitHub production"
      })
      const [plaintext] = Object.values(snapshot.secureVaultValues)
      expect(parseSecureVaultApiTokenItemPayload(plaintext)).toMatchObject({
        token: "ghp_test_secret",
        serviceUrl: "https://api.github.com",
        accountName: "deploy-bot",
        notes: "repo deploy scope"
      })
    })

    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("ghp_test_secret")
    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("https://api.github.com")
    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("deploy-bot")
    expect(mock.sessionStorageData.autofillSecureVaultKey).toBeTruthy()
  })

  it("copies and deletes saved API token vault items", async () => {
    const writeText = vi.fn(async () => undefined)
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: {
        writeText
      },
      configurable: true
    })
    await user.type(await screen.findByLabelText("API token名"), "GitHub production")
    await user.type(screen.getByLabelText("サービスURL"), "https://api.github.com")
    await user.type(screen.getByLabelText("アカウント"), "deploy-bot")
    await user.type(screen.getByLabelText("API token"), "ghp_test_secret")
    await user.click(screen.getByRole("button", { name: "API tokenを保存" }))

    expect(await screen.findByText("deploy-bot / https://api.github.com")).toBeTruthy()
    const copyButton = screen.getByRole("button", { name: "コピー" }) as HTMLButtonElement
    await waitFor(() => {
      expect(copyButton.disabled).toBe(false)
    })

    await user.click(copyButton)
    expect(writeText).toHaveBeenCalledWith("ghp_test_secret")

    await user.click(screen.getByRole("button", { name: "削除" }))
    await waitFor(async () => {
      const snapshot = await getStorageSnapshot()
      expect(Object.values(snapshot.secureVault.entries).filter((entry) => entry.kind === "api-token")).toHaveLength(0)
    })
    expect(screen.queryByText("GitHub production")).toBeNull()
  })

  it("edits saved API token vault items without creating duplicates", async () => {
    const writeText = vi.fn(async () => undefined)
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: {
        writeText
      },
      configurable: true
    })
    await user.type(await screen.findByLabelText("API token名"), "GitHub production")
    await user.type(screen.getByLabelText("サービスURL"), "https://api.github.com")
    await user.type(screen.getByLabelText("アカウント"), "deploy-bot")
    await user.type(screen.getByLabelText("API token"), "ghp_old_secret")
    await user.type(screen.getByLabelText("メモ"), "old scope")
    await user.click(screen.getByRole("button", { name: "API tokenを保存" }))

    await user.click(await screen.findByRole("button", { name: "編集" }))
    await user.clear(screen.getByLabelText("API token名"))
    await user.type(screen.getByLabelText("API token名"), "GitHub staging")
    await user.clear(screen.getByLabelText("サービスURL"))
    await user.type(screen.getByLabelText("サービスURL"), "https://staging.example.test")
    await user.clear(screen.getByLabelText("アカウント"))
    await user.type(screen.getByLabelText("アカウント"), "staging-bot")
    await user.clear(screen.getByLabelText("API token"))
    await user.type(screen.getByLabelText("API token"), "ghp_new_secret")
    await user.clear(screen.getByLabelText("メモ"))
    await user.type(screen.getByLabelText("メモ"), "staging scope")
    await user.click(screen.getByRole("button", { name: "API tokenを更新" }))

    await waitFor(async () => {
      const snapshot = await getStorageSnapshot()
      const entries = Object.values(snapshot.secureVault.entries).filter((entry) => entry.kind === "api-token")
      expect(entries).toHaveLength(1)
      expect(entries[0]).toMatchObject({
        label: "GitHub staging"
      })
      const [plaintext] = Object.values(snapshot.secureVaultValues)
      expect(parseSecureVaultApiTokenItemPayload(plaintext)).toMatchObject({
        token: "ghp_new_secret",
        serviceUrl: "https://staging.example.test",
        accountName: "staging-bot",
        notes: "staging scope"
      })
    })

    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("ghp_old_secret")
    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("ghp_new_secret")
    expect(JSON.stringify(mock.storageData.autofillSecureVault)).not.toContain("https://staging.example.test")

    await user.click(screen.getByRole("button", { name: "コピー" }))
    expect(writeText).toHaveBeenCalledWith("ghp_new_secret")
  })

  it("does not treat a leftover local vault key as usable for a different recovery package", async () => {
    const recoveryPackage = await createSecureVaultRecoveryPackage(secondVaultKey, "correct horse battery staple")
    const mock = createChromeMock({
      autofillProfile: {
        ...createEmptyProfile(),
        fullName: "山田 太郎"
      },
      autofillSecureVaultKey: vaultKey,
      autofillSecureVaultRecovery: recoveryPackage
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = mock.chromeMock as unknown as typeof chrome

    render(createElement(PopupApp))

    const user = userEvent.setup()
    await user.type(await screen.findByLabelText("回復フレーズ"), "correct horse battery staple")
    await user.click(screen.getByRole("button", { name: "Vault Keyを復元" }))

    await waitFor(() => {
      expect(mock.sessionStorageData.autofillSecureVaultKey).toEqual(secondVaultKey)
      expect(mock.storageData.autofillSecureVaultKey).toBeNull()
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
    expect(screen.queryByText(/event-0/)).toBeNull()
    expect(screen.queryByText(/event-24/)).toBeNull()
  })
})
