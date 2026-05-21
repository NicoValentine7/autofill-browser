import { PROFILE_KEYS, buildFieldDescriptor, buildFieldSignature, createEmptyProfile } from "@autofill-browser/autofill-core"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createAutofillController } from "../lib/content-controller"
import { getStorageSnapshot } from "../lib/storage"
import { createChromeMock } from "./helpers/mock-chrome"

const profile = {
  ...createEmptyProfile(),
  fullName: "山田 太郎",
  email: "taro@example.com",
  phone: "09012345678",
  organization: "OpenAI",
  postalCode: "1500001",
  prefecture: "東京都",
  addressLine1: "渋谷区神宮前1-2-3",
  addressLine2: "テストビル301"
}

const derivedProfile = {
  ...createEmptyProfile(),
  fullName: "山田花子",
  postalCode: "1000001",
  prefecture: "東京都",
  addressLine1: "千代田区千代田1-1",
  addressLine2: "テストマンション101"
}

const emptyProfile = Object.fromEntries(PROFILE_KEYS.map((key) => [key, ""])) as typeof profile

const flush = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe("content-controller", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    window.history.replaceState({}, "", "/form")
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("autofills even when only one profile field matches", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile,
      autofillSettings: {
        enabled: true,
        observeDynamicForms: true,
        minMatchCount: 1
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" />`

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("taro@example.com")
    const snapshot = await getStorageSnapshot()
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "autofill_run")).toBe(true)
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_filled")).toBe(true)
  })

  it("does not overwrite non-empty values", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" value="already@example.com" />`

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("already@example.com")
  })

  it("does not fill or log field_filled for dangerous-only pages", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <textarea id="recaptcha" name="g-recaptcha-response"></textarea>
      <input id="apbct" name="apbct_email_id_search_form" />
      <input id="email-otp" name="email_otp" autocomplete="one-time-code" />
    `

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("recaptcha") as HTMLTextAreaElement).value).toBe("")
    expect((document.getElementById("apbct") as HTMLInputElement).value).toBe("")
    expect((document.getElementById("email-otp") as HTMLInputElement).value).toBe("")

    const snapshot = await getStorageSnapshot()
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_filled")).toBe(false)
  })

  it("observes dynamically inserted forms", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<div id="mount"></div>`

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    const mount = document.getElementById("mount") as HTMLDivElement
    mount.innerHTML = `<input id="phone" name="phone" />`

    await vi.advanceTimersByTimeAsync(25)
    await flush()

    expect((document.getElementById("phone") as HTMLInputElement).value).toBe("09012345678")
  })

  it("records user corrections into field memory and event logs", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="company" name="company" />`

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const field = document.getElementById("company") as HTMLInputElement
    field.value = "OpenAI Japan合同会社"
    field.dispatchEvent(new Event("input", { bubbles: true }))
    field.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()

    const snapshot = await getStorageSnapshot()
    const memoryEntry = Object.values(snapshot.fieldMemory)[0] as { lastUserValue?: string } | undefined

    expect(memoryEntry?.lastUserValue).toBe("OpenAI Japan合同会社")
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_corrected_by_user")).toBe(true)
  })

  it("fills derived family name, given name, city and address line 2 fields", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: derivedProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="family-name">姓</label>
      <input id="family-name" name="billing[last_name]" />
      <label for="given-name">名</label>
      <input id="given-name" name="billing[first_name]" />
      <label for="city">市町村</label>
      <input id="city" name="billing[city]" />
      <label for="address2">住所欄2</label>
      <input id="address2" name="billing[address2]" />
    `

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("family-name") as HTMLInputElement).value).toBe("山田")
    expect((document.getElementById("given-name") as HTMLInputElement).value).toBe("花子")
    expect((document.getElementById("city") as HTMLInputElement).value).toBe("千代田区千代田")
    expect((document.getElementById("address2") as HTMLInputElement).value).toBe("テストマンション101")
  })

  it("ignores uncorrected field memory when heuristics are now better", async () => {
    document.body.innerHTML = `
      <label for="address2">住所欄2</label>
      <input id="address2" name="billing[address2]" />
    `
    const address2Field = document.getElementById("address2") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(address2Field))

    const { chromeMock } = createChromeMock({
      autofillProfile: derivedProfile,
      autofillFieldMemory: {
        [`example.com::${fieldSignature}`]: {
          hostname: "example.com",
          fieldSignature,
          profileKey: "addressLine1",
          lastAutofilledValue: "千代田区千代田1-1",
          lastUserValue: "",
          timesAutofilled: 3,
          timesCorrected: 0,
          updatedAt: new Date().toISOString()
        }
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect(address2Field.value).toBe("テストマンション101")
  })

  it("does not dispatch change events for text inputs", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: derivedProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="address1">住所欄1</label>
      <input id="address1" name="billing[address1]" />
    `

    const field = document.getElementById("address1") as HTMLInputElement
    field.addEventListener("change", () => {
      field.value = `${field.value}${field.value}`
    })

    const controller = createAutofillController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect(field.value).toBe("千代田区千代田1-1テストマンション101")
  })

  it("skips blacklisted domains and still runs for whitelisted domains when disabled globally", async () => {
    const disabledSettings = {
      enabled: false,
      observeDynamicForms: true,
      minMatchCount: 1
    }

    const blacklistChrome = createChromeMock({
      autofillProfile: profile,
      autofillSettings: disabledSettings,
      autofillDomainPolicies: {
        "example.com": "blacklist"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = blacklistChrome.chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email-blacklist" name="email" />`

    const blacklistController = createAutofillController({
      chromeApi: blacklistChrome.chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await blacklistController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email-blacklist") as HTMLInputElement).value).toBe("")

    const whitelistChrome = createChromeMock({
      autofillProfile: profile,
      autofillSettings: disabledSettings,
      autofillDomainPolicies: {
        "example.com": "whitelist"
      }
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = whitelistChrome.chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email-whitelist" name="email" />`

    const whitelistController = createAutofillController({
      chromeApi: whitelistChrome.chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await whitelistController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email-whitelist") as HTMLInputElement).value).toBe("taro@example.com")
  })
})
