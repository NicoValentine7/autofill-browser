import { PROFILE_KEYS, buildFieldDescriptor, buildFieldSignature, createEmptyProfile } from "@autofill-browser/autofill-core"
import { setImmediate as waitImmediate } from "node:timers/promises"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createAutofillController } from "../lib/content-controller"
import { createEmptySecureVault, ensureSecureVaultKeyCheck, type SecureVaultKey } from "../lib/secure-vault"
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

const vaultKey: SecureVaultKey = {
  schemaVersion: 1,
  keyId: "vault-key-1",
  algorithm: "AES-GCM",
  rawKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  createdAt: "2026-05-22T00:00:00.000Z"
}

const staleVaultKey: SecureVaultKey = {
  ...vaultKey,
  keyId: "vault-key-2",
  rawKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
}

const flush = async () => {
  for (let index = 0; index < 10; index += 1) {
    await Promise.resolve()
  }
  await waitImmediate()
}

const drainSnapshot = async () => {
  let snapshot = await getStorageSnapshot()
  for (let index = 0; index < 10; index += 1) {
    await vi.runAllTimersAsync()
    await flush()
    snapshot = await getStorageSnapshot()
  }
  return snapshot
}

const waitForSnapshot = async (predicate: (snapshot: Awaited<ReturnType<typeof getStorageSnapshot>>) => boolean) => {
  let snapshot = await getStorageSnapshot()
  for (let index = 0; index < 20; index += 1) {
    await vi.runAllTimersAsync()
    await flush()
    snapshot = await getStorageSnapshot()
    if (predicate(snapshot)) {
      return snapshot
    }
  }
  return snapshot
}

describe("content-controller", () => {
  const controllers: Array<ReturnType<typeof createAutofillController>> = []
  const createController = (...args: Parameters<typeof createAutofillController>) => {
    const controller = createAutofillController(...args)
    controllers.push(controller)
    return controller
  }

  beforeEach(() => {
    vi.useFakeTimers()
    window.history.replaceState({}, "", "/form")
  })

  afterEach(async () => {
    for (const controller of controllers) {
      await controller.flushPendingWrites()
    }
    for (const controller of controllers.splice(0)) {
      controller.dispose()
    }
    await vi.runOnlyPendingTimersAsync()
    await flush()
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

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("taro@example.com")
    const snapshot = await waitForSnapshot((nextSnapshot) => Object.values(nextSnapshot.secureVaultValues).length >= 2)
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "autofill_run")).toBe(true)
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_filled")).toBe(true)
  })

  it("autofills normal fields when session storage is unavailable to content scripts", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    chromeMock.storage.session.get = async () => {
      throw new Error("Access to storage is not allowed from this context.")
    }
    chromeMock.storage.session.set = async () => {
      throw new Error("Access to storage is not allowed from this context.")
    }
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" />`

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("taro@example.com")
  })

  it("silently deactivates when Chrome invalidates the content script context before storage reads", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    chromeMock.storage.local.get = async () => {
      throw new Error("Extension context invalidated.")
    }
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" />`

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await expect(controller.initialize()).resolves.toBeUndefined()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("")
    expect(controller.shouldAutofill()).toBe(false)
  })

  it("silently deactivates when Chrome invalidates the content script context before deferred writes", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" />`

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const field = document.getElementById("email") as HTMLInputElement
    expect(field.value).toBe("taro@example.com")

    chromeMock.storage.local.get = async () => {
      throw new Error("Extension context invalidated.")
    }
    field.value = "edited@example.com"
    field.dispatchEvent(new Event("input", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()

    expect(controller.shouldAutofill()).toBe(false)
  })

  it("does not overwrite non-empty values", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="email" name="email" value="already@example.com" />`

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email") as HTMLInputElement).value).toBe("already@example.com")
  })

  it("does not autofill a field while Japanese IME composition is active", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<input id="given-name" name="givenName" />`

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const field = document.getElementById("given-name") as HTMLInputElement
    field.value = ""
    field.dispatchEvent(new CompositionEvent("compositionstart", { bubbles: true, data: "た" }))

    await controller.runAutofill("mutation-observer")

    expect(field.value).toBe("")
  })

  it("does not autofill the focused field during automatic runs", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <input id="given-name" name="givenName" />
      <input id="family-name" name="familyName" />
    `

    const field = document.getElementById("given-name") as HTMLInputElement
    field.focus()

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect(field.value).toBe("")
    expect((document.getElementById("family-name") as HTMLInputElement).value).toBe("山田")
  })

  it("tracks IME composition before field-specific listeners are attached", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = ""

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    document.body.innerHTML = `<input id="given-name" name="givenName" />`
    const field = document.getElementById("given-name") as HTMLInputElement
    field.focus()
    field.dispatchEvent(new CompositionEvent("compositionstart", { bubbles: true, data: "た" }))

    await controller.runAutofill("mutation-observer")

    expect(field.value).toBe("")
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

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("recaptcha") as HTMLTextAreaElement).value).toBe("")
    expect((document.getElementById("apbct") as HTMLInputElement).value).toBe("")
    expect((document.getElementById("email-otp") as HTMLInputElement).value).toBe("")

    const snapshot = await waitForSnapshot((nextSnapshot) => {
      const values = Object.values(nextSnapshot.secureVaultValues)
      return values.includes("4111111111111111") && values.includes("12/30")
    })
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_filled")).toBe(false)
  })

  it("observes dynamically inserted forms", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: profile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `<div id="mount"></div>`

    const controller = createController({
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

    const controller = createController({
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

    const snapshot = await waitForSnapshot((nextSnapshot) => Object.values(nextSnapshot.secureVaultValues).includes("123"))
    const memoryEntry = Object.values(snapshot.fieldMemory)[0] as { lastUserValue?: string } | undefined

    expect(memoryEntry?.lastUserValue).toBe("OpenAI Japan合同会社")
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_corrected_by_user")).toBe(true)
  })

  it("learns safe manual input and hydrates empty profile fields", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="email">Email</label>
      <input id="email" name="email" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const field = document.getElementById("email") as HTMLInputElement
    field.value = "learned@example.com"
    field.dispatchEvent(new Event("input", { bubbles: true }))
    field.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()

    const snapshot = await drainSnapshot()
    const memoryEntry = Object.values(snapshot.fieldMemory)[0] as { lastUserValue?: string; profileKey?: string } | undefined

    expect(snapshot.profile.email).toBe("learned@example.com")
    expect(memoryEntry).toMatchObject({
      profileKey: "email",
      lastUserValue: "learned@example.com"
    })
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_learned_from_user")).toBe(true)
  })

  it("learns and later autofills custom fields outside the fixed profile", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="member-id">会員番号</label>
      <input id="member-id" name="member_id" />
    `

    const learningController = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await learningController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const learnedField = document.getElementById("member-id") as HTMLInputElement
    learnedField.value = "MEM-12345"
    learnedField.dispatchEvent(new Event("input", { bubbles: true }))
    learnedField.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()

    const learnedSnapshot = await getStorageSnapshot()
    const memoryEntry = Object.values(learnedSnapshot.fieldMemory)[0] as { lastUserValue?: string; profileKey?: string } | undefined
    expect(memoryEntry).toMatchObject({
      lastUserValue: "MEM-12345"
    })
    expect(memoryEntry?.profileKey).toBeUndefined()

    document.body.innerHTML = `
      <label for="member-id">会員番号</label>
      <input id="member-id" name="member_id" />
    `

    const autofillController = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await autofillController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("member-id") as HTMLInputElement).value).toBe("MEM-12345")
  })

  it("learns bank branch and account number inputs as custom fields", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="branch-code">INPUT_FORM:INPUT_BRANCH_CODE</label>
      <input id="branch-code" name="INPUT_FORM:INPUT_BRANCH_CODE" />
      <label for="account-number">INPUT_FORM:INPUT_ACCOUNT_NUMBER</label>
      <input id="account-number" name="INPUT_FORM:INPUT_ACCOUNT_NUMBER" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const branchField = document.getElementById("branch-code") as HTMLInputElement
    branchField.value = "235"
    branchField.dispatchEvent(new Event("input", { bubbles: true }))
    branchField.dispatchEvent(new Event("blur", { bubbles: true }))

    const accountField = document.getElementById("account-number") as HTMLInputElement
    accountField.value = "1234567"
    accountField.dispatchEvent(new Event("input", { bubbles: true }))
    accountField.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()
    await controller.flushPendingWrites()

    const snapshot = await getStorageSnapshot()
    const learnedValues = Object.values(snapshot.secureVaultValues)
    const learnedEvents = snapshot.eventLog.filter((entry: { type: string }) => entry.type === "field_learned_from_user")

    expect(learnedValues).toEqual(expect.arrayContaining(["235", "1234567"]))
    expect(snapshot.fieldMemory).toEqual({})
    expect(learnedEvents).toHaveLength(2)
    expect(learnedEvents.every((entry) => entry.nextValue === undefined && entry.detail?.includes("values:redacted"))).toBe(true)
  })

  it("does not learn secure vault fields when the local vault key fails the canary", async () => {
    const secureVault = await ensureSecureVaultKeyCheck(createEmptySecureVault(), vaultKey)
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile,
      autofillSecureVault: secureVault,
      autofillSecureVaultKey: staleVaultKey
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="account-number">Account number</label>
      <input id="account-number" name="account_number" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const accountField = document.getElementById("account-number") as HTMLInputElement
    accountField.value = "1234567"
    accountField.dispatchEvent(new Event("input", { bubbles: true }))
    accountField.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()
    await controller.flushPendingWrites()

    const snapshot = await getStorageSnapshot()
    expect(snapshot.secureVault.entries).toEqual({})
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_learned_from_user")).toBe(false)
  })

  it("learns payment card fields without writing raw values to event logs", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="card-number">Card number</label>
      <input id="card-number" name="card_number" autocomplete="cc-number" />
      <label for="card-exp">Expiry</label>
      <input id="card-exp" name="card_exp" autocomplete="cc-exp" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const cardNumber = document.getElementById("card-number") as HTMLInputElement
    cardNumber.value = "4111111111111111"
    cardNumber.dispatchEvent(new Event("input", { bubbles: true }))
    cardNumber.dispatchEvent(new Event("blur", { bubbles: true }))

    const cardExp = document.getElementById("card-exp") as HTMLInputElement
    cardExp.value = "12/30"
    cardExp.dispatchEvent(new Event("input", { bubbles: true }))
    cardExp.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()
    await controller.flushPendingWrites()

    const snapshot = await getStorageSnapshot()
    const learnedValues = Object.values(snapshot.secureVaultValues)
    const learnedEvents = snapshot.eventLog.filter((entry: { type: string }) => entry.type === "field_learned_from_user")

    expect(learnedValues).toEqual(expect.arrayContaining(["4111111111111111", "12/30"]))
    expect(snapshot.fieldMemory).toEqual({})
    expect(learnedEvents).toHaveLength(2)
    expect(learnedEvents.every((entry) => entry.nextValue === undefined && entry.detail?.includes("values:redacted"))).toBe(true)

    document.body.innerHTML = `
      <label for="card-number">Card number</label>
      <input id="card-number" name="card_number" autocomplete="cc-number" />
      <label for="card-exp">Expiry</label>
      <input id="card-exp" name="card_exp" autocomplete="cc-exp" />
    `

    const autofillController = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await autofillController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("card-number") as HTMLInputElement).value).toBe("")
    expect((document.getElementById("card-exp") as HTMLInputElement).value).toBe("")

    await autofillController.runAutofill("popup")
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("card-number") as HTMLInputElement).value).toBe("4111111111111111")
    expect((document.getElementById("card-exp") as HTMLInputElement).value).toBe("12/30")

    const filledSnapshot = await waitForSnapshot((nextSnapshot) => {
      return nextSnapshot.eventLog.filter((entry: { type: string }) => entry.type === "field_filled").length >= 2
    })
    const filledEvents = filledSnapshot.eventLog.filter((entry: { type: string }) => entry.type === "field_filled")
    expect(filledEvents).toHaveLength(2)
    expect(filledEvents.every((entry) => entry.nextValue === undefined && entry.detail?.includes("values:redacted"))).toBe(true)
  })

  it("does not persist or refill card security codes", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <label for="cvv">Security code</label>
      <input id="cvv" name="card_cvv" autocomplete="cc-csc" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const cvv = document.getElementById("cvv") as HTMLInputElement
    cvv.value = "123"
    cvv.dispatchEvent(new Event("input", { bubbles: true }))
    cvv.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()
    await controller.flushPendingWrites()

    const snapshot = await getStorageSnapshot()
    const learnedEvents = snapshot.eventLog.filter((entry: { type: string }) => entry.type === "field_learned_from_user")
    expect(Object.values(snapshot.secureVaultValues)).toEqual([])
    expect(snapshot.fieldMemory).toEqual({})
    expect(learnedEvents).toHaveLength(0)

    document.body.innerHTML = `
      <label for="cvv">Security code</label>
      <input id="cvv" name="card_cvv" autocomplete="cc-csc" />
    `

    const automaticController = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })
    await automaticController.initialize()
    await vi.runAllTimersAsync()
    await flush()
    expect((document.getElementById("cvv") as HTMLInputElement).value).toBe("")

    await automaticController.runAutofill("popup")
    expect((document.getElementById("cvv") as HTMLInputElement).value).toBe("")
  })

  it("does not learn dangerous manual inputs", async () => {
    const { chromeMock } = createChromeMock({
      autofillProfile: emptyProfile
    })
    ;(globalThis as { chrome: typeof chrome }).chrome = chromeMock as unknown as typeof chrome
    document.body.innerHTML = `
      <input id="email-otp" name="email_otp" autocomplete="one-time-code" />
      <textarea id="recaptcha" name="g-recaptcha-response"></textarea>
      <input id="password" name="password" type="password" />
      <label for="pin">PIN</label>
      <input id="pin" name="pin" />
      <label for="auth-code">Authentication code</label>
      <input id="auth-code" name="auth_code" />
      <label for="security-code">Security code</label>
      <input id="security-code" name="security_code" />
      <label for="secret-word">Secret word</label>
      <input id="secret-word" name="secret_word" />
    `

    const controller = createController({
      chromeApi: chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await controller.initialize()
    await vi.runAllTimersAsync()
    await flush()

    const otp = document.getElementById("email-otp") as HTMLInputElement
    otp.value = "123456"
    otp.dispatchEvent(new Event("input", { bubbles: true }))
    otp.dispatchEvent(new Event("blur", { bubbles: true }))

    const captcha = document.getElementById("recaptcha") as HTMLTextAreaElement
    captcha.value = "captcha-token"
    captcha.dispatchEvent(new Event("input", { bubbles: true }))
    captcha.dispatchEvent(new Event("blur", { bubbles: true }))

    const password = document.getElementById("password") as HTMLInputElement
    password.value = "pa55word"
    password.dispatchEvent(new Event("input", { bubbles: true }))
    password.dispatchEvent(new Event("blur", { bubbles: true }))

    const pin = document.getElementById("pin") as HTMLInputElement
    pin.value = "1234"
    pin.dispatchEvent(new Event("input", { bubbles: true }))
    pin.dispatchEvent(new Event("blur", { bubbles: true }))

    const authCode = document.getElementById("auth-code") as HTMLInputElement
    authCode.value = "123456"
    authCode.dispatchEvent(new Event("input", { bubbles: true }))
    authCode.dispatchEvent(new Event("blur", { bubbles: true }))

    const securityCode = document.getElementById("security-code") as HTMLInputElement
    securityCode.value = "123456"
    securityCode.dispatchEvent(new Event("input", { bubbles: true }))
    securityCode.dispatchEvent(new Event("blur", { bubbles: true }))

    const secretWord = document.getElementById("secret-word") as HTMLInputElement
    secretWord.value = "first pet"
    secretWord.dispatchEvent(new Event("input", { bubbles: true }))
    secretWord.dispatchEvent(new Event("blur", { bubbles: true }))

    await vi.runAllTimersAsync()
    await flush()
    await controller.flushPendingWrites()

    const snapshot = await getStorageSnapshot()
    expect(snapshot.fieldMemory).toEqual({})
    expect(snapshot.eventLog.some((entry: { type: string }) => entry.type === "field_learned_from_user")).toBe(false)
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

    const controller = createController({
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

    const controller = createController({
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

    const controller = createController({
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

    const blacklistController = createController({
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

    const whitelistController = createController({
      chromeApi: whitelistChrome.chromeMock as unknown as typeof chrome,
      debounceMs: 10
    })

    await whitelistController.initialize()
    await vi.runAllTimersAsync()
    await flush()

    expect((document.getElementById("email-whitelist") as HTMLInputElement).value).toBe("taro@example.com")
  })
})
