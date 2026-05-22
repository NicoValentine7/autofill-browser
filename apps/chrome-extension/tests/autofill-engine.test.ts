import {
  DEFAULT_AUTOFILL_SETTINGS,
  buildFieldDescriptor,
  buildFieldSignature,
  createEmptyProfile
} from "@autofill-browser/autofill-core"
import { describe, expect, it } from "vitest"

import { collectAutofillCandidates } from "../lib/autofill-engine"
import { createEmptySecureVault, getSecureVaultEntryKey } from "../lib/secure-vault"
import type { StorageSnapshot } from "../lib/storage"

const profile = {
  ...createEmptyProfile(),
  familyName: "山田",
  givenName: "花子",
  fullName: "山田花子",
  email: "hanako@example.test",
  phone: "08000001111",
  organization: "",
  postalCode: "1000001",
  prefecture: "東京都",
  city: "千代田区千代田",
  addressLine1: "千代田区千代田1-1",
  addressLine2: "テストマンション101"
}

const createSnapshot = (): StorageSnapshot => ({
  profile,
  settings: {
    ...DEFAULT_AUTOFILL_SETTINGS,
    enabled: true,
    observeDynamicForms: true,
    minMatchCount: 1
  },
  domainPolicies: {},
  fieldMemory: {},
  secureVault: createEmptySecureVault(),
  secureVaultValues: {},
  eventLog: [],
  accountSync: {}
})

const valueById = (snapshot: StorageSnapshot) =>
  Object.fromEntries(
    collectAutofillCandidates(document, snapshot, window.location).map((candidate) => [
      (candidate.field as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).id,
      candidate.rawValue
    ])
  )

describe("autofill-engine", () => {
  it("fills split postal code and phone inputs", () => {
    document.body.innerHTML = `
      <label for="zip1">郵便番号1</label>
      <input id="zip1" name="zip1" />
      <label for="zip2">郵便番号2</label>
      <input id="zip2" name="zip2" />
      <label for="tel1">電話番号1</label>
      <input id="tel1" name="tel1" />
      <label for="tel2">電話番号2</label>
      <input id="tel2" name="tel2" />
      <label for="tel3">電話番号3</label>
      <input id="tel3" name="tel3" />
    `

    const values = valueById(createSnapshot())

    expect(values).toMatchObject({
      zip1: "100",
      zip2: "0001",
      tel1: "080",
      tel2: "0000",
      tel3: "1111"
    })
  })

  it("strips city from address line 1 when the page has dedicated city and building fields", () => {
    document.body.innerHTML = `
      <label for="city">市町村</label>
      <input id="city" name="city" />
      <label for="address1">住所欄1</label>
      <input id="address1" name="address1" />
      <label for="address2">住所欄2</label>
      <input id="address2" name="address2" />
    `

    const values = valueById(createSnapshot())

    expect(values).toMatchObject({
      city: "千代田区千代田",
      address1: "1-1",
      address2: "テストマンション101"
    })
  })

  it("combines the full address for generic street-address fields", () => {
    document.body.innerHTML = `
      <label for="street-address">Street address</label>
      <input id="street-address" name="street_address" autocomplete="street-address" />
    `

    const values = valueById(createSnapshot())

    expect(values["street-address"]).toBe("東京都千代田区千代田1-1テストマンション101")
  })

  it("keeps ordinary contact fields eligible", () => {
    document.body.innerHTML = `
      <label for="name">Full name</label>
      <input id="name" name="full_name" />
      <label for="email">Email</label>
      <input id="email" name="email" />
      <label for="address2">住所欄2</label>
      <input id="address2" name="billing[address2]" />
    `

    const values = valueById(createSnapshot())

    expect(values).toMatchObject({
      name: "山田花子",
      email: "hanako@example.test",
      address2: "テストマンション101"
    })
  })

  it("applies remote blocked identity tokens", () => {
    document.body.innerHTML = `
      <label for="customer-secret">Customer Secret</label>
      <input id="customer-secret" name="customer_secret" />
      <label for="email">Email</label>
      <input id="email" name="email" />
    `

    const snapshot = createSnapshot()
    snapshot.remoteRules = {
      schemaVersion: 1,
      blockedIdentityTokens: ["customer secret"],
      updatedAt: "2026-05-21T00:00:00.000Z"
    }
    const values = valueById(snapshot)

    expect(values["customer-secret"]).toBeUndefined()
    expect(values.email).toBe("hanako@example.test")
  })

  it("skips captcha, anti-abuse and auth-code fields", () => {
    document.body.innerHTML = `
      <textarea id="recaptcha" name="g-recaptcha-response"></textarea>
      <textarea id="hcaptcha" name="h-captcha-response"></textarea>
      <input id="apbct" name="apbct_email_id_search_form" />
      <input id="email-otp" name="email_otp" autocomplete="one-time-code" />
      <label for="verification">Verification code</label>
      <input id="verification" name="verification_code" />
      <label for="auth-code">Authentication code</label>
      <input id="auth-code" name="auth_code" />
      <label for="totp">TOTP</label>
      <input id="totp" name="totp" />
      <label for="sms-code">SMS code</label>
      <input id="sms-code" name="sms_code" />
      <label for="email">Email</label>
      <input id="email" name="email" />
    `

    const values = valueById(createSnapshot())

    expect(values).toMatchObject({
      email: "hanako@example.test"
    })
    expect(values).not.toHaveProperty("recaptcha")
    expect(values).not.toHaveProperty("hcaptcha")
    expect(values).not.toHaveProperty("apbct")
    expect(values).not.toHaveProperty("email-otp")
    expect(values).not.toHaveProperty("verification")
    expect(values).not.toHaveProperty("auth-code")
    expect(values).not.toHaveProperty("totp")
    expect(values).not.toHaveProperty("sms-code")
  })

  it("does not let field memory re-enable sensitive username fields", () => {
    document.body.innerHTML = `
      <label for="iam-username">IAM username</label>
      <input id="iam-username" name="username" />
      <label for="login-user-id">ログインID</label>
      <input id="login-user-id" name="login_user_id" />
    `
    const usernameField = document.getElementById("iam-username") as HTMLInputElement
    const loginUserIdField = document.getElementById("login-user-id") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(usernameField))
    const loginUserIdSignature = buildFieldSignature(buildFieldDescriptor(loginUserIdField))
    const snapshot = createSnapshot()
    snapshot.fieldMemory = {
      [`example.com::${fieldSignature}`]: {
        hostname: "example.com",
        fieldSignature,
        profileKey: "fullName",
        lastAutofilledValue: "old-user",
        lastUserValue: "learned-user",
        timesAutofilled: 2,
        timesCorrected: 1,
        updatedAt: new Date().toISOString()
      },
      [`example.com::${loginUserIdSignature}`]: {
        hostname: "example.com",
        fieldSignature: loginUserIdSignature,
        profileKey: "fullName",
        lastAutofilledValue: "old-user-id",
        lastUserValue: "learned-user-id",
        timesAutofilled: 2,
        timesCorrected: 1,
        updatedAt: new Date().toISOString()
      }
    }

    expect(collectAutofillCandidates(document, snapshot, window.location)).toEqual([])
  })

  it("fills learned custom fields even when they do not map to the fixed profile", () => {
    document.body.innerHTML = `
      <label for="member-id">会員番号</label>
      <input id="member-id" name="member_id" />
    `
    const memberField = document.getElementById("member-id") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(memberField))
    const snapshot = createSnapshot()
    snapshot.profile = createEmptyProfile()
    snapshot.fieldMemory = {
      [`example.com::${fieldSignature}`]: {
        hostname: "example.com",
        fieldSignature,
        learnedLabel: "会員番号",
        lastAutofilledValue: "",
        lastUserValue: "MEM-12345",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    const values = valueById(snapshot)

    expect(values["member-id"]).toBe("MEM-12345")
  })

  it("keeps learned bank branch and account number fields fillable", () => {
    document.body.innerHTML = `
      <label for="branch-code">INPUT_FORM:INPUT_BRANCH_CODE</label>
      <input id="branch-code" name="INPUT_FORM:INPUT_BRANCH_CODE" />
      <label for="account-number">INPUT_FORM:INPUT_ACCOUNT_NUMBER</label>
      <input id="account-number" name="INPUT_FORM:INPUT_ACCOUNT_NUMBER" />
    `
    const branchField = document.getElementById("branch-code") as HTMLInputElement
    const accountField = document.getElementById("account-number") as HTMLInputElement
    const branchSignature = buildFieldSignature(buildFieldDescriptor(branchField))
    const accountSignature = buildFieldSignature(buildFieldDescriptor(accountField))
    const snapshot = createSnapshot()
    snapshot.profile = createEmptyProfile()
    snapshot.fieldMemory = {
      [`example.com::${branchSignature}`]: {
        hostname: "example.com",
        fieldSignature: branchSignature,
        learnedLabel: "INPUT_FORM:INPUT_BRANCH_CODE",
        lastAutofilledValue: "",
        lastUserValue: "235",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      },
      [`example.com::${accountSignature}`]: {
        hostname: "example.com",
        fieldSignature: accountSignature,
        learnedLabel: "INPUT_FORM:INPUT_ACCOUNT_NUMBER",
        lastAutofilledValue: "",
        lastUserValue: "1234567",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    const values = valueById(snapshot)

    expect(values).toMatchObject({
      "branch-code": "235",
      "account-number": "1234567"
    })
  })

  it("keeps learned payment card number, expiry and holder fields fillable", () => {
    document.body.innerHTML = `
      <label for="card-number">Card number</label>
      <input id="card-number" name="card_number" autocomplete="cc-number" />
      <label for="card-exp">Expiry</label>
      <input id="card-exp" name="card_exp" autocomplete="cc-exp" />
      <label for="card-name">Name on card</label>
      <input id="card-name" name="card_name" autocomplete="cc-name" />
    `
    const cardNumber = document.getElementById("card-number") as HTMLInputElement
    const cardExp = document.getElementById("card-exp") as HTMLInputElement
    const cardName = document.getElementById("card-name") as HTMLInputElement
    const cardNumberSignature = buildFieldSignature(buildFieldDescriptor(cardNumber))
    const cardExpSignature = buildFieldSignature(buildFieldDescriptor(cardExp))
    const cardNameSignature = buildFieldSignature(buildFieldDescriptor(cardName))
    const snapshot = createSnapshot()
    snapshot.profile = createEmptyProfile()
    snapshot.secureVaultValues = {
      [getSecureVaultEntryKey("example.com", cardNumberSignature)]: "4111111111111111",
      [getSecureVaultEntryKey("example.com", cardExpSignature)]: "12/30",
      [getSecureVaultEntryKey("example.com", cardNameSignature)]: "HANAKO YAMADA"
    }

    const values = valueById(snapshot)

    expect(values).toMatchObject({
      "card-number": "4111111111111111",
      "card-exp": "12/30",
      "card-name": "HANAKO YAMADA"
    })
  })

  it("does not persist or fill card security code candidates", () => {
    document.body.innerHTML = `
      <label for="cvv">Security code</label>
      <input id="cvv" name="card_cvv" autocomplete="cc-csc" />
    `
    const cvvField = document.getElementById("cvv") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(cvvField))
    const snapshot = createSnapshot()
    snapshot.fieldMemory = {
      [`example.com::${fieldSignature}`]: {
        hostname: "example.com",
        fieldSignature,
        lastAutofilledValue: "",
        lastUserValue: "123",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    expect(collectAutofillCandidates(document, snapshot, window.location)).toEqual([])
  })

  it("blocks generic security code fields without card context", () => {
    document.body.innerHTML = `
      <label for="security-code">Security code</label>
      <input id="security-code" name="security_code" />
    `
    const securityCodeField = document.getElementById("security-code") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(securityCodeField))
    const snapshot = createSnapshot()
    snapshot.fieldMemory = {
      [`example.com::${fieldSignature}`]: {
        hostname: "example.com",
        fieldSignature,
        lastAutofilledValue: "",
        lastUserValue: "123",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    expect(collectAutofillCandidates(document, snapshot, window.location)).toEqual([])
  })

  it("does not let memory re-enable pin or secret answer fields", () => {
    document.body.innerHTML = `
      <label for="pin">PIN</label>
      <input id="pin" name="pin" />
      <label for="secret-word">Secret word</label>
      <input id="secret-word" name="secret_word" />
    `
    const pinField = document.getElementById("pin") as HTMLInputElement
    const secretField = document.getElementById("secret-word") as HTMLInputElement
    const pinSignature = buildFieldSignature(buildFieldDescriptor(pinField))
    const secretSignature = buildFieldSignature(buildFieldDescriptor(secretField))
    const snapshot = createSnapshot()
    snapshot.fieldMemory = {
      [`example.com::${pinSignature}`]: {
        hostname: "example.com",
        fieldSignature: pinSignature,
        lastAutofilledValue: "",
        lastUserValue: "1234",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      },
      [`example.com::${secretSignature}`]: {
        hostname: "example.com",
        fieldSignature: secretSignature,
        lastAutofilledValue: "",
        lastUserValue: "first pet",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    expect(collectAutofillCandidates(document, snapshot, window.location)).toEqual([])
  })

  it("does not let custom field memory re-enable one-time-code fields", () => {
    document.body.innerHTML = `
      <label for="otp">Email OTP</label>
      <input id="otp" name="email_otp" autocomplete="one-time-code" />
    `
    const otpField = document.getElementById("otp") as HTMLInputElement
    const fieldSignature = buildFieldSignature(buildFieldDescriptor(otpField))
    const snapshot = createSnapshot()
    snapshot.fieldMemory = {
      [`example.com::${fieldSignature}`]: {
        hostname: "example.com",
        fieldSignature,
        lastAutofilledValue: "",
        lastUserValue: "123456",
        timesAutofilled: 0,
        timesCorrected: 0,
        timesLearned: 1,
        updatedAt: new Date().toISOString()
      }
    }

    expect(collectAutofillCandidates(document, snapshot, window.location)).toEqual([])
  })

  it("skips hidden and aria-hidden fields", () => {
    document.body.innerHTML = `
      <input id="hidden-attr" name="email" hidden />
      <div aria-hidden="true">
        <input id="aria-hidden" name="email" />
      </div>
      <div inert>
        <input id="inert-field" name="email" />
      </div>
      <input id="display-none" name="email" style="display: none" />
      <input id="visibility-hidden" name="email" style="visibility: hidden" />
      <label for="email">Email</label>
      <input id="email" name="email" />
    `

    const values = valueById(createSnapshot())

    expect(values).toEqual({
      email: "hanako@example.test"
    })
  })
})
