import {
  buildFieldDescriptor,
  buildFieldSignature,
  exportAutofillRules,
  getDomainPolicy,
  matchProfileKey,
  normalizeText,
  PROFILE_KEYS,
  resolveSelectOptionValue
} from "@autofill-browser/autofill-core"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

describe("autofill-core", () => {
  it("matches Japanese postal code fields", () => {
    document.body.innerHTML = `
      <label for="postal">郵便番号</label>
      <input id="postal" name="postal_code" />
    `

    const field = document.getElementById("postal") as HTMLInputElement
    const descriptor = buildFieldDescriptor(field)

    expect(matchProfileKey(descriptor)).toBe("postalCode")
  })

  it("uses negative matchers for kana fields", () => {
    document.body.innerHTML = `
      <label for="name-kana">お名前(カナ)</label>
      <input id="name-kana" name="nameKana" />
    `

    const field = document.getElementById("name-kana") as HTMLInputElement
    const descriptor = buildFieldDescriptor(field)

    expect(matchProfileKey(descriptor)).toBeNull()
  })

  it("distinguishes family and given name fields", () => {
    document.body.innerHTML = `
      <label for="family-name">姓</label>
      <input id="family-name" name="billing[last_name]" />
      <label for="given-name">名</label>
      <input id="given-name" name="billing[first_name]" />
    `

    const familyField = document.getElementById("family-name") as HTMLInputElement
    const givenField = document.getElementById("given-name") as HTMLInputElement

    expect(matchProfileKey(buildFieldDescriptor(familyField))).toBe("familyName")
    expect(matchProfileKey(buildFieldDescriptor(givenField))).toBe("givenName")
  })

  it("uses aria-labelledby and nearby text for app-style Japanese name fields", () => {
    document.body.innerHTML = `
      <div>
        <span id="apple-given-label">名</span>
        <input id="apple-given" aria-labelledby="apple-given-label" />
      </div>
      <div>
        <span>姓</span>
        <input id="apple-family" />
      </div>
    `

    const givenField = document.getElementById("apple-given") as HTMLInputElement
    const familyField = document.getElementById("apple-family") as HTMLInputElement

    expect(matchProfileKey(buildFieldDescriptor(givenField))).toBe("givenName")
    expect(matchProfileKey(buildFieldDescriptor(familyField))).toBe("familyName")
  })

  it("matches city and address line 2 independently", () => {
    document.body.innerHTML = `
      <label for="city">市町村</label>
      <input id="city" name="billing[city]" />
      <label for="address2">住所欄2</label>
      <input id="address2" name="billing[address2]" />
    `

    const cityField = document.getElementById("city") as HTMLInputElement
    const address2Field = document.getElementById("address2") as HTMLInputElement

    expect(matchProfileKey(buildFieldDescriptor(cityField))).toBe("city")
    expect(matchProfileKey(buildFieldDescriptor(address2Field))).toBe("addressLine2")
  })

  it("does not match username or cardholder name fields as profile names", () => {
    document.body.innerHTML = `
      <label for="username">User name</label>
      <input id="username" name="username" />
      <label for="cardholder">Cardholder name</label>
      <input id="cardholder" name="cardholder_name" />
    `

    const usernameField = document.getElementById("username") as HTMLInputElement
    const cardholderField = document.getElementById("cardholder") as HTMLInputElement

    expect(matchProfileKey(buildFieldDescriptor(usernameField))).toBeNull()
    expect(matchProfileKey(buildFieldDescriptor(cardholderField))).toBeNull()
  })

  it("does not match phone extension fields as phone numbers", () => {
    document.body.innerHTML = `
      <label for="phone-extension">内線</label>
      <input id="phone-extension" name="phoneNumberExtension" />
    `

    const field = document.getElementById("phone-extension") as HTMLInputElement

    expect(matchProfileKey(buildFieldDescriptor(field))).toBeNull()
  })

  it("builds stable field signatures", () => {
    document.body.innerHTML = `
      <label for="company">会社名</label>
      <input id="company" name="company" autocomplete="organization" />
    `

    const field = document.getElementById("company") as HTMLInputElement
    const first = buildFieldSignature(buildFieldDescriptor(field))
    const second = buildFieldSignature(buildFieldDescriptor(field))

    expect(first).toBe(second)
    expect(normalizeText(first)).toContain("organization")
  })

  it("resolves select options for prefecture values", () => {
    document.body.innerHTML = `
      <label for="prefecture">都道府県</label>
      <select id="prefecture" name="prefecture">
        <option value="">選択してください</option>
        <option value="tokyo">東京都</option>
        <option value="kanagawa">神奈川県</option>
      </select>
    `

    const field = document.getElementById("prefecture") as HTMLSelectElement
    const descriptor = buildFieldDescriptor(field)

    expect(resolveSelectOptionValue(descriptor, "東京都")).toBe("tokyo")
  })

  it("falls back to default domain policy", () => {
    expect(getDomainPolicy({}, "example.com")).toBe("default")
    expect(getDomainPolicy({ "example.com": "blacklist" }, "example.com")).toBe("blacklist")
  })

  it("exports profile rules for the Android asset", () => {
    const exportedRules = exportAutofillRules()
    const androidRules = JSON.parse(
      readFileSync(resolve(process.cwd(), "../android-browser/app/src/main/assets/autofill-rules.json"), "utf8")
    )

    expect(exportedRules.schemaVersion).toBe(1)
    expect(exportedRules.profileKeys).toEqual([...PROFILE_KEYS])
    expect(exportedRules.rules.map((rule) => rule.key)).toContain("email")
    expect(androidRules).toEqual(exportedRules)
  })
})
