import {
  buildFieldDescriptor,
  buildFieldSignature,
  matchProfileKey,
  normalizeText,
  resolveSelectOptionValue,
  resolveValueFromProfile,
  type FieldDescriptor,
  type FieldMemoryEntry,
  type ProfileKey
} from "@autofill-browser/autofill-core"

import type { StorageSnapshot } from "./storage"

export type FieldElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement

export type AutofillCandidate = {
  field: FieldElement
  descriptor: FieldDescriptor
  fieldSignature: string
  profileKey?: ProfileKey
  fieldMemoryEntry?: FieldMemoryEntry
  rawValue: string
  appliedValue: string
}

type CandidateDraft = Omit<AutofillCandidate, "rawValue" | "appliedValue">

type CandidateContext = {
  groupIndex: number
  groupSize: number
  pageProfileKeys: Set<ProfileKey>
}

const BLOCKED_INPUT_TYPES = new Set([
  "password",
  "hidden",
  "search",
  "submit",
  "button",
  "checkbox",
  "radio",
  "file"
])

const SENSITIVE_FIELD_IDENTITY_TOKENS = [
  "captcha",
  "recaptcha",
  "h captcha",
  "g recaptcha",
  "apbct",
  "honeypot",
  "csrf",
  "xsrf",
  "token",
  "otp",
  "one time code",
  "2fa",
  "mfa",
  "verification code",
  "passcode",
  "password",
  "passwd",
  "username",
  "user name",
  "iam username"
]

const getDescriptorIdentity = (descriptor: FieldDescriptor) =>
  normalizeText(
    [
      descriptor.name,
      descriptor.id,
      descriptor.autocomplete,
      descriptor.placeholder,
      descriptor.ariaLabel,
      descriptor.labelText
    ].join(" ")
  )

const hasIdentityToken = (identity: string, tokens: string[]) => tokens.some((token) => identity.includes(token))

const hasHiddenAncestor = (field: FieldElement) => Boolean(field.closest("[hidden], [aria-hidden='true'], [inert]"))

const hasHiddenComputedStyle = (field: FieldElement) => {
  const view = field.ownerDocument.defaultView
  if (!view) {
    return false
  }

  for (let element: Element | null = field; element; element = element.parentElement) {
    const style = view.getComputedStyle(element)
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") {
      return true
    }
  }

  return false
}

const isSensitiveAutofillTarget = (descriptor: FieldDescriptor, remoteTokens: string[] = []) =>
  hasIdentityToken(getDescriptorIdentity(descriptor), [...SENSITIVE_FIELD_IDENTITY_TOKENS, ...remoteTokens])

const compactDigits = (value: string) => value.replace(/\D+/g, "")

const splitPostalCode = (postalCode: string) => {
  const digits = compactDigits(postalCode)
  if (digits.length < 7) {
    return [digits, ""]
  }

  return [digits.slice(0, 3), digits.slice(3, 7)]
}

const splitPhoneNumber = (phone: string) => {
  const digits = compactDigits(phone)
  if (!digits) {
    return ["", "", ""]
  }

  if (/^(050|060|070|080|090)\d{8}$/.test(digits)) {
    return [digits.slice(0, 3), digits.slice(3, 7), digits.slice(7, 11)]
  }

  if (/^(03|06)\d{8}$/.test(digits)) {
    return [digits.slice(0, 2), digits.slice(2, 6), digits.slice(6, 10)]
  }

  if (/^0\d{9}$/.test(digits)) {
    return [digits.slice(0, 3), digits.slice(3, 6), digits.slice(6, 10)]
  }

  if (/^0\d{10}$/.test(digits)) {
    return [digits.slice(0, 3), digits.slice(3, 7), digits.slice(7, 11)]
  }

  return [digits, "", ""]
}

const getStreetPart = (profile: StorageSnapshot["profile"]) => {
  const addressLine1 = profile.addressLine1.trim()
  const city = profile.city.trim()

  if (!addressLine1) {
    return ""
  }

  if (city && addressLine1.startsWith(city)) {
    const stripped = addressLine1.slice(city.length).trim()
    return stripped || addressLine1
  }

  const matched = addressLine1.match(/^(.+?)(\d[\d０-９\-−ー丁目番地].*)$/u)
  if (matched?.[2]) {
    return matched[2].trim()
  }

  return addressLine1
}

const joinCompact = (parts: string[]) => parts.map((part) => part.trim()).filter(Boolean).join("")

const hasLearnedCorrection = (memoryEntry?: FieldMemoryEntry) =>
  Boolean(memoryEntry && (memoryEntry.timesCorrected > 0 || memoryEntry.lastUserValue.trim().length > 0))

const resolveMemoryEntry = (
  snapshot: StorageSnapshot,
  descriptor: FieldDescriptor,
  fieldSignature: string
) => snapshot.fieldMemory[`${descriptor.hostname}::${fieldSignature}`]

const resolveProfileKeyForDescriptor = (descriptor: FieldDescriptor, memoryEntry?: FieldMemoryEntry) =>
  hasLearnedCorrection(memoryEntry) ? memoryEntry?.profileKey ?? matchProfileKey(descriptor) : matchProfileKey(descriptor)

export type LearnableFieldDescriptor = {
  descriptor: FieldDescriptor
  fieldSignature: string
  profileKey: ProfileKey | null
  fieldMemoryEntry?: FieldMemoryEntry
}

export const describeLearnableField = (
  field: Element,
  snapshot: StorageSnapshot,
  currentLocation: Pick<Location, "hostname" | "href">
): LearnableFieldDescriptor | null => {
  if (!isEligibleField(field)) {
    return null
  }

  const descriptor = buildFieldDescriptor(field, currentLocation)
  if (isSensitiveAutofillTarget(descriptor, snapshot.remoteRules?.blockedIdentityTokens ?? [])) {
    return null
  }

  const fieldSignature = buildFieldSignature(descriptor)
  const fieldMemoryEntry = resolveMemoryEntry(snapshot, descriptor, fieldSignature)

  return {
    descriptor,
    fieldSignature,
    profileKey: resolveProfileKeyForDescriptor(descriptor, fieldMemoryEntry),
    fieldMemoryEntry
  }
}

const resolvePostalValue = (descriptor: FieldDescriptor, postalCode: string, context: CandidateContext) => {
  const identity = getDescriptorIdentity(descriptor)
  const [first, second] = splitPostalCode(postalCode)

  if (
    hasIdentityToken(identity, [
      "zip1",
      "zip 1",
      "postal1",
      "postal 1",
      "postcode1",
      "postcode 1",
      "post1",
      "post 1",
      "郵便番号1",
      "前半",
      "前",
      "3桁",
      "first"
    ])
  ) {
    return first
  }

  if (
    hasIdentityToken(identity, [
      "zip2",
      "zip 2",
      "postal2",
      "postal 2",
      "postcode2",
      "postcode 2",
      "post2",
      "post 2",
      "郵便番号2",
      "後半",
      "後",
      "4桁",
      "last",
      "second"
    ])
  ) {
    return second
  }

  if (context.groupSize === 2) {
    return context.groupIndex === 0 ? first : second
  }

  return compactDigits(postalCode)
}

const resolvePhoneValue = (descriptor: FieldDescriptor, phone: string, context: CandidateContext) => {
  const identity = getDescriptorIdentity(descriptor)
  const segments = splitPhoneNumber(phone)

  if (
    hasIdentityToken(identity, [
      "tel1",
      "tel 1",
      "phone1",
      "phone 1",
      "mobile1",
      "mobile 1",
      "電話番号1",
      "前半",
      "先頭",
      "first",
      "area",
      "市外局番"
    ])
  ) {
    return segments[0]
  }

  if (
    hasIdentityToken(identity, [
      "tel2",
      "tel 2",
      "phone2",
      "phone 2",
      "mobile2",
      "mobile 2",
      "電話番号2",
      "middle",
      "mid",
      "中央",
      "真ん中",
      "second"
    ])
  ) {
    return segments[1]
  }

  if (
    hasIdentityToken(identity, [
      "tel3",
      "tel 3",
      "phone3",
      "phone 3",
      "mobile3",
      "mobile 3",
      "電話番号3",
      "後半",
      "末尾",
      "last",
      "third"
    ])
  ) {
    return segments[2]
  }

  if (context.groupSize === 3) {
    return segments[context.groupIndex] ?? ""
  }

  return compactDigits(phone)
}

const resolveAddressLine1Value = (
  descriptor: FieldDescriptor,
  profile: StorageSnapshot["profile"],
  context: CandidateContext
) => {
  const identity = getDescriptorIdentity(descriptor)
  const hasSeparatePrefecture = context.pageProfileKeys.has("prefecture")
  const hasSeparateCity = context.pageProfileKeys.has("city")
  const hasSeparateAddressLine2 = context.pageProfileKeys.has("addressLine2")
  const streetPart = getStreetPart(profile)
  const explicitLine1 = hasIdentityToken(identity, [
    "address line1",
    "address 1",
    "address1",
    "addr1",
    "line1",
    "line 1",
    "住所1",
    "住所欄1",
    "番地",
    "丁目"
  ])
  const genericAddress = hasIdentityToken(identity, [
    "street address",
    "street-address",
    "full address",
    "billing address",
    "shipping address"
  ]) || (identity === "住所" || identity === "address")

  if (genericAddress && !explicitLine1) {
    return joinCompact([
      hasSeparatePrefecture ? "" : profile.prefecture,
      hasSeparateCity ? "" : profile.addressLine1,
      hasSeparateCity ? streetPart : "",
      hasSeparateAddressLine2 ? "" : profile.addressLine2
    ])
  }

  if (hasSeparateCity) {
    return joinCompact([streetPart, hasSeparateAddressLine2 ? "" : profile.addressLine2])
  }

  return joinCompact([profile.addressLine1, hasSeparateAddressLine2 ? "" : profile.addressLine2])
}

const resolveProfileValueForField = (
  descriptor: FieldDescriptor,
  profileKey: ProfileKey,
  profile: StorageSnapshot["profile"],
  context: CandidateContext
) => {
  switch (profileKey) {
    case "postalCode":
      return resolvePostalValue(descriptor, profile.postalCode, context)
    case "phone":
      return resolvePhoneValue(descriptor, profile.phone, context)
    case "addressLine1":
      return resolveAddressLine1Value(descriptor, profile, context)
    default:
      return resolveValueFromProfile(profileKey, profile)
  }
}

const resolveRawValue = (
  descriptor: FieldDescriptor,
  profileKey: ProfileKey | undefined,
  profile: StorageSnapshot["profile"],
  memoryEntry: FieldMemoryEntry | undefined,
  context: CandidateContext
) => {
  const rememberedValue = hasLearnedCorrection(memoryEntry) ? memoryEntry?.lastUserValue.trim() || "" : ""
  if (!profileKey) {
    return rememberedValue
  }

  return rememberedValue || resolveProfileValueForField(descriptor, profileKey, profile, context)
}

export const getFieldCurrentValue = (field: FieldElement) => {
  if (field instanceof HTMLSelectElement) {
    return field.value
  }

  return field.value
}

export const hasUserProvidedValue = (field: FieldElement) => getFieldCurrentValue(field).trim().length > 0

export const isEligibleField = (field: Element): field is FieldElement => {
  if (!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement || field instanceof HTMLSelectElement)) {
    return false
  }

  if (field instanceof HTMLInputElement) {
    const type = normalizeText(field.type)
    if (BLOCKED_INPUT_TYPES.has(type)) {
      return false
    }
  }

  const isReadOnly = field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement ? field.readOnly : false

  return !field.disabled && !isReadOnly && !hasHiddenAncestor(field) && !hasHiddenComputedStyle(field)
}

export const resolveAppliedValue = (
  descriptor: FieldDescriptor,
  profileKey: ProfileKey | undefined,
  profile: StorageSnapshot["profile"],
  memoryEntry: FieldMemoryEntry | undefined,
  context: CandidateContext
) => {
  const rawValue = resolveRawValue(descriptor, profileKey, profile, memoryEntry, context)
  if (!rawValue) {
    return null
  }

  if (descriptor.tagName === "select") {
    const selectValue = resolveSelectOptionValue(descriptor, rawValue)
    if (!selectValue) {
      return null
    }

    return {
      rawValue,
      appliedValue: selectValue
    }
  }

  return {
    rawValue,
    appliedValue: rawValue
  }
}

export const collectAutofillCandidates = (
  root: ParentNode,
  snapshot: StorageSnapshot,
  currentLocation: Pick<Location, "hostname" | "href">
) => {
  const fields = Array.from(root.querySelectorAll("input, textarea, select")).filter(isEligibleField)
  const drafts: CandidateDraft[] = []

  for (const field of fields) {
    if (hasUserProvidedValue(field)) {
      continue
    }

    const learnableField = describeLearnableField(field, snapshot, currentLocation)
    if (!learnableField) {
      continue
    }

    const hasLearnedValue = hasLearnedCorrection(learnableField.fieldMemoryEntry)
    if (!learnableField.profileKey && !hasLearnedValue) {
      continue
    }

    drafts.push({
      field,
      descriptor: learnableField.descriptor,
      fieldSignature: learnableField.fieldSignature,
      fieldMemoryEntry: learnableField.fieldMemoryEntry,
      profileKey: learnableField.profileKey ?? undefined
    })
  }

  const pageProfileKeys = new Set(
    drafts.flatMap((candidate) => (candidate.profileKey ? [candidate.profileKey] : []))
  )

  return drafts.flatMap((draft) => {
    const sameKeyDrafts = draft.profileKey
      ? drafts.filter((candidate) => candidate.profileKey === draft.profileKey)
      : [draft]
    const context: CandidateContext = {
      groupIndex: sameKeyDrafts.findIndex((candidate) => candidate.field === draft.field),
      groupSize: sameKeyDrafts.length,
      pageProfileKeys
    }
    const resolvedValue = resolveAppliedValue(
      draft.descriptor,
      draft.profileKey,
      snapshot.profile,
      draft.fieldMemoryEntry,
      context
    )

    if (!resolvedValue) {
      return []
    }

    return [
      {
        ...draft,
        rawValue: resolvedValue.rawValue,
        appliedValue: resolvedValue.appliedValue
      }
    ]
  })
}
