import autofillRulesData from "./autofill-rules.json"

export const PROFILE_KEYS = [
  "familyName",
  "givenName",
  "fullName",
  "email",
  "phone",
  "organization",
  "postalCode",
  "prefecture",
  "city",
  "addressLine1",
  "addressLine2"
] as const

export type ProfileKey = (typeof PROFILE_KEYS)[number]

export type StoredProfile = Record<ProfileKey, string>

export type RulePatternDefinition = {
  source: string
  flags: string
}

export type ProfileRuleDefinition = {
  key: ProfileKey
  includes: string[]
  patterns?: RulePatternDefinition[]
  excludes?: string[]
  excludePatterns?: RulePatternDefinition[]
}

export type ExportedAutofillRules = {
  schemaVersion: 1
  profileKeys: ProfileKey[]
  rules: ProfileRuleDefinition[]
}

export type DomainPolicy = "default" | "whitelist" | "blacklist"

export type AutofillSettings = {
  enabled: boolean
  observeDynamicForms: boolean
  minMatchCount: number
}

export type SelectOptionDescriptor = {
  label: string
  value: string
}

export type FieldDescriptor = {
  hostname: string
  url: string
  tagName: string
  type: string
  name: string
  id: string
  autocomplete: string
  placeholder: string
  ariaLabel: string
  labelText: string
  selectOptions: SelectOptionDescriptor[]
}

export type FieldMemoryEntry = {
  hostname: string
  fieldSignature: string
  profileKey: ProfileKey
  lastAutofilledValue: string
  lastUserValue: string
  timesAutofilled: number
  timesCorrected: number
  updatedAt: string
}

export type AutofillEventSource =
  | "automatic-load"
  | "mutation-observer"
  | "navigation"
  | "popup"
  | "storage-update"
  | "popup-ui"

export type EventLogType =
  | "autofill_run"
  | "field_filled"
  | "field_corrected_by_user"
  | "setting_changed"
  | "domain_policy_changed"
  | "profile_updated"
  | "manual_autofill_triggered"

export type EventLogEntry = {
  id: string
  type: EventLogType
  timestamp: string
  hostname: string
  url: string
  fieldSignature?: string
  profileKey?: ProfileKey
  previousValue?: string
  nextValue?: string
  source: AutofillEventSource
  runId?: string
  detail?: string
}

export const DEFAULT_AUTOFILL_SETTINGS: AutofillSettings = {
  enabled: true,
  observeDynamicForms: true,
  minMatchCount: 1
}

export const createEmptyProfile = (): StoredProfile => ({
  familyName: "",
  givenName: "",
  fullName: "",
  email: "",
  phone: "",
  organization: "",
  postalCode: "",
  prefecture: "",
  city: "",
  addressLine1: "",
  addressLine2: ""
})

export const DEFAULT_PROFILE: StoredProfile = createEmptyProfile()

export const isProfileConfigured = (profile: StoredProfile) =>
  PROFILE_KEYS.some((key) => profile[key].trim().length > 0)

export const normalizeText = (value: string | null | undefined) =>
  (value ?? "")
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[_\-/:.,()[\]{}]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()

type FieldElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement

const readLabelText = (field: FieldElement) => {
  const labels = field.labels ? Array.from(field.labels) : []

  if (labels.length > 0) {
    return labels
      .map((label) => label.textContent ?? "")
      .join(" ")
      .trim()
  }

  if (field.id) {
    const inlineLabel = field.ownerDocument.querySelector(`label[for="${field.id}"]`)
    if (inlineLabel?.textContent) {
      return inlineLabel.textContent.trim()
    }
  }

  const wrappingLabel = field.closest("label")
  return wrappingLabel?.textContent?.trim() ?? ""
}

export const buildFieldDescriptor = (
  field: FieldElement,
  currentLocation: Pick<Location, "hostname" | "href"> = window.location
): FieldDescriptor => ({
  hostname: currentLocation.hostname,
  url: currentLocation.href,
  tagName: field.tagName.toLowerCase(),
  type: normalizeText(field.getAttribute("type")) || (field.tagName === "SELECT" ? "select" : ""),
  name: field.getAttribute("name") ?? "",
  id: field.id,
  autocomplete: field.getAttribute("autocomplete") ?? "",
  placeholder: field.getAttribute("placeholder") ?? "",
  ariaLabel: field.getAttribute("aria-label") ?? "",
  labelText: readLabelText(field),
  selectOptions:
    field instanceof HTMLSelectElement
      ? Array.from(field.options).map((option) => ({
          label: option.text,
          value: option.value
        }))
      : []
})

export const buildFieldSignature = (descriptor: FieldDescriptor) =>
  [
    descriptor.tagName,
    descriptor.type,
    descriptor.name,
    descriptor.id,
    descriptor.autocomplete,
    descriptor.placeholder,
    descriptor.ariaLabel,
    descriptor.labelText
  ]
    .map((value) => normalizeText(value))
    .join("|")

const combinedFieldText = (descriptor: FieldDescriptor) =>
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

const PROFILE_RULE_DEFINITIONS = autofillRulesData.rules as ProfileRuleDefinition[]

const cloneProfileRuleDefinitions = () =>
  PROFILE_RULE_DEFINITIONS.map((rule) => ({
    key: rule.key,
    includes: [...rule.includes],
    ...(rule.patterns ? { patterns: rule.patterns.map((pattern) => ({ ...pattern })) } : {}),
    ...(rule.excludes ? { excludes: [...rule.excludes] } : {}),
    ...(rule.excludePatterns
      ? { excludePatterns: rule.excludePatterns.map((pattern) => ({ ...pattern })) }
      : {})
  }))

export const exportAutofillRules = (): ExportedAutofillRules => ({
  schemaVersion: 1,
  profileKeys: [...PROFILE_KEYS],
  rules: cloneProfileRuleDefinitions()
})

const compilePattern = (pattern: RulePatternDefinition) => new RegExp(pattern.source, pattern.flags)

const PROFILE_RULES: Array<{
  key: ProfileKey
  includes: string[]
  patterns?: RegExp[]
  excludes?: string[]
  excludePatterns?: RegExp[]
}> = PROFILE_RULE_DEFINITIONS.map((rule) => ({
  key: rule.key,
  includes: rule.includes,
  patterns: rule.patterns?.map(compilePattern),
  excludes: rule.excludes,
  excludePatterns: rule.excludePatterns?.map(compilePattern)
}))

export const matchProfileKey = (descriptor: FieldDescriptor): ProfileKey | null => {
  const identity = combinedFieldText(descriptor)

  if (!identity) {
    return null
  }

  for (const rule of PROFILE_RULES) {
    const matchedByIncludes = rule.includes.some((matcher) => identity.includes(normalizeText(matcher)))
    const matchedByPatterns = rule.patterns?.some((pattern) => pattern.test(identity)) ?? false
    const matched = matchedByIncludes || matchedByPatterns
    if (!matched) {
      continue
    }

    const blockedByIncludes = rule.excludes?.some((matcher) => identity.includes(normalizeText(matcher))) ?? false
    const blockedByPatterns = rule.excludePatterns?.some((pattern) => pattern.test(identity)) ?? false
    const blocked = blockedByIncludes || blockedByPatterns
    if (!blocked) {
      return rule.key
    }
  }

  return null
}

export const resolveValueFromProfile = (profileKey: ProfileKey, profile: StoredProfile) => profile[profileKey].trim()

const buildSelectMatchCandidates = (desiredValue: string) => {
  const base = normalizeText(desiredValue)
  const withoutPrefectureSuffix = base.replace(/(都|道|府|県)$/u, "")
  return Array.from(new Set([base, withoutPrefectureSuffix].filter(Boolean)))
}

export const resolveSelectOptionValue = (descriptor: FieldDescriptor, desiredValue: string) => {
  const candidates = buildSelectMatchCandidates(desiredValue)

  if (descriptor.selectOptions.length === 0 || candidates.length === 0) {
    return null
  }

  for (const candidate of candidates) {
    const exact = descriptor.selectOptions.find((option) => {
      const normalizedLabel = normalizeText(option.label)
      const normalizedValue = normalizeText(option.value)
      return normalizedLabel === candidate || normalizedValue === candidate
    })

    if (exact) {
      return exact.value
    }
  }

  for (const candidate of candidates) {
    const partial = descriptor.selectOptions.find((option) => {
      const normalizedLabel = normalizeText(option.label)
      const normalizedValue = normalizeText(option.value)
      return normalizedLabel.includes(candidate) || normalizedValue.includes(candidate)
    })

    if (partial) {
      return partial.value
    }
  }

  return null
}

export const buildFieldMemoryKey = (hostname: string, fieldSignature: string) => `${hostname}::${fieldSignature}`

export const getDomainPolicy = (domainPolicies: Record<string, DomainPolicy>, hostname: string): DomainPolicy =>
  domainPolicies[hostname] ?? "default"
