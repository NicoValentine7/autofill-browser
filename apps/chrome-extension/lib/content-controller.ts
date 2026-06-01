import {
  getDomainPolicy,
  isProfileConfigured,
  type AutofillEventSource,
  type FieldDescriptor,
  type FieldMemoryEntry,
  type StoredProfile
} from "@autofill-browser/autofill-core"

import {
  collectAutofillCandidates,
  describeLearnableField,
  getFieldCurrentValue,
  type FieldElement
} from "./autofill-engine"
import {
  isSecureVaultField,
  requiresSecureAutofillConfirmation,
  shouldRedactFieldEventValues,
  type FieldSecurityClassification
} from "./field-security"
import type { ExtensionMessage } from "./messages"
import { validateSecureVaultKey, type SecureVaultValueUpdate } from "./secure-vault"
import {
  commitStorageChanges,
  createUnavailableStorageSnapshot,
  getStorageSnapshot,
  type NewEventLogEntry,
  type StorageSnapshot
} from "./storage"

type CorrectionState = {
  field: FieldElement
  hostname: string
  url: string
  fieldSignature: string
  profileKey: FieldMemoryEntry["profileKey"]
  securityClassification: FieldSecurityClassification
  secureVaultKind?: SecureVaultValueUpdate["kind"]
  autofilledValue: string
  runId: string
  lastPersistedValue: string
  timerId?: number
}

type LearningState = {
  lastPersistedValue: string
  timerId?: number
}

type ControllerDeps = {
  chromeApi?: typeof chrome
  windowObject?: Window
  documentObject?: Document
  locationObject?: Location
  debounceMs?: number
}

const createRunId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`

const MAX_LEARNED_VALUE_LENGTH = 300
const FIELD_SELECTOR = "input, textarea, select"
const USER_EDIT_AUTOFILL_SUPPRESSION_MS = 1500
const EXTENSION_CONTEXT_INVALIDATED_PATTERN = /Extension context invalidated/i

const hasLearnedFieldValues = (fieldMemory: StorageSnapshot["fieldMemory"]) =>
  Object.values(fieldMemory).some((entry) => entry.lastUserValue.trim().length > 0)

const hasSecureVaultValues = (secureVaultValues: StorageSnapshot["secureVaultValues"]) =>
  Object.values(secureVaultValues).some((value) => value.trim().length > 0)

const hasSecureVaultMaterial = (snapshot: StorageSnapshot) =>
  Object.keys(snapshot.secureVault.entries).length > 0 || Boolean(snapshot.secureVaultRecovery || snapshot.secureVault.keyCheck)

const canUseSecureVaultKey = async (snapshot: StorageSnapshot) =>
  Boolean(snapshot.secureVaultKey) &&
  (!snapshot.secureVault.keyCheck || (await validateSecureVaultKey(snapshot.secureVault, snapshot.secureVaultKey)))

const normalizeLearnedValue = (field: FieldElement) => {
  const value = getFieldCurrentValue(field).trim()
  if (!value || value.length > MAX_LEARNED_VALUE_LENGTH) {
    return ""
  }

  if (field instanceof HTMLTextAreaElement && value.split(/\r?\n/).length > 4) {
    return ""
  }

  return value
}

const getLearnedLabel = (descriptor: FieldDescriptor) =>
  [
    descriptor.labelText,
    descriptor.placeholder,
    descriptor.ariaLabel,
    descriptor.name,
    descriptor.id
  ]
    .map((value) => value.trim())
    .find(Boolean)

const promoteProfileValue = (
  profile: StoredProfile,
  profileKey: FieldMemoryEntry["profileKey"],
  value: string
) => {
  if (!profileKey || profile[profileKey].trim()) {
    return null
  }

  return {
    ...profile,
    [profileKey]: value
  }
}

const createEventValueFields = (
  securityClassification: FieldSecurityClassification,
  previousValue: string | undefined,
  nextValue: string | undefined
) =>
  shouldRedactFieldEventValues(securityClassification)
    ? {}
    : {
        previousValue,
        nextValue
      }

const appendRedactionDetail = (detail: string, securityClassification: FieldSecurityClassification) =>
  shouldRedactFieldEventValues(securityClassification) ? `${detail};values:redacted` : detail

const setNativeFieldValue = (field: FieldElement, value: string) => {
  if (field instanceof HTMLInputElement) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set
    setter?.call(field, value)
    return
  }

  if (field instanceof HTMLTextAreaElement) {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set
    setter?.call(field, value)
    return
  }

  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set
  setter?.call(field, value)
}

export const createAutofillController = ({
  chromeApi = chrome,
  windowObject = window,
  documentObject = document,
  locationObject = window.location,
  debounceMs = 300
}: ControllerDeps = {}) => {
  let snapshot: StorageSnapshot | null = null
  let observer: MutationObserver | null = null
  let mutationTimer: number | undefined
  let navigationTimer: number | undefined
  let initialized = false

  const autofillState = new WeakMap<FieldElement, CorrectionState>()
  const learningState = new WeakMap<FieldElement, LearningState>()
  const internalAutofillFields = new WeakSet<FieldElement>()
  const userInteractionTrackedFields = new WeakSet<FieldElement>()
  const composingFields = new WeakSet<FieldElement>()
  const lastUserEditAt = new WeakMap<FieldElement, number>()
  const processedRunKeys = new Set<string>()
  let learnedInputPersistQueue: Promise<void> = Promise.resolve()
  let extensionContextAvailable = true

  const getNow = () => windowObject.performance?.now?.() ?? Date.now()

  const isExtensionContextInvalidatedError = (error: unknown) =>
    error instanceof Error && EXTENSION_CONTEXT_INVALIDATED_PATTERN.test(error.message)

  const deactivateInvalidatedExtensionContext = () => {
    extensionContextAvailable = false
    windowObject.clearTimeout(mutationTimer)
    windowObject.clearTimeout(navigationTimer)
    observer?.disconnect()
    observer = null
    snapshot = createUnavailableStorageSnapshot()
  }

  const ignoreInvalidatedExtensionContext = async <Result>(operation: () => Promise<Result>) => {
    if (!extensionContextAvailable) {
      return undefined
    }

    try {
      return await operation()
    } catch (error) {
      if (isExtensionContextInvalidatedError(error)) {
        deactivateInvalidatedExtensionContext()
        return undefined
      }

      throw error
    }
  }

  const isComposingEvent = (event: Event | undefined) =>
    Boolean(event && "isComposing" in event && (event as InputEvent).isComposing)

  const markUserEdit = (field: FieldElement, event?: Event) => {
    if (internalAutofillFields.has(field)) {
      return
    }

    lastUserEditAt.set(field, getNow())
    if (isComposingEvent(event)) {
      composingFields.add(field)
    }
  }

  const isUserEditingField = (field: FieldElement) => {
    if (composingFields.has(field)) {
      return true
    }

    const lastEditAt = lastUserEditAt.get(field)
    return lastEditAt !== undefined && getNow() - lastEditAt < USER_EDIT_AUTOFILL_SUPPRESSION_MS
  }

  const attachUserInteractionTracking = (field: FieldElement) => {
    if (userInteractionTrackedFields.has(field)) {
      return
    }

    field.addEventListener("compositionstart", () => {
      if (!internalAutofillFields.has(field)) {
        composingFields.add(field)
        lastUserEditAt.set(field, getNow())
      }
    })
    field.addEventListener("compositionend", () => {
      if (!internalAutofillFields.has(field)) {
        composingFields.delete(field)
        lastUserEditAt.set(field, getNow())
      }
    })
    field.addEventListener("beforeinput", (event) => markUserEdit(field, event))
    field.addEventListener("input", (event) => markUserEdit(field, event))
    userInteractionTrackedFields.add(field)
  }

  const loadSnapshot = async () => {
    const nextSnapshot = await ignoreInvalidatedExtensionContext(() => getStorageSnapshot())
    if (!nextSnapshot) {
      return snapshot ?? createUnavailableStorageSnapshot()
    }

    snapshot = nextSnapshot
    syncLearningListeners(snapshot)
    syncMutationObserver()
    return snapshot
  }

  const canOperateOnPage = (nextSnapshot: StorageSnapshot) => {
    const domainPolicy = getDomainPolicy(nextSnapshot.domainPolicies, locationObject.hostname)
    if (domainPolicy === "blacklist") {
      return false
    }

    if (domainPolicy === "whitelist") {
      return true
    }

    return nextSnapshot.settings.enabled
  }

  const shouldAutofill = (nextSnapshot: StorageSnapshot) => {
    if (!canOperateOnPage(nextSnapshot)) {
      return false
    }

    return (
      isProfileConfigured(nextSnapshot.profile) ||
      hasLearnedFieldValues(nextSnapshot.fieldMemory) ||
      hasSecureVaultValues(nextSnapshot.secureVaultValues)
    )
  }

  const syncMutationObserver = () => {
    if (!snapshot) {
      return
    }

    const shouldObserve = snapshot.settings.observeDynamicForms && canOperateOnPage(snapshot)
    if (shouldObserve && !observer) {
      observer = new MutationObserver(() => {
        windowObject.clearTimeout(mutationTimer)
        mutationTimer = windowObject.setTimeout(() => {
          if (snapshot) {
            syncLearningListeners(snapshot)
          }
          void runAutofill("mutation-observer")
        }, debounceMs)
      })
      observer.observe(documentObject.documentElement, {
        childList: true,
        subtree: true
      })
      return
    }

    if (!shouldObserve && observer) {
      observer.disconnect()
      observer = null
    }
  }

  const persistCorrection = async (state: CorrectionState) => {
    if (!extensionContextAvailable) {
      return
    }

    const currentValue = getFieldCurrentValue(state.field).trim()

    if (!currentValue || currentValue === state.autofilledValue || currentValue === state.lastPersistedValue) {
      return
    }

    const currentSnapshot = snapshot ?? (await loadSnapshot())
    if (isSecureVaultField(state.securityClassification) && !(await canUseSecureVaultKey(currentSnapshot))) {
      return
    }

    state.lastPersistedValue = currentValue
    const nextSnapshot = await ignoreInvalidatedExtensionContext(() =>
      commitStorageChanges({
        ...(isSecureVaultField(state.securityClassification) && state.secureVaultKind
          ? {
              secureVaultUpdates: [
                {
                  hostname: state.hostname,
                  fieldSignature: state.fieldSignature,
                  kind: state.secureVaultKind,
                  value: currentValue,
                  incrementCorrected: true
                }
              ],
              fieldMemoryDeletes: [
                {
                  hostname: state.hostname,
                  fieldSignature: state.fieldSignature
                }
              ]
            }
          : {
              fieldMemoryUpdates: [
                {
                  hostname: state.hostname,
                  fieldSignature: state.fieldSignature,
                  profileKey: state.profileKey,
                  lastAutofilledValue: state.autofilledValue,
                  lastUserValue: currentValue,
                  timesAutofilled: currentSnapshot.fieldMemory[`${state.hostname}::${state.fieldSignature}`]?.timesAutofilled ?? 0,
                  timesCorrected: (currentSnapshot.fieldMemory[`${state.hostname}::${state.fieldSignature}`]?.timesCorrected ?? 0) + 1,
                  timesLearned: currentSnapshot.fieldMemory[`${state.hostname}::${state.fieldSignature}`]?.timesLearned ?? 0,
                  learnedLabel: currentSnapshot.fieldMemory[`${state.hostname}::${state.fieldSignature}`]?.learnedLabel,
                  updatedAt: new Date().toISOString()
                }
              ]
            }),
        eventEntries: [
          {
            type: "field_corrected_by_user",
            hostname: state.hostname,
            url: state.url,
            fieldSignature: state.fieldSignature,
            profileKey: state.profileKey,
            ...createEventValueFields(state.securityClassification, state.autofilledValue, currentValue),
            source: "storage-update",
            runId: state.runId,
            detail: appendRedactionDetail("correction", state.securityClassification)
          }
        ]
      })
    )

    if (nextSnapshot) {
      snapshot = nextSnapshot
    }
  }

  const attachCorrectionTracking = (
    field: FieldElement,
    state: Omit<CorrectionState, "field" | "lastPersistedValue" | "timerId">
  ) => {
    const nextState: CorrectionState = {
      ...state,
      field,
      lastPersistedValue: state.autofilledValue
    }

    autofillState.set(field, nextState)

    attachUserInteractionTracking(field)

    const schedulePersist = (immediate: boolean, event?: Event) => {
      const activeState = autofillState.get(field)
      if (!activeState) {
        return
      }

      if (isComposingEvent(event) || composingFields.has(field)) {
        return
      }

      if (activeState.timerId) {
        windowObject.clearTimeout(activeState.timerId)
      }

      if (immediate) {
        void persistCorrection(activeState)
        return
      }

      activeState.timerId = windowObject.setTimeout(() => {
        void persistCorrection(activeState)
      }, 400)
    }

    if (field.dataset.autofillTracked !== "true") {
      field.addEventListener("input", (event) => schedulePersist(false, event))
      field.addEventListener("compositionend", (event) => schedulePersist(false, event))
      field.addEventListener("change", (event) => schedulePersist(true, event))
      field.addEventListener("blur", (event) => schedulePersist(true, event))
      field.dataset.autofillTracked = "true"
    }
  }

  const persistLearnedInput = async (field: FieldElement, state: LearningState) => {
    if (!extensionContextAvailable) {
      return
    }

    if (autofillState.has(field) || internalAutofillFields.has(field)) {
      return
    }

    const currentValue = normalizeLearnedValue(field)
    if (!currentValue || currentValue === state.lastPersistedValue) {
      return
    }

    const currentSnapshot = snapshot ?? (await loadSnapshot())
    if (!canOperateOnPage(currentSnapshot)) {
      return
    }

    const learnableField = describeLearnableField(field, currentSnapshot, locationObject)
    if (!learnableField) {
      return
    }

    const isSecureField = isSecureVaultField(learnableField.securityClassification)
    if (isSecureField && hasSecureVaultMaterial(currentSnapshot) && !(await canUseSecureVaultKey(currentSnapshot))) {
      return
    }

    const existingEntry = learnableField.fieldMemoryEntry
    const nextProfile = isSecureField
      ? null
      : promoteProfileValue(currentSnapshot.profile, learnableField.profileKey ?? existingEntry?.profileKey, currentValue)
    const previousLearnedValue = existingEntry?.lastUserValue.trim() ?? ""

    if ((isSecureField ? learnableField.secureVaultValue : previousLearnedValue) === currentValue && !nextProfile) {
      state.lastPersistedValue = currentValue
      return
    }

    const profileKey = learnableField.profileKey ?? existingEntry?.profileKey
    const eventDetail = isSecureField
      ? `vault:${learnableField.secureVaultKind ?? "custom"}`
      : nextProfile
        ? `profile:${profileKey}`
        : profileKey
          ? `memory:${profileKey}`
          : "memory:custom"

    state.lastPersistedValue = currentValue
    const nextSnapshot = await ignoreInvalidatedExtensionContext(() =>
      commitStorageChanges({
        ...(nextProfile ? { profile: nextProfile } : {}),
        ...(isSecureField && learnableField.secureVaultKind
          ? {
              secureVaultUpdates: [
                {
                  hostname: learnableField.descriptor.hostname,
                  fieldSignature: learnableField.fieldSignature,
                  kind: learnableField.secureVaultKind,
                  label: getLearnedLabel(learnableField.descriptor) ?? learnableField.secureVaultEntry?.label,
                  value: currentValue,
                  incrementLearned: true
                }
              ],
              fieldMemoryDeletes: [
                {
                  hostname: learnableField.descriptor.hostname,
                  fieldSignature: learnableField.fieldSignature
                }
              ]
            }
          : {
              fieldMemoryUpdates: [
                {
                  hostname: learnableField.descriptor.hostname,
                  fieldSignature: learnableField.fieldSignature,
                  profileKey: profileKey ?? undefined,
                  learnedLabel: getLearnedLabel(learnableField.descriptor) ?? existingEntry?.learnedLabel,
                  lastAutofilledValue: existingEntry?.lastAutofilledValue ?? "",
                  lastUserValue: currentValue,
                  timesAutofilled: existingEntry?.timesAutofilled ?? 0,
                  timesCorrected: existingEntry?.timesCorrected ?? 0,
                  timesLearned: (existingEntry?.timesLearned ?? 0) + 1,
                  updatedAt: new Date().toISOString()
                }
              ]
            }),
        eventEntries: [
          {
            type: "field_learned_from_user",
            hostname: learnableField.descriptor.hostname,
            url: learnableField.descriptor.url,
            fieldSignature: learnableField.fieldSignature,
            profileKey: profileKey ?? undefined,
            ...createEventValueFields(
              learnableField.securityClassification,
              previousLearnedValue || undefined,
              currentValue
            ),
            source: "storage-update",
            detail: appendRedactionDetail(eventDetail, learnableField.securityClassification)
          }
        ]
      })
    )

    if (nextSnapshot) {
      snapshot = nextSnapshot
    }
  }

  const queueLearnedInputPersist = (field: FieldElement, state: LearningState) => {
    learnedInputPersistQueue = learnedInputPersistQueue
      .catch(() => undefined)
      .then(() => persistLearnedInput(field, state))

    return learnedInputPersistQueue
  }

  const attachLearningTracking = (field: FieldElement) => {
    if (field.dataset.autofillLearnTracked === "true") {
      return
    }

    const state: LearningState = {
      lastPersistedValue: normalizeLearnedValue(field)
    }
    learningState.set(field, state)

    attachUserInteractionTracking(field)

    const schedulePersist = (immediate: boolean, event?: Event) => {
      if (internalAutofillFields.has(field)) {
        return
      }

      if (isComposingEvent(event) || composingFields.has(field)) {
        return
      }

      const activeState = learningState.get(field)
      if (!activeState) {
        return
      }

      if (activeState.timerId) {
        windowObject.clearTimeout(activeState.timerId)
      }

      if (immediate) {
        void queueLearnedInputPersist(field, activeState)
        return
      }

      activeState.timerId = windowObject.setTimeout(() => {
        void queueLearnedInputPersist(field, activeState)
      }, 400)
    }

    field.addEventListener("input", (event) => schedulePersist(false, event))
    field.addEventListener("compositionend", (event) => schedulePersist(false, event))
    field.addEventListener("change", (event) => schedulePersist(true, event))
    field.addEventListener("blur", (event) => schedulePersist(true, event))
    field.dataset.autofillLearnTracked = "true"
  }

  const syncLearningListeners = (nextSnapshot: StorageSnapshot) => {
    if (!canOperateOnPage(nextSnapshot)) {
      return
    }

    for (const field of Array.from(documentObject.querySelectorAll(FIELD_SELECTOR))) {
      const learnableField = describeLearnableField(field, nextSnapshot, locationObject)
      if (learnableField) {
        attachLearningTracking(field as FieldElement)
      }
    }
  }

  const runAutofill = async (source: AutofillEventSource) => {
    if (!extensionContextAvailable) {
      return false
    }

    const nextSnapshot = snapshot ?? (await loadSnapshot())
    if (!shouldAutofill(nextSnapshot)) {
      return false
    }

    const candidates = collectAutofillCandidates(documentObject, nextSnapshot, locationObject)
    if (candidates.length < nextSnapshot.settings.minMatchCount) {
      return false
    }

    const runId = createRunId()
    const fieldMemoryUpdates: FieldMemoryEntry[] = []
    const fieldMemoryDeletes: Array<{ hostname: string; fieldSignature: string }> = []
    const secureVaultUpdates: SecureVaultValueUpdate[] = []
    const eventEntries: NewEventLogEntry[] = [
      {
        type: "autofill_run",
        hostname: locationObject.hostname,
        url: locationObject.href,
        source,
        runId,
        detail: `matches:${candidates.length}`
      }
    ]

    for (const candidate of candidates) {
      const dedupeKey = `${candidate.fieldSignature}::${locationObject.href}::${source}`
      if (processedRunKeys.has(dedupeKey)) {
        continue
      }

      const previousValue = getFieldCurrentValue(candidate.field)
      if (previousValue.trim() || isUserEditingField(candidate.field)) {
        continue
      }

      if (requiresSecureAutofillConfirmation(candidate.securityClassification) && source !== "popup") {
        continue
      }

      if (isSecureVaultField(candidate.securityClassification) && source !== "popup") {
        continue
      }

      if (isSecureVaultField(candidate.securityClassification) && !(await canUseSecureVaultKey(nextSnapshot))) {
        continue
      }

      internalAutofillFields.add(candidate.field)
      setNativeFieldValue(candidate.field, candidate.appliedValue)
      candidate.field.dispatchEvent(new Event("input", { bubbles: true }))
      if (candidate.field instanceof HTMLSelectElement) {
        candidate.field.dispatchEvent(new Event("change", { bubbles: true }))
      }
      internalAutofillFields.delete(candidate.field)
      processedRunKeys.add(dedupeKey)

      if (isSecureVaultField(candidate.securityClassification) && candidate.secureVaultKind) {
        secureVaultUpdates.push({
          hostname: candidate.descriptor.hostname,
          fieldSignature: candidate.fieldSignature,
          kind: candidate.secureVaultKind,
          label: candidate.secureVaultEntry?.label ?? getLearnedLabel(candidate.descriptor),
          value: candidate.rawValue,
          incrementAutofilled: true
        })
        if (candidate.usesLegacyMemoryValue) {
          fieldMemoryDeletes.push({
            hostname: candidate.descriptor.hostname,
            fieldSignature: candidate.fieldSignature
          })
        }
      } else {
        fieldMemoryUpdates.push({
          hostname: candidate.descriptor.hostname,
          fieldSignature: candidate.fieldSignature,
          profileKey: candidate.profileKey,
          lastAutofilledValue: candidate.rawValue,
          lastUserValue: candidate.fieldMemoryEntry?.lastUserValue ?? "",
          timesAutofilled: (candidate.fieldMemoryEntry?.timesAutofilled ?? 0) + 1,
          timesCorrected: candidate.fieldMemoryEntry?.timesCorrected ?? 0,
          timesLearned: candidate.fieldMemoryEntry?.timesLearned ?? 0,
          learnedLabel: candidate.fieldMemoryEntry?.learnedLabel,
          updatedAt: new Date().toISOString()
        })
      }
      eventEntries.push({
        type: "field_filled",
        hostname: candidate.descriptor.hostname,
        url: candidate.descriptor.url,
        fieldSignature: candidate.fieldSignature,
        profileKey: candidate.profileKey,
        ...createEventValueFields(candidate.securityClassification, previousValue, candidate.rawValue),
        source,
        runId,
        detail: appendRedactionDetail("filled", candidate.securityClassification)
      })

      attachCorrectionTracking(candidate.field, {
        hostname: candidate.descriptor.hostname,
        url: candidate.descriptor.url,
        fieldSignature: candidate.fieldSignature,
        profileKey: candidate.profileKey,
        secureVaultKind: candidate.secureVaultKind,
        securityClassification: candidate.securityClassification,
        autofilledValue: candidate.rawValue,
        runId
      })
    }

    if (fieldMemoryUpdates.length === 0 && secureVaultUpdates.length === 0 && fieldMemoryDeletes.length === 0) {
      return false
    }

    const committedSnapshot = await ignoreInvalidatedExtensionContext(() =>
      commitStorageChanges({
        fieldMemoryUpdates,
        fieldMemoryDeletes,
        secureVaultUpdates,
        eventEntries
      })
    )

    if (!committedSnapshot) {
      return false
    }

    snapshot = committedSnapshot

    return true
  }

  const scheduleNavigationRun = () => {
    if (!extensionContextAvailable) {
      return
    }

    windowObject.clearTimeout(navigationTimer)
    navigationTimer = windowObject.setTimeout(() => {
      void loadSnapshot().then(() => runAutofill("navigation"))
    }, debounceMs)
  }

  const installNavigationListeners = () => {
    const originalPushState = windowObject.history.pushState.bind(windowObject.history)
    const originalReplaceState = windowObject.history.replaceState.bind(windowObject.history)

    windowObject.history.pushState = ((...args) => {
      const result = originalPushState(...args)
      scheduleNavigationRun()
      return result
    }) as History["pushState"]

    windowObject.history.replaceState = ((...args) => {
      const result = originalReplaceState(...args)
      scheduleNavigationRun()
      return result
    }) as History["replaceState"]

    windowObject.addEventListener("popstate", () => {
      scheduleNavigationRun()
    })
  }

  const handleMessage = async (message: ExtensionMessage) => {
    if (!extensionContextAvailable) {
      return
    }

    switch (message.type) {
      case "RUN_AUTOFILL":
        await loadSnapshot()
        await runAutofill(message.source ?? "popup")
        break
      case "PROFILE_UPDATED":
      case "SETTINGS_UPDATED":
        await loadSnapshot()
        await runAutofill("storage-update")
        break
      case "DOMAIN_POLICY_UPDATED":
        await loadSnapshot()
        if (message.hostname && message.hostname === locationObject.hostname) {
          await runAutofill("storage-update")
        }
        break
      default:
        break
    }
  }

  const initialize = async () => {
    if (initialized) {
      return
    }

    initialized = true
    try {
      chromeApi.runtime.onMessage.addListener((message: ExtensionMessage) => {
        void handleMessage(message)
      })
    } catch (error) {
      if (isExtensionContextInvalidatedError(error)) {
        deactivateInvalidatedExtensionContext()
        return
      }

      throw error
    }

    installNavigationListeners()
    await loadSnapshot()
    if (!extensionContextAvailable) {
      return
    }

    const start = () => {
      if (!extensionContextAvailable) {
        return
      }

      void runAutofill("automatic-load")
    }

    if (documentObject.readyState === "complete") {
      start()
      return
    }

    windowObject.addEventListener("load", start, { once: true })
  }

  return {
    initialize,
    loadSnapshot,
    runAutofill,
    flushPendingWrites: () => learnedInputPersistQueue.catch(() => undefined),
    shouldAutofill: () => (snapshot ? shouldAutofill(snapshot) : false),
    dispose: () => {
      windowObject.clearTimeout(mutationTimer)
      windowObject.clearTimeout(navigationTimer)
      observer?.disconnect()
      observer = null
      initialized = false
    }
  }
}
