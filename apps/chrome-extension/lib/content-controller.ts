import { getDomainPolicy, isProfileConfigured, type AutofillEventSource, type FieldMemoryEntry } from "@autofill-browser/autofill-core"

import { collectAutofillCandidates, getFieldCurrentValue, type FieldElement } from "./autofill-engine"
import type { ExtensionMessage } from "./messages"
import { commitStorageChanges, getStorageSnapshot, type NewEventLogEntry, type StorageSnapshot } from "./storage"

type CorrectionState = {
  field: FieldElement
  hostname: string
  url: string
  fieldSignature: string
  profileKey: FieldMemoryEntry["profileKey"]
  autofilledValue: string
  runId: string
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
  const processedRunKeys = new Set<string>()

  const loadSnapshot = async () => {
    snapshot = await getStorageSnapshot()
    syncMutationObserver()
    return snapshot
  }

  const shouldAutofill = (nextSnapshot: StorageSnapshot) => {
    if (!isProfileConfigured(nextSnapshot.profile)) {
      return false
    }

    const domainPolicy = getDomainPolicy(nextSnapshot.domainPolicies, locationObject.hostname)
    if (domainPolicy === "blacklist") {
      return false
    }

    if (domainPolicy === "whitelist") {
      return true
    }

    return nextSnapshot.settings.enabled
  }

  const syncMutationObserver = () => {
    if (!snapshot) {
      return
    }

    const shouldObserve = snapshot.settings.observeDynamicForms && shouldAutofill(snapshot)
    if (shouldObserve && !observer) {
      observer = new MutationObserver(() => {
        windowObject.clearTimeout(mutationTimer)
        mutationTimer = windowObject.setTimeout(() => {
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
    const currentValue = getFieldCurrentValue(state.field).trim()

    if (!currentValue || currentValue === state.autofilledValue || currentValue === state.lastPersistedValue) {
      return
    }

    const currentSnapshot = snapshot ?? (await loadSnapshot())
    const existingEntry = currentSnapshot.fieldMemory[`${state.hostname}::${state.fieldSignature}`]
    const updatedEntry: FieldMemoryEntry = {
      hostname: state.hostname,
      fieldSignature: state.fieldSignature,
      profileKey: state.profileKey,
      lastAutofilledValue: state.autofilledValue,
      lastUserValue: currentValue,
      timesAutofilled: existingEntry?.timesAutofilled ?? 0,
      timesCorrected: (existingEntry?.timesCorrected ?? 0) + 1,
      updatedAt: new Date().toISOString()
    }

    state.lastPersistedValue = currentValue
    snapshot = await commitStorageChanges({
      fieldMemoryUpdates: [updatedEntry],
      eventEntries: [
        {
          type: "field_corrected_by_user",
          hostname: state.hostname,
          url: state.url,
          fieldSignature: state.fieldSignature,
          profileKey: state.profileKey,
          previousValue: state.autofilledValue,
          nextValue: currentValue,
          source: "storage-update",
          runId: state.runId
        }
      ]
    })
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

    const schedulePersist = (immediate: boolean) => {
      const activeState = autofillState.get(field)
      if (!activeState) {
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
      field.addEventListener("input", () => schedulePersist(false))
      field.addEventListener("change", () => schedulePersist(true))
      field.addEventListener("blur", () => schedulePersist(true))
      field.dataset.autofillTracked = "true"
    }
  }

  const runAutofill = async (source: AutofillEventSource) => {
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
      if (previousValue.trim()) {
        continue
      }

      setNativeFieldValue(candidate.field, candidate.appliedValue)
      candidate.field.dispatchEvent(new Event("input", { bubbles: true }))
      if (candidate.field instanceof HTMLSelectElement) {
        candidate.field.dispatchEvent(new Event("change", { bubbles: true }))
      }
      processedRunKeys.add(dedupeKey)

      const updatedEntry: FieldMemoryEntry = {
        hostname: candidate.descriptor.hostname,
        fieldSignature: candidate.fieldSignature,
        profileKey: candidate.profileKey,
        lastAutofilledValue: candidate.rawValue,
        lastUserValue: candidate.fieldMemoryEntry?.lastUserValue ?? "",
        timesAutofilled: (candidate.fieldMemoryEntry?.timesAutofilled ?? 0) + 1,
        timesCorrected: candidate.fieldMemoryEntry?.timesCorrected ?? 0,
        updatedAt: new Date().toISOString()
      }

      fieldMemoryUpdates.push(updatedEntry)
      eventEntries.push({
        type: "field_filled",
        hostname: candidate.descriptor.hostname,
        url: candidate.descriptor.url,
        fieldSignature: candidate.fieldSignature,
        profileKey: candidate.profileKey,
        previousValue,
        nextValue: candidate.rawValue,
        source,
        runId
      })

      attachCorrectionTracking(candidate.field, {
        hostname: candidate.descriptor.hostname,
        url: candidate.descriptor.url,
        fieldSignature: candidate.fieldSignature,
        profileKey: candidate.profileKey,
        autofilledValue: candidate.rawValue,
        runId
      })
    }

    if (fieldMemoryUpdates.length === 0) {
      return false
    }

    snapshot = await commitStorageChanges({
      fieldMemoryUpdates,
      eventEntries
    })

    return true
  }

  const scheduleNavigationRun = () => {
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
    chromeApi.runtime.onMessage.addListener((message: ExtensionMessage) => {
      void handleMessage(message)
    })

    installNavigationListeners()
    await loadSnapshot()

    const start = () => {
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
    shouldAutofill: () => (snapshot ? shouldAutofill(snapshot) : false)
  }
}
