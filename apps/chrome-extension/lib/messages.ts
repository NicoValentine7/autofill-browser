import type { AutofillEventSource, EventLogEntry } from "@autofill-browser/autofill-core"

export type ExtensionMessage =
  | {
      type: "RUN_AUTOFILL"
      source?: AutofillEventSource
    }
  | {
      type: "PROFILE_UPDATED"
    }
  | {
      type: "SETTINGS_UPDATED"
    }
  | {
      type: "DOMAIN_POLICY_UPDATED"
      hostname?: string
    }
  | {
      type: "SYNC_EVENT_LOGS_TO_CLOUD"
      events: EventLogEntry[]
      preferGoogleAuth?: boolean
    }

export const sendMessageToTab = async (tabId: number, message: ExtensionMessage) => {
  try {
    await chrome.tabs.sendMessage(tabId, message)
  } catch (_error) {
    return false
  }

  return true
}

export const sendCloudLogSyncMessage = async (events: EventLogEntry[], preferGoogleAuth = false) => {
  if (events.length === 0 || !preferGoogleAuth) {
    return false
  }

  try {
    await chrome.runtime.sendMessage({
      type: "SYNC_EVENT_LOGS_TO_CLOUD",
      events,
      preferGoogleAuth
    } satisfies ExtensionMessage)
  } catch (_error) {
    return false
  }

  return true
}
