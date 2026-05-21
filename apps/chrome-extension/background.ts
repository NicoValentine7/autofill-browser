import { sendEventLogEntriesToCloud } from "~lib/cloud-log-sync"
import type { ExtensionMessage } from "~lib/messages"

chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
  if (message.type !== "SYNC_EVENT_LOGS_TO_CLOUD") {
    return
  }

  void sendEventLogEntriesToCloud(message.events, message.settings)
})
