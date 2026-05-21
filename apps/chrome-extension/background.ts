import { sendEventLogEntriesToCloud } from "~lib/cloud-log-sync"
import { getGoogleAccessToken } from "~lib/google-auth"
import type { ExtensionMessage } from "~lib/messages"

chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
  if (message.type !== "SYNC_EVENT_LOGS_TO_CLOUD") {
    return
  }

  void (async () => {
    const googleAccessToken = message.preferGoogleAuth ? await getGoogleAccessToken(false) : null
    const sentWithGoogle = googleAccessToken
      ? await sendEventLogEntriesToCloud(message.events, message.settings, fetch, googleAccessToken)
      : false

    if (!sentWithGoogle) {
      await sendEventLogEntriesToCloud(message.events, message.settings)
    }
  })()
})
