type StorageData = Record<string, unknown>

type RuntimeListener = (message: unknown) => void

type StorageListener = (changes: Record<string, { oldValue: unknown; newValue: unknown }>, areaName: string) => void

export const createChromeMock = (
  initialStorage: StorageData = {},
  activeTab: { id?: number; url?: string } = {
    id: 1,
    url: "https://example.com/form"
  },
  identityOptions: {
    authToken?: string
    failAuthToken?: boolean
  } = {
    authToken: "google-token"
  }
) => {
  const storageData: StorageData = { ...initialStorage }
  const sessionStorageData: StorageData = {}
  const runtimeListeners = new Set<RuntimeListener>()
  const storageListeners = new Set<StorageListener>()
  const runtimeMessages: unknown[] = []
  const sentMessages: Array<{ tabId: number; message: unknown }> = []
  const identityRequests: unknown[] = []
  let authTokensCleared = false

  const createStorageArea = (areaData: StorageData, areaName: string) => ({
    async get(keys?: string | string[] | Record<string, unknown>) {
      if (!keys) {
        return { ...areaData }
      }

      if (typeof keys === "string") {
        return {
          [keys]: areaData[keys]
        }
      }

      if (Array.isArray(keys)) {
        return Object.fromEntries(keys.map((key) => [key, areaData[key]]))
      }

      return Object.fromEntries(Object.entries(keys).map(([key, fallbackValue]) => [key, areaData[key] ?? fallbackValue]))
    },
    async set(items: StorageData) {
      const changes = Object.fromEntries(
        Object.entries(items).map(([key, newValue]) => {
          const oldValue = areaData[key]
          areaData[key] = newValue
          return [key, { oldValue, newValue }]
        })
      )

      for (const listener of storageListeners) {
        listener(changes, areaName)
      }
    }
  })

  const chromeMock = {
    runtime: {
      async sendMessage(message: unknown) {
        runtimeMessages.push(message)
        for (const listener of runtimeListeners) {
          listener(message)
        }
      },
      onMessage: {
        addListener: (listener: RuntimeListener) => {
          runtimeListeners.add(listener)
        }
      }
    },
    storage: {
      local: createStorageArea(storageData, "local"),
      session: createStorageArea(sessionStorageData, "session"),
      onChanged: {
        addListener: (listener: StorageListener) => {
          storageListeners.add(listener)
        }
      }
    },
    tabs: {
      async query() {
        return [activeTab]
      },
      async sendMessage(tabId: number, message: unknown) {
        sentMessages.push({ tabId, message })
      }
    },
    identity: {
      async getAuthToken(details?: unknown) {
        identityRequests.push(details)
        if (identityOptions.failAuthToken) {
          throw new Error("auth failed")
        }
        return {
          token: identityOptions.authToken ?? "google-token"
        }
      },
      async clearAllCachedAuthTokens() {
        authTokensCleared = true
      }
    }
  }

  return {
    chromeMock,
    storageData,
    sessionStorageData,
    runtimeMessages,
    sentMessages,
    identityRequests,
    get authTokensCleared() {
      return authTokensCleared
    },
    emitRuntimeMessage(message: unknown) {
      for (const listener of runtimeListeners) {
        listener(message)
      }
    }
  }
}
