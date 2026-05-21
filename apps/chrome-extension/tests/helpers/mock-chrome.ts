type StorageData = Record<string, unknown>

type RuntimeListener = (message: unknown) => void

type StorageListener = (changes: Record<string, { oldValue: unknown; newValue: unknown }>, areaName: string) => void

export const createChromeMock = (
  initialStorage: StorageData = {},
  activeTab: { id?: number; url?: string } = {
    id: 1,
    url: "https://example.com/form"
  }
) => {
  const storageData: StorageData = { ...initialStorage }
  const runtimeListeners = new Set<RuntimeListener>()
  const storageListeners = new Set<StorageListener>()
  const runtimeMessages: unknown[] = []
  const sentMessages: Array<{ tabId: number; message: unknown }> = []

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
      local: {
        async get(keys?: string | string[] | Record<string, unknown>) {
          if (!keys) {
            return { ...storageData }
          }

          if (typeof keys === "string") {
            return {
              [keys]: storageData[keys]
            }
          }

          if (Array.isArray(keys)) {
            return Object.fromEntries(keys.map((key) => [key, storageData[key]]))
          }

          return Object.fromEntries(
            Object.entries(keys).map(([key, fallbackValue]) => [key, storageData[key] ?? fallbackValue])
          )
        },
        async set(items: StorageData) {
          const changes = Object.fromEntries(
            Object.entries(items).map(([key, newValue]) => {
              const oldValue = storageData[key]
              storageData[key] = newValue
              return [key, { oldValue, newValue }]
            })
          )

          for (const listener of storageListeners) {
            listener(changes, "local")
          }
        }
      },
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
    }
  }

  return {
    chromeMock,
    storageData,
    runtimeMessages,
    sentMessages,
    emitRuntimeMessage(message: unknown) {
      for (const listener of runtimeListeners) {
        listener(message)
      }
    }
  }
}
