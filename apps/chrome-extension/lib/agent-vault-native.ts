import { DEFAULT_AGENT_VAULT_SCOPE, normalizeAgentVaultScope, type AgentVaultScope } from "./secure-vault"

const AGENT_VAULT_NATIVE_HOST = "io.nico.agvt"

export type AgentVaultUpsertApiTokenInput = {
  item: string
  vault?: AgentVaultScope
  token: string
  label?: string
  serviceUrl?: string
  accountName?: string
  accountId?: string
  notes?: string
}

export type AgentVaultNativeResult = {
  ok: boolean
  message?: string
}

export const normalizeAgentVaultItemName = (value: string) => {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 128)
  return /^[a-z0-9]/.test(normalized) ? normalized : ""
}

export const buildAgentVaultSecretRef = (vault: AgentVaultScope, item: string) => `agvt://${vault}/${item}/token`

export const upsertAgentVaultApiToken = async (input: AgentVaultUpsertApiTokenInput): Promise<AgentVaultNativeResult> => {
  const item = normalizeAgentVaultItemName(input.item)
  const vault = normalizeAgentVaultScope(input.vault ?? DEFAULT_AGENT_VAULT_SCOPE)
  if (!item || !input.token.trim()) {
    return { ok: false, message: "Agent Vault item名かtokenが空やで" }
  }

  if (!chrome.runtime.sendNativeMessage) {
    return { ok: false, message: "native messagingを使えへん環境やで" }
  }

  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(
      AGENT_VAULT_NATIVE_HOST,
      {
        type: "upsert-api-token",
        item,
        vault,
        token: input.token,
        label: input.label,
        serviceUrl: input.serviceUrl,
        accountName: input.accountName,
        accountId: input.accountId,
        notes: input.notes
      },
      (response?: AgentVaultNativeResult) => {
        const error = chrome.runtime.lastError
        if (error) {
          resolve({ ok: false, message: error.message })
          return
        }
        resolve(response?.ok ? response : { ok: false, message: response?.message ?? "Agent Vault bridgeの応答が不正やで" })
      }
    )
  })
}
