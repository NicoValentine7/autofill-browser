import { useEffect, useMemo, useState, type CSSProperties } from "react"

import { createEmptyProfile, getDomainPolicy, isProfileConfigured, type DomainPolicy, type EventLogEntry, type StoredProfile } from "@autofill-browser/autofill-core"

import { fetchRemoteRules, fetchSignedInUser, pullSyncedSnapshot, pushSyncedSnapshot, type SyncField } from "./account-sync"
import { buildAgentVaultSecretRef, normalizeAgentVaultItemName, upsertAgentVaultApiToken } from "./agent-vault-native"
import { clearGoogleAuthTokens, getGoogleAccessToken } from "./google-auth"
import type { ExtensionMessage } from "./messages"
import { sendMessageToTab } from "./messages"
import {
  MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH,
  DEFAULT_AGENT_VAULT_SCOPE,
  createManualSecureVaultValueUpdate,
  createSecureVaultRecoveryPackage,
  generateSecureVaultRecoveryPhrase,
  getSecureVaultEntryKey,
  isManualSecureVaultItem,
  normalizeAgentVaultScope,
  parseSecureVaultApiTokenItemPayload,
  recoverSecureVaultKey,
  stringifySecureVaultApiTokenItemPayload,
  type AgentVaultScope,
  type SecureVaultEntry
} from "./secure-vault"
import {
  applySyncedSnapshot,
  appendEventEntries,
  clearGoogleAuthUser,
  commitStorageChanges,
  getStorageSnapshot,
  saveAccountSyncState,
  saveDomainPolicy,
  saveGoogleAuthUser,
  saveProfile,
  saveRemoteRules,
  saveSecureVaultKey,
  saveSecureVaultRecoveryPackage,
  saveSettings,
  type StorageSnapshot
} from "./storage"

type ActiveTabContext = {
  id?: number
  hostname: string
  url: string
}

const sectionStyle = {
  padding: 12,
  borderRadius: 12,
  background: "#172030"
} satisfies CSSProperties

const inputStyle = {
  borderRadius: 8,
  border: "1px solid #334155",
  padding: "8px 10px",
  background: "#0f172a",
  color: "#f8fafc"
} satisfies CSSProperties

const buttonStyle = {
  border: 0,
  borderRadius: 10,
  padding: "10px 12px",
  fontWeight: 600,
  color: "#10131a",
  cursor: "pointer"
} satisfies CSSProperties

const fieldLabels: Array<{ key: keyof StoredProfile; label: string; placeholder: string }> = [
  { key: "familyName", label: "姓", placeholder: "例: 山田" },
  { key: "givenName", label: "名", placeholder: "例: 太郎" },
  { key: "fullName", label: "氏名", placeholder: "例: 山田 太郎" },
  { key: "email", label: "メール", placeholder: "例: taro@example.com" },
  { key: "phone", label: "電話番号", placeholder: "例: 09012345678" },
  { key: "organization", label: "会社名", placeholder: "例: OpenAI Japan" },
  { key: "postalCode", label: "郵便番号", placeholder: "例: 1500001" },
  { key: "prefecture", label: "都道府県", placeholder: "例: 東京都" },
  { key: "city", label: "市区町村", placeholder: "例: 渋谷区神宮前" },
  { key: "addressLine1", label: "住所1", placeholder: "例: 渋谷区神宮前1-2-3" },
  { key: "addressLine2", label: "住所2", placeholder: "例: テストビル 301" }
]

const primaryProfileFields = fieldLabels.filter((field) => ["fullName", "email", "phone"].includes(field.key))
const optionalProfileFields = fieldLabels.filter((field) => !["fullName", "email", "phone"].includes(field.key))

const eventTypeLabels: Record<EventLogEntry["type"], string> = {
  autofill_run: "自動入力実行",
  field_filled: "フィールド入力",
  field_corrected_by_user: "手修正を記録",
  field_learned_from_user: "手入力を学習",
  setting_changed: "設定変更",
  domain_policy_changed: "ドメイン制御変更",
  profile_updated: "プロフィール更新",
  manual_autofill_triggered: "手動再実行",
  vault_item_created: "Vault項目を追加",
  vault_item_updated: "Vault項目を更新",
  vault_item_deleted: "Vault項目を削除"
}

const getActiveTabContext = async (): Promise<ActiveTabContext> => {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  })

  try {
    const url = new URL(tab?.url ?? "https://invalid.local")
    return {
      id: tab?.id,
      hostname: url.hostname,
      url: url.toString()
    }
  } catch (_error) {
    return {
      id: tab?.id,
      hostname: "",
      url: tab?.url ?? ""
    }
  }
}

const notifyActiveTab = async (tabId: number | undefined, message: ExtensionMessage) => {
  if (!tabId) {
    return false
  }

  return sendMessageToTab(tabId, message)
}

const formatEvent = (event: EventLogEntry) => {
  const parts = [eventTypeLabels[event.type], new Date(event.timestamp).toLocaleString("ja-JP")]
  if (event.hostname) {
    parts.push(event.hostname)
  }
  return parts.join(" / ")
}

function PopupApp() {
  const [snapshot, setSnapshot] = useState<StorageSnapshot | null>(null)
  const [profileForm, setProfileForm] = useState<StoredProfile>(createEmptyProfile())
  const [vaultRecoveryPassphrase, setVaultRecoveryPassphrase] = useState("")
  const [isGeneratedVaultRecoveryPassphrase, setIsGeneratedVaultRecoveryPassphrase] = useState(false)
  const [showVaultRecoveryPassphrase, setShowVaultRecoveryPassphrase] = useState(false)
  const [apiTokenLabel, setApiTokenLabel] = useState("")
  const [apiTokenServiceUrl, setApiTokenServiceUrl] = useState("")
  const [apiTokenAccountName, setApiTokenAccountName] = useState("")
  const [apiTokenAccountId, setApiTokenAccountId] = useState("")
  const [apiTokenAgentVaultItem, setApiTokenAgentVaultItem] = useState("")
  const [apiTokenAgentVaultScope, setApiTokenAgentVaultScope] = useState<AgentVaultScope>(DEFAULT_AGENT_VAULT_SCOPE)
  const [apiTokenValue, setApiTokenValue] = useState("")
  const [apiTokenNotes, setApiTokenNotes] = useState("")
  const [showApiTokenValue, setShowApiTokenValue] = useState(false)
  const [editingApiTokenEntryKey, setEditingApiTokenEntryKey] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<ActiveTabContext>({ hostname: "", url: "" })
  const [status, setStatus] = useState("読み込み中やで")

  const refreshState = async () => {
    const [nextSnapshot, nextTab] = await Promise.all([getStorageSnapshot(), getActiveTabContext()])
    setSnapshot(nextSnapshot)
    setProfileForm(nextSnapshot.profile)
    setActiveTab(nextTab)
    return { nextSnapshot, nextTab }
  }

  const refreshRemoteRulesIfSignedIn = async (googleAccessToken?: string | null) => {
    const token = googleAccessToken ?? (await getGoogleAccessToken(false))
    if (!token) {
      return null
    }

    const remoteRules = await fetchRemoteRules(token)
    if (!remoteRules) {
      return null
    }

    const nextSnapshot = await saveRemoteRules(remoteRules)
    setSnapshot(nextSnapshot)
    return nextSnapshot
  }

  const pushSnapshotIfSignedIn = async (nextSnapshot: StorageSnapshot, changedFields: SyncField[] = ["profile", "settings", "domainPolicies", "secureVault", "secureVaultRecovery"]) => {
    if (!nextSnapshot.googleAuthUser) {
      return nextSnapshot
    }

    const googleAccessToken = await getGoogleAccessToken(false)
    if (!googleAccessToken) {
      setStatus("ローカル保存したで。Google同期は再ログインが必要やな")
      return nextSnapshot
    }

    const result = await pushSyncedSnapshot(googleAccessToken, nextSnapshot, changedFields)

    if (!result) {
      setStatus("ローカル保存したで。Google同期は失敗したわ")
      return nextSnapshot
    }

    if ("conflict" in result) {
      const syncedSnapshot = await applyRemoteSnapshot(result.snapshot ?? null)
      setStatus("クラウド側の同じ項目が先に更新されてたから、そっちを反映したで")
      return syncedSnapshot ?? nextSnapshot
    }

    const syncedSnapshot = await saveAccountSyncState({
      lastPushedAt: new Date().toISOString(),
      lastRemoteUpdatedAt: result.updatedAt,
      lastRevision: result.revision
    })
    setSnapshot(syncedSnapshot)
    if (result.merged) {
      setStatus("別PCの変更と差分マージして保存したで")
    }
    return syncedSnapshot
  }

  const applyRemoteSnapshot = async (remoteSnapshot: Awaited<ReturnType<typeof pullSyncedSnapshot>>) => {
    if (!remoteSnapshot) {
      return null
    }

    const nextSnapshot = await applySyncedSnapshot(remoteSnapshot, remoteSnapshot.updatedAt)
    setSnapshot(nextSnapshot)
    setProfileForm(nextSnapshot.profile)
    await notifyActiveTab(activeTab.id, { type: "SETTINGS_UPDATED" })
    await notifyActiveTab(activeTab.id, { type: "PROFILE_UPDATED" })
    return nextSnapshot
  }

  const pullRemoteSnapshotIfSignedIn = async (nextSnapshot: StorageSnapshot) => {
    if (!nextSnapshot.googleAuthUser) {
      return nextSnapshot
    }

    const googleAccessToken = await getGoogleAccessToken(false)
    if (!googleAccessToken) {
      setStatus("Google同期は再ログインが必要やな")
      return nextSnapshot
    }

    const remoteSnapshot = await pullSyncedSnapshot(googleAccessToken)
    if (!remoteSnapshot) {
      return nextSnapshot
    }

    if (remoteSnapshot.revision !== undefined && remoteSnapshot.revision <= (nextSnapshot.accountSync.lastRevision ?? 0)) {
      return nextSnapshot
    }

    const syncedSnapshot = await applyRemoteSnapshot(remoteSnapshot)
    setStatus("クラウドの最新設定を反映したで")
    return syncedSnapshot ?? nextSnapshot
  }

  useEffect(() => {
    void refreshState().then(({ nextSnapshot }) => {
      setStatus("設定を確認できたで")
      void pullRemoteSnapshotIfSignedIn(nextSnapshot).then((pulledSnapshot) => {
        if (pulledSnapshot.googleAuthUser) {
          void refreshRemoteRulesIfSignedIn()
        }
      })
    })
  }, [])

  const currentPolicy = useMemo(() => {
    if (!snapshot || !activeTab.hostname) {
      return "default"
    }

    return getDomainPolicy(snapshot.domainPolicies, activeTab.hostname)
  }, [activeTab.hostname, snapshot])

  if (!snapshot) {
    return (
      <main style={{ minWidth: 360, padding: 16, background: "#10131a", color: "#f5f7fb" }}>
        読み込み中...
      </main>
    )
  }

  const profileReady = isProfileConfigured(snapshot.profile)
  const vaultEntryCount = Object.keys(snapshot.secureVault.entries).length
  const hasUsableVaultKey = Boolean(
    snapshot.secureVaultKey && (!snapshot.secureVaultRecovery || snapshot.secureVaultKey.keyId === snapshot.secureVaultRecovery.keyId)
  )
  const shouldShowVaultRecovery =
    Boolean(snapshot.secureVaultKey) || Boolean(snapshot.secureVaultRecovery) || vaultEntryCount > 0
  const apiTokenEntries = Object.entries(snapshot.secureVault.entries)
    .filter(([, entry]) => isManualSecureVaultItem(entry) && entry.kind === "api-token")
    .sort(([, left], [, right]) => right.updatedAt.localeCompare(left.updatedAt))
  const apiTokenItems = apiTokenEntries.map(([entryKey, entry]) => ({
    entryKey,
    entry,
    payload: parseSecureVaultApiTokenItemPayload(snapshot.secureVaultValues[entryKey])
  }))
  const editingApiTokenEntry = editingApiTokenEntryKey ? snapshot.secureVault.entries[editingApiTokenEntryKey] : undefined

  const handleProfileFieldChange = (key: keyof StoredProfile, value: string) => {
    setProfileForm((current) => ({
      ...current,
      [key]: value
    }))
  }

  const handleSaveProfile = async () => {
    const nextSnapshot = await saveProfile(profileForm, "popup-ui", {
      hostname: activeTab.hostname,
      url: activeTab.url
    })
    setSnapshot(nextSnapshot)
    await notifyActiveTab(activeTab.id, { type: "PROFILE_UPDATED" })
    await pushSnapshotIfSignedIn(nextSnapshot, ["profile"])
    setStatus("プロフィールを保存したで")
  }

  const handleSettingsChange = async (patch: Partial<StorageSnapshot["settings"]>) => {
    const nextSnapshot = await saveSettings(patch, "popup-ui", {
      hostname: activeTab.hostname,
      url: activeTab.url
    })
    setSnapshot(nextSnapshot)
    await notifyActiveTab(activeTab.id, { type: "SETTINGS_UPDATED" })
    await pushSnapshotIfSignedIn(nextSnapshot, ["settings"])
    setStatus("設定を更新したで")
  }

  const handlePolicyChange = async (policy: DomainPolicy) => {
    if (!activeTab.hostname) {
      setStatus("このタブではドメイン制御できへん")
      return
    }

    const nextSnapshot = await saveDomainPolicy(activeTab.hostname, policy, "popup-ui", snapshot.domainPolicies, {
      hostname: activeTab.hostname,
      url: activeTab.url
    })
    setSnapshot(nextSnapshot)
    await pushSnapshotIfSignedIn(nextSnapshot, ["domainPolicies"])
    await notifyActiveTab(activeTab.id, {
      type: "DOMAIN_POLICY_UPDATED",
      hostname: activeTab.hostname
    })
    setStatus("ドメイン制御を更新したで")
  }

  const handleManualAutofill = async () => {
    await appendEventEntries([
      {
        type: "manual_autofill_triggered",
        hostname: activeTab.hostname,
        url: activeTab.url,
        source: "popup",
        detail: "manual-run"
      }
    ])
    await notifyActiveTab(activeTab.id, {
      type: "RUN_AUTOFILL",
      source: "popup"
    })
    const nextSnapshot = await getStorageSnapshot()
    setSnapshot(nextSnapshot)
    setStatus("このページで再実行したで")
  }

  const handleGoogleLogin = async () => {
    const googleAccessToken = await getGoogleAccessToken(true)
    if (!googleAccessToken) {
      setStatus("Googleログインがキャンセルされたか失敗したで")
      return
    }

    const googleAuthUser = await fetchSignedInUser(googleAccessToken)
    if (!googleAuthUser) {
      setStatus("WorkerでGoogleログインを確認できへんかった")
      return
    }

    const signedInSnapshot = await saveGoogleAuthUser(googleAuthUser)
    setSnapshot(signedInSnapshot)
    await refreshRemoteRulesIfSignedIn(googleAccessToken)
    const remoteSnapshot = await pullSyncedSnapshot(googleAccessToken)

    if (remoteSnapshot) {
      await applyRemoteSnapshot(remoteSnapshot)
      setStatus(`${googleAuthUser.email} のクラウド設定を反映したで`)
      return
    }

    await pushSnapshotIfSignedIn(signedInSnapshot, ["profile", "settings", "domainPolicies"])
    setStatus(`${googleAuthUser.email} でログインしてクラウドへ初期保存したで`)
  }

  const handleGoogleLogout = async () => {
    await clearGoogleAuthTokens()
    const nextSnapshot = await clearGoogleAuthUser()
    setSnapshot(nextSnapshot)
    setStatus("Googleログアウトしたで")
  }

  const handleGenerateVaultRecoveryPassphrase = () => {
    setVaultRecoveryPassphrase(generateSecureVaultRecoveryPhrase())
    setIsGeneratedVaultRecoveryPassphrase(true)
    setShowVaultRecoveryPassphrase(true)
    setStatus("生成した回復フレーズを控えてから保存してな")
  }

  const handleSaveVaultRecovery = async () => {
    if (!snapshot.secureVaultKey || !hasUsableVaultKey) {
      setStatus("このSystem AccountのVault Keyを先に復元してな")
      return
    }

    if (!isGeneratedVaultRecoveryPassphrase) {
      setStatus("生成ボタンで高強度の回復フレーズを作ってから保存してな")
      return
    }

    if (vaultRecoveryPassphrase.trim().length < MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH) {
      setStatus(`回復フレーズは${MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH}文字以上にしてな`)
      return
    }

    const recoveryPackage = await createSecureVaultRecoveryPackage(
      snapshot.secureVaultKey,
      vaultRecoveryPassphrase,
      snapshot.secureVault.vaultId
    )
    if (!recoveryPackage) {
      setStatus("回復フレーズを保存できへんかった")
      return
    }

    const nextSnapshot = await saveSecureVaultRecoveryPackage(recoveryPackage)
    setSnapshot(nextSnapshot)
    setVaultRecoveryPassphrase("")
    setIsGeneratedVaultRecoveryPassphrase(false)
    setShowVaultRecoveryPassphrase(false)
    const pushedSnapshot = await pushSnapshotIfSignedIn(nextSnapshot, ["secureVaultRecovery"])
    if (!nextSnapshot.googleAuthUser) {
      setStatus("回復フレーズをローカル保存したで。Googleログイン後にもう一度保存してな")
    } else if ((pushedSnapshot.accountSync.lastPushedAt ?? "") !== (nextSnapshot.accountSync.lastPushedAt ?? "")) {
      setStatus("Secure Vaultの回復フレーズをクラウド保存したで")
    }
  }

  const handleRecoverVaultKey = async () => {
    if (!snapshot.secureVaultRecovery) {
      setStatus("クラウドにVault回復データがないで")
      return
    }

    const recoveredKey = await recoverSecureVaultKey(snapshot.secureVaultRecovery, vaultRecoveryPassphrase, snapshot.secureVault)
    if (!recoveredKey) {
      setStatus("回復フレーズが違うか短すぎるで")
      return
    }

    const nextSnapshot = await saveSecureVaultKey(recoveredKey)
    setSnapshot(nextSnapshot)
    setVaultRecoveryPassphrase("")
    setIsGeneratedVaultRecoveryPassphrase(false)
    setShowVaultRecoveryPassphrase(false)
    await notifyActiveTab(activeTab.id, { type: "SETTINGS_UPDATED" })
    setStatus("Vault Keyをこの端末へ復元したで")
  }

  const resetApiTokenForm = () => {
    setApiTokenLabel("")
    setApiTokenServiceUrl("")
    setApiTokenAccountName("")
    setApiTokenAccountId("")
    setApiTokenAgentVaultItem("")
    setApiTokenAgentVaultScope(DEFAULT_AGENT_VAULT_SCOPE)
    setApiTokenValue("")
    setApiTokenNotes("")
    setShowApiTokenValue(false)
    setEditingApiTokenEntryKey(null)
  }

  const handleSaveApiToken = async () => {
    const value = apiTokenValue.trim()
    if (!value) {
      setStatus("API tokenの値を入れてな")
      return
    }

    const nextUpdate = editingApiTokenEntry
      ? {
          hostname: editingApiTokenEntry.hostname,
          fieldSignature: editingApiTokenEntry.fieldSignature,
          kind: "api-token" as const,
          value: stringifySecureVaultApiTokenItemPayload({
            token: value,
            serviceUrl: apiTokenServiceUrl,
            accountName: apiTokenAccountName,
            accountId: apiTokenAccountId,
            agentVaultItem: apiTokenAgentVaultItem,
            agentVaultScope: apiTokenAgentVaultScope,
            notes: apiTokenNotes
          }),
          label: apiTokenLabel.trim() || editingApiTokenEntry.label || "API token"
        }
      : createManualSecureVaultValueUpdate({
          kind: "api-token",
          value: stringifySecureVaultApiTokenItemPayload({
            token: value,
            serviceUrl: apiTokenServiceUrl,
            accountName: apiTokenAccountName,
            accountId: apiTokenAccountId,
            agentVaultItem: apiTokenAgentVaultItem,
            agentVaultScope: apiTokenAgentVaultScope,
            notes: apiTokenNotes
          }),
          label: apiTokenLabel.trim() || "API token"
        })

    const nextSnapshot = await commitStorageChanges({
      secureVaultUpdates: [nextUpdate],
      eventEntries: [
        {
          type: editingApiTokenEntry ? "vault_item_updated" : "vault_item_created",
          hostname: "",
          url: "",
          source: "popup-ui",
          detail: "vault:api-token;values:redacted"
        }
      ]
    })

    setSnapshot(nextSnapshot)
    resetApiTokenForm()
    await pushSnapshotIfSignedIn(nextSnapshot, ["secureVault"])
    const normalizedAgentVaultItem = normalizeAgentVaultItemName(apiTokenAgentVaultItem)
    if (normalizedAgentVaultItem) {
      const bridgeResult = await upsertAgentVaultApiToken({
        item: normalizedAgentVaultItem,
        vault: apiTokenAgentVaultScope,
        token: value,
        label: apiTokenLabel.trim() || "API token",
        serviceUrl: apiTokenServiceUrl,
        accountName: apiTokenAccountName,
        accountId: apiTokenAccountId,
        notes: apiTokenNotes
      })
      setStatus(
        bridgeResult.ok
          ? "API tokenをSecure VaultとAgent Vaultへ保存したで"
          : `API tokenはSecure Vaultへ保存したで / Agent Vault bridgeは未接続やな`
      )
      return
    }
    setStatus(editingApiTokenEntry ? "API tokenを更新したで" : "API tokenをVaultに保存したで")
  }

  const handleEditApiToken = (entryKey: string, entry: SecureVaultEntry) => {
    const payload = parseSecureVaultApiTokenItemPayload(snapshot.secureVaultValues[entryKey])
    if (!payload?.token) {
      setStatus("Vault Keyを復元してから編集してな")
      return
    }

    setEditingApiTokenEntryKey(entryKey)
    setApiTokenLabel(entry.label ?? "API token")
    setApiTokenServiceUrl(payload.serviceUrl ?? "")
    setApiTokenAccountName(payload.accountName ?? "")
    setApiTokenAccountId(payload.accountId ?? "")
    setApiTokenAgentVaultItem(payload.agentVaultItem ?? "")
    setApiTokenAgentVaultScope(normalizeAgentVaultScope(payload.agentVaultScope))
    setApiTokenValue(payload.token)
    setApiTokenNotes(payload.notes ?? "")
    setShowApiTokenValue(false)
    setStatus(`${entry.label ?? "API token"} を編集中やで`)
  }

  const handleCopyApiToken = async (entryKey: string, entry: SecureVaultEntry) => {
    if (!hasUsableVaultKey) {
      setStatus("Vault Keyを復元してからコピーしてな")
      return
    }

    const payload = parseSecureVaultApiTokenItemPayload(snapshot.secureVaultValues[entryKey])
    if (!payload?.token) {
      setStatus("このAPI tokenはこの端末では復号できへん")
      return
    }

    try {
      if (!navigator.clipboard?.writeText) {
        setStatus("この環境ではクリップボードへコピーできへん")
        return
      }

      await navigator.clipboard.writeText(payload.token)
      setStatus(`${entry.label ?? "API token"} をコピーしたで`)
    } catch (_error) {
      setStatus("API tokenのコピーに失敗したで")
    }
  }

  const handleDeleteApiToken = async (entry: SecureVaultEntry) => {
    const nextSnapshot = await commitStorageChanges({
      secureVaultDeletes: [
        {
          hostname: entry.hostname,
          fieldSignature: entry.fieldSignature
        }
      ],
      eventEntries: [
        {
          type: "vault_item_deleted",
          hostname: "",
          url: "",
          source: "popup-ui",
          detail: "vault:api-token;values:redacted"
        }
      ]
    })

    setSnapshot(nextSnapshot)
    if (editingApiTokenEntryKey === getSecureVaultEntryKey(entry.hostname, entry.fieldSignature)) {
      resetApiTokenForm()
    }
    await pushSnapshotIfSignedIn(nextSnapshot, ["secureVault"])
    setStatus("API tokenを削除したで")
  }

  return (
    <main
      style={{
        margin: 0,
        minWidth: 380,
        padding: 16,
        background: "#10131a",
        color: "#f5f7fb",
        fontFamily: "ui-sans-serif, system-ui, sans-serif",
        display: "grid",
        gap: 12
      }}>
      <section style={sectionStyle}>
        <h1 style={{ margin: "0 0 8px", fontSize: 18 }}>Autofill Browser</h1>
        <p style={{ margin: 0, fontSize: 12, lineHeight: 1.5, color: "#c7d0dd" }}>
          1項目マッチでも攻めて自動入力する v1 やで。誤差は履歴と学習メモに貯める想定や。
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
          <span style={{ borderRadius: 999, padding: "4px 8px", background: profileReady ? "#134e4a" : "#4c1d95", fontSize: 11 }}>
            {profileReady ? "プロフィールあり" : "プロフィール未設定"}
          </span>
          <span style={{ borderRadius: 999, padding: "4px 8px", background: snapshot.googleAuthUser ? "#14532d" : "#713f12", fontSize: 11 }}>
            {snapshot.googleAuthUser ? "Google同期ON" : "Google未ログイン"}
          </span>
        </div>
        <p style={{ margin: "8px 0 0", fontSize: 12, color: "#99f6e4" }}>{status}</p>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>
          {profileReady ? "プロフィール" : "まずプロフィールを登録"}
        </h2>
        <div style={{ display: "grid", gap: 8 }}>
          {primaryProfileFields.map((field) => (
            <label key={field.key} style={{ display: "grid", gap: 4, fontSize: 12 }}>
              <span>{field.label}</span>
              <input
                value={profileForm[field.key]}
                onChange={(event) => handleProfileFieldChange(field.key, event.target.value)}
                placeholder={field.placeholder}
                style={inputStyle}
              />
            </label>
          ))}
          <details>
            <summary style={{ cursor: "pointer", fontSize: 12, color: "#c7d0dd" }}>住所・会社など任意項目</summary>
            <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
              {optionalProfileFields.map((field) => (
                <label key={field.key} style={{ display: "grid", gap: 4, fontSize: 12 }}>
                  <span>{field.label}</span>
                  <input
                    value={profileForm[field.key]}
                    onChange={(event) => handleProfileFieldChange(field.key, event.target.value)}
                    placeholder={field.placeholder}
                    style={inputStyle}
                  />
                </label>
              ))}
            </div>
          </details>
          <button
            type="button"
            onClick={handleSaveProfile}
            style={{
              marginTop: 4,
              ...buttonStyle,
              background: "#99f6e4",
            }}>
            プロフィールを保存
          </button>
        </div>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>Google同期</h2>
        <p style={{ margin: "0 0 8px", fontSize: 12, color: "#c7d0dd" }}>
          {snapshot.googleAuthUser ? `${snapshot.googleAuthUser.email} でログイン中` : "ログインすると別PCへプロフィールと設定を復元できるで"}
        </p>
        {snapshot.accountSync.lastRemoteUpdatedAt ? (
          <p style={{ margin: "0 0 8px", fontSize: 12, color: "#94a3b8" }}>
            最終同期: {new Date(snapshot.accountSync.lastRemoteUpdatedAt).toLocaleString("ja-JP")}
          </p>
        ) : null}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <button
            type="button"
            onClick={snapshot.googleAuthUser ? handleGoogleLogout : handleGoogleLogin}
            style={{
              ...buttonStyle,
              gridColumn: "1 / -1",
              background: snapshot.googleAuthUser ? "#fecaca" : "#bbf7d0",
            }}>
            {snapshot.googleAuthUser ? "ログアウト" : "Googleでログイン"}
          </button>
        </div>
      </section>

      {shouldShowVaultRecovery ? (
        <section style={sectionStyle}>
          <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>Secure Vault</h2>
          <p style={{ margin: "0 0 8px", fontSize: 12, color: "#c7d0dd" }}>
            {hasUsableVaultKey
              ? snapshot.secureVaultRecovery
                ? "この端末で復号OK / 回復フレーズ保存済み"
                : "この端末で復号OK"
              : snapshot.secureVaultRecovery
                ? "回復フレーズで復元できるで"
                : "この端末ではまだ復号できへん"}
          </p>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>回復フレーズ</span>
            <div style={{ display: "grid", gridTemplateColumns: hasUsableVaultKey ? "1fr auto" : "1fr", gap: 8 }}>
              <input
                type={showVaultRecoveryPassphrase ? "text" : "password"}
                value={vaultRecoveryPassphrase}
                onChange={(event) => {
                  setVaultRecoveryPassphrase(event.target.value)
                  setIsGeneratedVaultRecoveryPassphrase(false)
                }}
                placeholder={hasUsableVaultKey ? "生成して保存" : `${MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH}文字以上`}
                style={inputStyle}
              />
              {hasUsableVaultKey ? (
                <button
                  type="button"
                  onClick={handleGenerateVaultRecoveryPassphrase}
                  style={{
                    ...buttonStyle,
                    padding: "8px 10px",
                    background: "#c4b5fd",
                  }}>
                  生成
                </button>
              ) : null}
            </div>
          </label>
          <button
            type="button"
            onClick={hasUsableVaultKey ? handleSaveVaultRecovery : handleRecoverVaultKey}
            style={{
              marginTop: 8,
              width: "100%",
              ...buttonStyle,
              background: hasUsableVaultKey ? "#a7f3d0" : "#bfdbfe",
            }}>
            {hasUsableVaultKey ? "回復フレーズを保存" : "Vault Keyを復元"}
          </button>
        </section>
      ) : null}

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>API Token Vault</h2>
        <div style={{ display: "grid", gap: 8 }}>
          {editingApiTokenEntry ? (
            <p style={{ margin: 0, fontSize: 12, color: "#fde68a" }}>
              {editingApiTokenEntry.label ?? "API token"} を編集中
            </p>
          ) : null}
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>API token名</span>
            <input
              value={apiTokenLabel}
              onChange={(event) => setApiTokenLabel(event.target.value)}
              placeholder="例: GitHub production"
              autoComplete="off"
              style={inputStyle}
            />
          </label>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>サービスURL</span>
            <input
              value={apiTokenServiceUrl}
              onChange={(event) => setApiTokenServiceUrl(event.target.value)}
              placeholder="例: https://api.github.com"
              autoComplete="off"
              style={inputStyle}
            />
          </label>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>アカウント</span>
            <input
              value={apiTokenAccountName}
              onChange={(event) => setApiTokenAccountName(event.target.value)}
              placeholder="例: deploy-bot@example.com"
              autoComplete="off"
              style={inputStyle}
            />
          </label>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>Cloudflare Account ID</span>
            <input
              value={apiTokenAccountId}
              onChange={(event) => setApiTokenAccountId(event.target.value)}
              placeholder="例: 0123456789abcdef"
              autoComplete="off"
              style={inputStyle}
            />
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 0.8fr) minmax(0, 1.2fr)", gap: 8 }}>
            <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
              <span>Agent Vault scope</span>
              <select
                value={apiTokenAgentVaultScope}
                onChange={(event) => setApiTokenAgentVaultScope(normalizeAgentVaultScope(event.target.value))}
                style={inputStyle}>
                <option value="repo">repo-local</option>
                <option value="global">global</option>
              </select>
            </label>
            <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
              <span>Agent Vault item</span>
              <input
                value={apiTokenAgentVaultItem}
                onChange={(event) => setApiTokenAgentVaultItem(normalizeAgentVaultItemName(event.target.value))}
                placeholder="例: cloudflare"
                autoComplete="off"
                style={inputStyle}
              />
            </label>
          </div>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>API token</span>
            <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8 }}>
              <input
                type={showApiTokenValue ? "text" : "password"}
                value={apiTokenValue}
                onChange={(event) => setApiTokenValue(event.target.value)}
                placeholder="手動で保存するtoken"
                autoComplete="off"
                style={inputStyle}
              />
              <button
                type="button"
                onClick={() => setShowApiTokenValue((current) => !current)}
                style={{
                  ...buttonStyle,
                  padding: "8px 10px",
                  background: "#bfdbfe",
                }}>
                {showApiTokenValue ? "隠す" : "表示"}
              </button>
            </div>
          </label>
          <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <span>メモ</span>
            <textarea
              value={apiTokenNotes}
              onChange={(event) => setApiTokenNotes(event.target.value)}
              placeholder="用途や権限スコープ"
              rows={3}
              autoComplete="off"
              style={{
                ...inputStyle,
                resize: "vertical"
              }}
            />
          </label>
          <button
            type="button"
            onClick={handleSaveApiToken}
            style={{
              ...buttonStyle,
              background: "#a7f3d0",
            }}>
            {editingApiTokenEntry ? "API tokenを更新" : "API tokenを保存"}
          </button>
          {editingApiTokenEntry ? (
            <button
              type="button"
              onClick={resetApiTokenForm}
              style={{
                ...buttonStyle,
                background: "#cbd5e1",
              }}>
              編集をやめる
            </button>
          ) : null}
        </div>
        {apiTokenItems.length > 0 ? (
          <ul style={{ margin: "12px 0 0", padding: 0, display: "grid", gap: 8, listStyle: "none" }}>
            {apiTokenItems.map(({ entryKey, entry, payload }) => (
              <li
                key={entryKey}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto auto auto",
                  gap: 8,
                  alignItems: "center",
                  fontSize: 12
                }}>
                <div style={{ minWidth: 0, display: "grid", gap: 2 }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 700 }}>
                    {entry.label ?? "API token"}
                  </span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#c7d0dd" }}>
                    {payload
                      ? [payload.accountName, payload.accountId, payload.serviceUrl].filter(Boolean).join(" / ") || "詳細なし"
                      : "Vault Key復元後に詳細表示"}
                  </span>
                  {payload?.agentVaultItem ? (
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#99f6e4" }}>
                      {buildAgentVaultSecretRef(normalizeAgentVaultScope(payload.agentVaultScope), payload.agentVaultItem)}
                    </span>
                  ) : null}
                  {payload?.notes ? (
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#94a3b8" }}>
                      {payload.notes}
                    </span>
                  ) : null}
                </div>
                <button
                  type="button"
                  onClick={() => handleEditApiToken(entryKey, entry)}
                  disabled={!payload}
                  style={{
                    ...buttonStyle,
                    padding: "7px 9px",
                    background: payload ? "#bfdbfe" : "#475569",
                    color: payload ? "#10131a" : "#cbd5e1",
                    cursor: payload ? "pointer" : "not-allowed"
                  }}>
                  編集
                </button>
                <button
                  type="button"
                  onClick={() => {
                    void handleCopyApiToken(entryKey, entry)
                  }}
                  disabled={!hasUsableVaultKey}
                  style={{
                    ...buttonStyle,
                    padding: "7px 9px",
                    background: hasUsableVaultKey ? "#fde68a" : "#475569",
                    color: hasUsableVaultKey ? "#10131a" : "#cbd5e1",
                    cursor: hasUsableVaultKey ? "pointer" : "not-allowed"
                  }}>
                  コピー
                </button>
                <button
                  type="button"
                  onClick={() => {
                    void handleDeleteApiToken(entry)
                  }}
                  style={{
                    ...buttonStyle,
                    padding: "7px 9px",
                    background: "#fecaca",
                  }}>
                  削除
                </button>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>このサイト</h2>
        <p style={{ margin: "0 0 8px", fontSize: 12, color: "#c7d0dd" }}>{activeTab.hostname || "判定できへん"}</p>
        <label style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 8 }}>
          <span>自動入力を有効化</span>
          <input
            type="checkbox"
            checked={snapshot.settings.enabled}
            onChange={(event) => {
              void handleSettingsChange({
                enabled: event.target.checked
              })
            }}
          />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
          <span>ドメイン制御</span>
          <select
            value={currentPolicy}
            onChange={(event) => {
              void handlePolicyChange(event.target.value as DomainPolicy)
            }}
            disabled={!activeTab.hostname}
            style={inputStyle}>
            <option value="default">標準</option>
            <option value="whitelist">常に使う</option>
            <option value="blacklist">このサイトは使わない</option>
          </select>
        </label>
        <button
          type="button"
          onClick={handleManualAutofill}
          style={{
            marginTop: 8,
            width: "100%",
            ...buttonStyle,
            background: "#fde68a",
          }}>
          このページで再実行
        </button>
      </section>

      <details style={sectionStyle} open={snapshot.eventLog.length > 0}>
        <summary style={{ cursor: "pointer", fontSize: 14, fontWeight: 700 }}>最近の履歴</summary>
        <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6 }}>
          {snapshot.eventLog.slice(0, 20).map((event) => (
            <li key={event.id} style={{ fontSize: 12, lineHeight: 1.4, color: "#c7d0dd" }}>
              {formatEvent(event)}
            </li>
          ))}
          {snapshot.eventLog.length === 0 ? (
            <li style={{ fontSize: 12, color: "#94a3b8" }}>まだ履歴はないで</li>
          ) : null}
        </ul>
      </details>
    </main>
  )
}

export default PopupApp
