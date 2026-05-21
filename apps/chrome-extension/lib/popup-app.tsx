import { useEffect, useMemo, useState, type CSSProperties } from "react"

import { createEmptyProfile, getDomainPolicy, isProfileConfigured, type DomainPolicy, type EventLogEntry, type StoredProfile } from "@autofill-browser/autofill-core"

import { fetchSignedInUser, pullSyncedSnapshot, pushSyncedSnapshot } from "./account-sync"
import { clearGoogleAuthTokens, getGoogleAccessToken } from "./google-auth"
import type { ExtensionMessage } from "./messages"
import { sendMessageToTab } from "./messages"
import {
  applySyncedSnapshot,
  appendEventEntries,
  clearGoogleAuthUser,
  getStorageSnapshot,
  saveAccountSyncState,
  saveDomainPolicy,
  saveGoogleAuthUser,
  saveProfile,
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

const eventTypeLabels: Record<EventLogEntry["type"], string> = {
  autofill_run: "自動入力実行",
  field_filled: "フィールド入力",
  field_corrected_by_user: "手修正を記録",
  setting_changed: "設定変更",
  domain_policy_changed: "ドメイン制御変更",
  profile_updated: "プロフィール更新",
  manual_autofill_triggered: "手動再実行"
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
  if (event.detail) {
    parts.push(event.detail)
  }
  return parts.join(" / ")
}

function PopupApp() {
  const [snapshot, setSnapshot] = useState<StorageSnapshot | null>(null)
  const [profileForm, setProfileForm] = useState<StoredProfile>(createEmptyProfile())
  const [cloudLogSyncForm, setCloudLogSyncForm] = useState<StorageSnapshot["settings"]["cloudLogSync"]>({
    endpointUrl: "",
    bearerToken: "",
    includeFieldValues: true
  })
  const [activeTab, setActiveTab] = useState<ActiveTabContext>({ hostname: "", url: "" })
  const [status, setStatus] = useState("読み込み中やで")

  const refreshState = async () => {
    const [nextSnapshot, nextTab] = await Promise.all([getStorageSnapshot(), getActiveTabContext()])
    setSnapshot(nextSnapshot)
    setProfileForm(nextSnapshot.profile)
    setCloudLogSyncForm(nextSnapshot.settings.cloudLogSync)
    setActiveTab(nextTab)
    return { nextSnapshot, nextTab }
  }

  useEffect(() => {
    void refreshState().then(() => {
      setStatus("設定を確認できたで")
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

  const handleProfileFieldChange = (key: keyof StoredProfile, value: string) => {
    setProfileForm((current) => ({
      ...current,
      [key]: value
    }))
  }

  const saveDraftCloudLogSettings = async () => {
    const endpointUrl = cloudLogSyncForm.endpointUrl.trim()
    if (endpointUrl && !endpointUrl.startsWith("https://")) {
      setStatus("クラウド保存は https の endpoint が必要やで")
      return null
    }

    if (
      endpointUrl === snapshot.settings.cloudLogSync.endpointUrl &&
      cloudLogSyncForm.bearerToken === snapshot.settings.cloudLogSync.bearerToken &&
      cloudLogSyncForm.includeFieldValues === snapshot.settings.cloudLogSync.includeFieldValues
    ) {
      return snapshot
    }

    const nextSnapshot = await saveSettings(
      {
        cloudLogSync: cloudLogSyncForm
      },
      "popup-ui",
      {
        hostname: activeTab.hostname,
        url: activeTab.url
      }
    )
    setSnapshot(nextSnapshot)
    setCloudLogSyncForm(nextSnapshot.settings.cloudLogSync)
    return nextSnapshot
  }

  const pushSnapshotIfSignedIn = async (nextSnapshot: StorageSnapshot) => {
    if (!nextSnapshot.googleAuthUser || !nextSnapshot.settings.cloudLogSync.endpointUrl.trim()) {
      return nextSnapshot
    }

    const googleAccessToken = await getGoogleAccessToken(false)
    if (!googleAccessToken) {
      setStatus("ローカル保存したで。Google同期は再ログインが必要やな")
      return nextSnapshot
    }

    const remoteUpdatedAt = await pushSyncedSnapshot(
      nextSnapshot.settings.cloudLogSync.endpointUrl,
      googleAccessToken,
      nextSnapshot
    )

    if (!remoteUpdatedAt) {
      setStatus("ローカル保存したで。Google同期は失敗したわ")
      return nextSnapshot
    }

    const syncedSnapshot = await saveAccountSyncState({
      lastPushedAt: new Date().toISOString(),
      lastRemoteUpdatedAt: remoteUpdatedAt
    })
    setSnapshot(syncedSnapshot)
    return syncedSnapshot
  }

  const handleSaveProfile = async () => {
    const nextSnapshot = await saveProfile(profileForm, "popup-ui", {
      hostname: activeTab.hostname,
      url: activeTab.url
    })
    setSnapshot(nextSnapshot)
    await notifyActiveTab(activeTab.id, { type: "PROFILE_UPDATED" })
    await pushSnapshotIfSignedIn(nextSnapshot)
    setStatus("プロフィールを保存したで")
  }

  const handleSettingsChange = async (patch: Partial<StorageSnapshot["settings"]>) => {
    const nextSnapshot = await saveSettings(patch, "popup-ui", {
      hostname: activeTab.hostname,
      url: activeTab.url
    })
    setSnapshot(nextSnapshot)
    await notifyActiveTab(activeTab.id, { type: "SETTINGS_UPDATED" })
    await pushSnapshotIfSignedIn(nextSnapshot)
    setStatus("設定を更新したで")
  }

  const handleCloudLogSyncChange = (patch: Partial<StorageSnapshot["settings"]["cloudLogSync"]>) => {
    setCloudLogSyncForm((current) => ({
      ...current,
      ...patch
    }))
  }

  const handleCloudLogSyncSave = async () => {
    const nextSnapshot = await saveDraftCloudLogSettings()
    if (!nextSnapshot) {
      return
    }

    await pushSnapshotIfSignedIn(nextSnapshot)
    setStatus("クラウドログ設定を保存したで")
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
    await pushSnapshotIfSignedIn(nextSnapshot)
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
    const snapshotWithEndpoint = await saveDraftCloudLogSettings()
    if (!snapshotWithEndpoint) {
      return
    }

    if (!snapshotWithEndpoint.settings.cloudLogSync.endpointUrl.trim()) {
      setStatus("GoogleログインにはWorkerのEndpoint URLが必要やで")
      return
    }

    const googleAccessToken = await getGoogleAccessToken(true)
    if (!googleAccessToken) {
      setStatus("Googleログインがキャンセルされたか失敗したで")
      return
    }

    const googleAuthUser = await fetchSignedInUser(snapshotWithEndpoint.settings.cloudLogSync.endpointUrl, googleAccessToken)
    if (!googleAuthUser) {
      setStatus("WorkerでGoogleログインを確認できへんかった")
      return
    }

    const signedInSnapshot = await saveGoogleAuthUser(googleAuthUser)
    setSnapshot(signedInSnapshot)
    await pushSnapshotIfSignedIn(signedInSnapshot)
    setStatus(`${googleAuthUser.email} でログインしたで`)
  }

  const handleGoogleLogout = async () => {
    await clearGoogleAuthTokens()
    const nextSnapshot = await clearGoogleAuthUser()
    setSnapshot(nextSnapshot)
    setStatus("Googleログアウトしたで")
  }

  const handlePushSync = async () => {
    const snapshotWithEndpoint = await saveDraftCloudLogSettings()
    if (!snapshotWithEndpoint?.settings.cloudLogSync.endpointUrl.trim()) {
      setStatus("同期にはWorkerのEndpoint URLが必要やで")
      return
    }

    const googleAccessToken = await getGoogleAccessToken(true)
    if (!googleAccessToken) {
      setStatus("Googleログインが必要やで")
      return
    }

    const remoteUpdatedAt = await pushSyncedSnapshot(
      snapshotWithEndpoint.settings.cloudLogSync.endpointUrl,
      googleAccessToken,
      snapshotWithEndpoint
    )
    if (!remoteUpdatedAt) {
      setStatus("クラウド保存に失敗したで")
      return
    }

    const nextSnapshot = await saveAccountSyncState({
      lastPushedAt: new Date().toISOString(),
      lastRemoteUpdatedAt: remoteUpdatedAt
    })
    setSnapshot(nextSnapshot)
    setStatus("設定をクラウドへ保存したで")
  }

  const handlePullSync = async () => {
    const snapshotWithEndpoint = await saveDraftCloudLogSettings()
    if (!snapshotWithEndpoint?.settings.cloudLogSync.endpointUrl.trim()) {
      setStatus("復元にはWorkerのEndpoint URLが必要やで")
      return
    }

    const googleAccessToken = await getGoogleAccessToken(true)
    if (!googleAccessToken) {
      setStatus("Googleログインが必要やで")
      return
    }

    const remoteSnapshot = await pullSyncedSnapshot(snapshotWithEndpoint.settings.cloudLogSync.endpointUrl, googleAccessToken)
    if (!remoteSnapshot) {
      setStatus("復元できるクラウド設定がまだ無いで")
      return
    }

    const nextSnapshot = await applySyncedSnapshot(remoteSnapshot, remoteSnapshot.updatedAt)
    setSnapshot(nextSnapshot)
    setProfileForm(nextSnapshot.profile)
    setCloudLogSyncForm(nextSnapshot.settings.cloudLogSync)
    await notifyActiveTab(activeTab.id, { type: "SETTINGS_UPDATED" })
    await notifyActiveTab(activeTab.id, { type: "PROFILE_UPDATED" })
    setStatus("クラウドから設定を復元したで")
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
        <p style={{ margin: "8px 0 0", fontSize: 12, color: "#99f6e4" }}>{status}</p>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>
          {profileReady ? "プロフィール編集" : "まずプロフィールを登録"}
        </h2>
        <div style={{ display: "grid", gap: 8 }}>
          {fieldLabels.map((field) => (
            <label key={field.key} style={{ display: "grid", gap: 4, fontSize: 12 }}>
              <span>{field.label}</span>
              <input
                value={profileForm[field.key]}
                onChange={(event) => handleProfileFieldChange(field.key, event.target.value)}
                placeholder={field.placeholder}
                style={{
                  borderRadius: 8,
                  border: "1px solid #334155",
                  padding: "8px 10px",
                  background: "#0f172a",
                  color: "#f8fafc"
                }}
              />
            </label>
          ))}
          <button
            type="button"
            onClick={handleSaveProfile}
            style={{
              marginTop: 4,
              border: 0,
              borderRadius: 10,
              padding: "10px 12px",
              fontWeight: 600,
              color: "#10131a",
              background: "#99f6e4",
              cursor: "pointer"
            }}>
            プロフィールを保存
          </button>
        </div>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>自動入力の設定</h2>
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
        <label style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 8 }}>
          <span>動的フォームも監視</span>
          <input
            type="checkbox"
            checked={snapshot.settings.observeDynamicForms}
            onChange={(event) => {
              void handleSettingsChange({
                observeDynamicForms: event.target.checked
              })
            }}
          />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
          <span>最小マッチ数</span>
          <input
            type="number"
            min={1}
            value={snapshot.settings.minMatchCount}
            onChange={(event) => {
              void handleSettingsChange({
                minMatchCount: Math.max(1, Number(event.target.value) || 1)
              })
            }}
            style={{
              borderRadius: 8,
              border: "1px solid #334155",
              padding: "8px 10px",
              background: "#0f172a",
              color: "#f8fafc"
            }}
          />
        </label>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>クラウドログ</h2>
        <label style={{ display: "grid", gap: 4, fontSize: 12, marginBottom: 8 }}>
          <span>Endpoint URL</span>
          <input
            type="url"
            value={cloudLogSyncForm.endpointUrl}
            onChange={(event) => {
              handleCloudLogSyncChange({
                endpointUrl: event.target.value
              })
            }}
            placeholder="https://example.com/autofill-logs"
            style={{
              borderRadius: 8,
              border: "1px solid #334155",
              padding: "8px 10px",
              background: "#0f172a",
              color: "#f8fafc"
            }}
          />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 12, marginBottom: 8 }}>
          <span>Bearer token</span>
          <input
            type="password"
            value={cloudLogSyncForm.bearerToken}
            onChange={(event) => {
              handleCloudLogSyncChange({
                bearerToken: event.target.value
              })
            }}
            placeholder="optional"
            style={{
              borderRadius: 8,
              border: "1px solid #334155",
              padding: "8px 10px",
              background: "#0f172a",
              color: "#f8fafc"
            }}
          />
        </label>
        <label style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 8 }}>
          <span>入力値も送信</span>
          <input
            type="checkbox"
            checked={cloudLogSyncForm.includeFieldValues}
            onChange={(event) => {
              handleCloudLogSyncChange({
                includeFieldValues: event.target.checked
              })
            }}
          />
        </label>
        <button
          type="button"
          onClick={handleCloudLogSyncSave}
          style={{
            marginTop: 4,
            width: "100%",
            border: 0,
            borderRadius: 10,
            padding: "10px 12px",
            fontWeight: 600,
            color: "#10131a",
            background: "#bae6fd",
            cursor: "pointer"
          }}>
          クラウドログ設定を保存
        </button>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>Googleアカウント</h2>
        <p style={{ margin: "0 0 8px", fontSize: 12, color: "#c7d0dd" }}>
          {snapshot.googleAuthUser ? `${snapshot.googleAuthUser.email} でログイン中` : "未ログイン"}
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
              border: 0,
              borderRadius: 10,
              padding: "10px 12px",
              fontWeight: 600,
              color: "#10131a",
              background: snapshot.googleAuthUser ? "#fecaca" : "#bbf7d0",
              cursor: "pointer"
            }}>
            {snapshot.googleAuthUser ? "ログアウト" : "Googleでログイン"}
          </button>
          <button
            type="button"
            onClick={handlePushSync}
            style={{
              border: 0,
              borderRadius: 10,
              padding: "10px 12px",
              fontWeight: 600,
              color: "#10131a",
              background: "#c4b5fd",
              cursor: "pointer"
            }}>
            クラウドへ保存
          </button>
          <button
            type="button"
            onClick={handlePullSync}
            style={{
              border: 0,
              borderRadius: 10,
              padding: "10px 12px",
              fontWeight: 600,
              color: "#10131a",
              background: "#fbcfe8",
              cursor: "pointer",
              gridColumn: "1 / -1"
            }}>
            クラウドから復元
          </button>
        </div>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>現在ドメイン</h2>
        <p style={{ margin: "0 0 8px", fontSize: 12, color: "#c7d0dd" }}>{activeTab.hostname || "判定できへん"}</p>
        <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
          <span>ドメイン制御</span>
          <select
            value={currentPolicy}
            onChange={(event) => {
              void handlePolicyChange(event.target.value as DomainPolicy)
            }}
            disabled={!activeTab.hostname}
            style={{
              borderRadius: 8,
              border: "1px solid #334155",
              padding: "8px 10px",
              background: "#0f172a",
              color: "#f8fafc"
            }}>
            <option value="default">default</option>
            <option value="whitelist">whitelist</option>
            <option value="blacklist">blacklist</option>
          </select>
        </label>
        <button
          type="button"
          onClick={handleManualAutofill}
          style={{
            marginTop: 8,
            width: "100%",
            border: 0,
            borderRadius: 10,
            padding: "10px 12px",
            fontWeight: 600,
            color: "#10131a",
            background: "#fde68a",
            cursor: "pointer"
          }}>
          このページで再実行
        </button>
      </section>

      <section style={sectionStyle}>
        <h2 style={{ margin: "0 0 8px", fontSize: 14 }}>最近の履歴</h2>
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
      </section>
    </main>
  )
}

export default PopupApp
