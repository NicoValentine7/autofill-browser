import { type FieldDescriptor } from "@autofill-browser/autofill-core"

import {
  getDescriptorIdentity,
  hasIdentityToken,
  requiresSecureAutofillConfirmation,
  type FieldSecurityClassification
} from "./field-security"

export type SecureVaultEntryKind = "bank-account" | "payment-card" | "card-security-code" | "auth-identifier" | "custom"

export type SecureVaultEncryptedValue = {
  schemaVersion: 1
  algorithm: "AES-GCM"
  iv: string
  ciphertext: string
}

export type SecureVaultEntry = {
  hostname: string
  fieldSignature: string
  kind: SecureVaultEntryKind
  label?: string
  encryptedValue: SecureVaultEncryptedValue
  timesAutofilled: number
  timesCorrected: number
  timesLearned: number
  createdAt: string
  updatedAt: string
}

export type SecureVaultState = {
  schemaVersion: 1
  encryptionVersion: 1
  entries: Record<string, SecureVaultEntry>
}

export type SecureVaultKey = {
  schemaVersion: 1
  keyId: string
  algorithm: "AES-GCM"
  rawKey: string
  createdAt: string
}

export type SecureVaultValueUpdate = {
  hostname: string
  fieldSignature: string
  kind: SecureVaultEntryKind
  value: string
  label?: string
  incrementAutofilled?: boolean
  incrementCorrected?: boolean
  incrementLearned?: boolean
}

export const createEmptySecureVault = (): SecureVaultState => ({
  schemaVersion: 1,
  encryptionVersion: 1,
  entries: {}
})

const bytesToBase64 = (bytes: Uint8Array) => {
  let binary = ""
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

const base64ToBytes = (value: string) => {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

const getCrypto = () => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable")
  }
  return globalThis.crypto
}

const importKey = async (key: SecureVaultKey) =>
  getCrypto().subtle.importKey("raw", base64ToBytes(key.rawKey), { name: "AES-GCM" }, false, ["encrypt", "decrypt"])

export const createSecureVaultKey = (): SecureVaultKey => {
  const rawKey = new Uint8Array(32)
  getCrypto().getRandomValues(rawKey)

  return {
    schemaVersion: 1,
    keyId: typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
    algorithm: "AES-GCM",
    rawKey: bytesToBase64(rawKey),
    createdAt: new Date().toISOString()
  }
}

export const normalizeSecureVaultKey = (key?: Partial<SecureVaultKey> | null): SecureVaultKey | undefined => {
  if (key?.schemaVersion !== 1 || key.algorithm !== "AES-GCM" || !key.rawKey || !key.keyId || !key.createdAt) {
    return undefined
  }

  return {
    schemaVersion: 1,
    keyId: key.keyId,
    algorithm: "AES-GCM",
    rawKey: key.rawKey,
    createdAt: key.createdAt
  }
}

const normalizeEncryptedValue = (value?: Partial<SecureVaultEncryptedValue>): SecureVaultEncryptedValue | null => {
  if (value?.schemaVersion !== 1 || value.algorithm !== "AES-GCM" || !value.iv || !value.ciphertext) {
    return null
  }

  return {
    schemaVersion: 1,
    algorithm: "AES-GCM",
    iv: value.iv,
    ciphertext: value.ciphertext
  }
}

const normalizeEntryKind = (value: unknown): SecureVaultEntryKind =>
  value === "bank-account" ||
  value === "payment-card" ||
  value === "card-security-code" ||
  value === "auth-identifier" ||
  value === "custom"
    ? value
    : "custom"

export const normalizeSecureVaultState = (vault?: Partial<SecureVaultState> | null): SecureVaultState => {
  const entries: Record<string, SecureVaultEntry> = {}
  const rawEntries = vault?.entries && typeof vault.entries === "object" ? vault.entries : {}

  for (const [key, value] of Object.entries(rawEntries)) {
    const entry = value as Partial<SecureVaultEntry>
    const encryptedValue = normalizeEncryptedValue(entry.encryptedValue)
    if (!entry.hostname || !entry.fieldSignature || !encryptedValue) {
      continue
    }

    entries[key] = {
      hostname: entry.hostname,
      fieldSignature: entry.fieldSignature,
      kind: normalizeEntryKind(entry.kind),
      label: entry.label?.trim() || undefined,
      encryptedValue,
      timesAutofilled: Math.max(0, Math.floor(entry.timesAutofilled ?? 0)),
      timesCorrected: Math.max(0, Math.floor(entry.timesCorrected ?? 0)),
      timesLearned: Math.max(0, Math.floor(entry.timesLearned ?? 0)),
      createdAt: entry.createdAt?.trim() || new Date().toISOString(),
      updatedAt: entry.updatedAt?.trim() || new Date().toISOString()
    }
  }

  return {
    schemaVersion: 1,
    encryptionVersion: 1,
    entries
  }
}

export const getSecureVaultEntryKey = (hostname: string, fieldSignature: string) => `${hostname}::${fieldSignature}`

export const classifySecureVaultKind = (
  descriptor: FieldDescriptor,
  classification: FieldSecurityClassification
): SecureVaultEntryKind | null => {
  if (classification === "normal" || classification === "blocked") {
    return null
  }

  if (requiresSecureAutofillConfirmation(classification)) {
    return "card-security-code"
  }

  const identity = getDescriptorIdentity(descriptor)

  if (
    hasIdentityToken(identity, [
      "branch code",
      "branch number",
      "account number",
      "account no",
      "bank account",
      "支店番号",
      "支店コード",
      "口座番号"
    ])
  ) {
    return "bank-account"
  }

  if (
    hasIdentityToken(identity, [
      "card number",
      "credit card",
      "cc number",
      "cc name",
      "cardholder",
      "card holder",
      "name on card",
      "expiry",
      "expiration",
      "cc exp",
      "カード番号",
      "カード名義",
      "名義人",
      "有効期限"
    ])
  ) {
    return "payment-card"
  }

  if (
    hasIdentityToken(identity, [
      "login user id",
      "user id",
      "userid",
      "customer id",
      "ログインid",
      "ユーザーid"
    ])
  ) {
    return "auth-identifier"
  }

  return "custom"
}

export const encryptSecureValue = async (value: string, key: SecureVaultKey): Promise<SecureVaultEncryptedValue> => {
  const iv = new Uint8Array(12)
  getCrypto().getRandomValues(iv)
  const cryptoKey = await importKey(key)
  const ciphertext = await getCrypto().subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, new TextEncoder().encode(value))

  return {
    schemaVersion: 1,
    algorithm: "AES-GCM",
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  }
}

export const decryptSecureValue = async (
  encryptedValue: SecureVaultEncryptedValue,
  key: SecureVaultKey
): Promise<string | null> => {
  try {
    const cryptoKey = await importKey(key)
    const plaintext = await getCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(encryptedValue.iv) },
      cryptoKey,
      base64ToBytes(encryptedValue.ciphertext)
    )
    return new TextDecoder().decode(plaintext)
  } catch (_error) {
    return null
  }
}

export const decryptSecureVaultValues = async (vault: SecureVaultState, key?: SecureVaultKey) => {
  if (!key) {
    return {}
  }

  const values: Record<string, string> = {}
  for (const [entryKey, entry] of Object.entries(vault.entries)) {
    const value = await decryptSecureValue(entry.encryptedValue, key)
    if (value) {
      values[entryKey] = value
    }
  }
  return values
}

export const upsertSecureVaultValue = async (
  vault: SecureVaultState,
  key: SecureVaultKey,
  update: SecureVaultValueUpdate
): Promise<SecureVaultState> => {
  const entryKey = getSecureVaultEntryKey(update.hostname, update.fieldSignature)
  const existingEntry = vault.entries[entryKey]
  const now = new Date().toISOString()

  return {
    ...vault,
    entries: {
      ...vault.entries,
      [entryKey]: {
        hostname: update.hostname,
        fieldSignature: update.fieldSignature,
        kind: update.kind,
        label: update.label?.trim() || existingEntry?.label,
        encryptedValue: await encryptSecureValue(update.value, key),
        timesAutofilled: (existingEntry?.timesAutofilled ?? 0) + (update.incrementAutofilled ? 1 : 0),
        timesCorrected: (existingEntry?.timesCorrected ?? 0) + (update.incrementCorrected ? 1 : 0),
        timesLearned: (existingEntry?.timesLearned ?? 0) + (update.incrementLearned ? 1 : 0),
        createdAt: existingEntry?.createdAt ?? now,
        updatedAt: now
      }
    }
  }
}
