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

export type SecureVaultRecoveryPackage = {
  schemaVersion: 1
  keyId: string
  algorithm: "PBKDF2-SHA256/AES-GCM"
  iterations: number
  salt: string
  iv: string
  ciphertext: string
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

const RECOVERY_KEY_ITERATIONS = 600_000
const MIN_RECOVERY_KEY_ITERATIONS = 250_000
const MAX_RECOVERY_KEY_ITERATIONS = 5_000_000
const RECOVERY_PHRASE_BYTES = 32
export const MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH = 24

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

const bytesToBase64Url = (bytes: Uint8Array) => bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

const base64ToBytes = (value: string) => {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

const getBase64ByteLength = (value: string) => {
  try {
    return base64ToBytes(value).byteLength
  } catch (_error) {
    return null
  }
}

const toArrayBuffer = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer

const getCrypto = () => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable")
  }
  return globalThis.crypto
}

const importKey = async (key: SecureVaultKey) =>
  getCrypto().subtle.importKey("raw", base64ToBytes(key.rawKey), { name: "AES-GCM" }, false, ["encrypt", "decrypt"])

const importPassphraseKey = async (passphrase: string) =>
  getCrypto().subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"])

const deriveRecoveryKey = async (passphrase: string, salt: Uint8Array, iterations: number) =>
  getCrypto().subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      iterations
    },
    await importPassphraseKey(passphrase),
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  )

const normalizeRecoveryPassphrase = (passphrase: string) => passphrase.trim()

const encodeRecoveryAdditionalData = (
  recoveryPackage: Pick<
    SecureVaultRecoveryPackage,
    "schemaVersion" | "keyId" | "algorithm" | "iterations" | "salt" | "iv" | "createdAt"
  >
) =>
  new TextEncoder().encode(
    JSON.stringify([
      recoveryPackage.schemaVersion,
      recoveryPackage.keyId,
      recoveryPackage.algorithm,
      recoveryPackage.iterations,
      recoveryPackage.salt,
      recoveryPackage.iv,
      recoveryPackage.createdAt
    ])
  )

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

export const generateSecureVaultRecoveryPhrase = () => {
  const bytes = new Uint8Array(RECOVERY_PHRASE_BYTES)
  getCrypto().getRandomValues(bytes)
  return bytesToBase64Url(bytes)
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

export const normalizeSecureVaultRecoveryPackage = (
  recoveryPackage?: Partial<SecureVaultRecoveryPackage> | null
): SecureVaultRecoveryPackage | undefined => {
  if (
    recoveryPackage?.schemaVersion !== 1 ||
    recoveryPackage.algorithm !== "PBKDF2-SHA256/AES-GCM" ||
    !recoveryPackage.keyId ||
    !recoveryPackage.salt ||
    !recoveryPackage.iv ||
    !recoveryPackage.ciphertext ||
    !recoveryPackage.createdAt ||
    typeof recoveryPackage.iterations !== "number" ||
    !Number.isFinite(recoveryPackage.iterations) ||
    recoveryPackage.iterations < MIN_RECOVERY_KEY_ITERATIONS ||
    recoveryPackage.iterations > MAX_RECOVERY_KEY_ITERATIONS ||
    getBase64ByteLength(recoveryPackage.salt) !== 16 ||
    getBase64ByteLength(recoveryPackage.iv) !== 12 ||
    (getBase64ByteLength(recoveryPackage.ciphertext) ?? 0) < 16
  ) {
    return undefined
  }

  return {
    schemaVersion: 1,
    keyId: recoveryPackage.keyId,
    algorithm: "PBKDF2-SHA256/AES-GCM",
    iterations: Math.floor(recoveryPackage.iterations),
    salt: recoveryPackage.salt,
    iv: recoveryPackage.iv,
    ciphertext: recoveryPackage.ciphertext,
    createdAt: recoveryPackage.createdAt
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

export const createSecureVaultRecoveryPackage = async (
  key: SecureVaultKey,
  passphrase: string
): Promise<SecureVaultRecoveryPackage | null> => {
  const normalizedPassphrase = normalizeRecoveryPassphrase(passphrase)
  if (normalizedPassphrase.length < MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH) {
    return null
  }

  const salt = new Uint8Array(16)
  const iv = new Uint8Array(12)
  getCrypto().getRandomValues(salt)
  getCrypto().getRandomValues(iv)
  const createdAt = new Date().toISOString()
  const partialRecoveryPackage = {
    schemaVersion: 1 as const,
    keyId: key.keyId,
    algorithm: "PBKDF2-SHA256/AES-GCM" as const,
    iterations: RECOVERY_KEY_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    createdAt
  }
  const recoveryKey = await deriveRecoveryKey(normalizedPassphrase, salt, RECOVERY_KEY_ITERATIONS)
  const ciphertext = await getCrypto().subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: encodeRecoveryAdditionalData(partialRecoveryPackage)
    },
    recoveryKey,
    new TextEncoder().encode(JSON.stringify(key))
  )

  return {
    ...partialRecoveryPackage,
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  }
}

export const recoverSecureVaultKey = async (
  recoveryPackage: SecureVaultRecoveryPackage,
  passphrase: string
): Promise<SecureVaultKey | null> => {
  const normalizedRecoveryPackage = normalizeSecureVaultRecoveryPackage(recoveryPackage)
  if (!normalizedRecoveryPackage) {
    return null
  }

  const normalizedPassphrase = normalizeRecoveryPassphrase(passphrase)
  if (normalizedPassphrase.length < MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH) {
    return null
  }

  try {
    const recoveryKey = await deriveRecoveryKey(
      normalizedPassphrase,
      base64ToBytes(normalizedRecoveryPackage.salt),
      normalizedRecoveryPackage.iterations
    )
    const plaintext = await getCrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(normalizedRecoveryPackage.iv),
        additionalData: encodeRecoveryAdditionalData(normalizedRecoveryPackage)
      },
      recoveryKey,
      base64ToBytes(normalizedRecoveryPackage.ciphertext)
    )
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<SecureVaultKey>
    const recoveredKey = normalizeSecureVaultKey(parsed)
    return recoveredKey?.keyId === normalizedRecoveryPackage.keyId ? recoveredKey : null
  } catch (_error) {
    return null
  }
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
