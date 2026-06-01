import { type FieldDescriptor } from "@autofill-browser/autofill-core"

import {
  getDescriptorIdentity,
  hasIdentityToken,
  requiresSecureAutofillConfirmation,
  type FieldSecurityClassification
} from "./field-security"

export type SecureVaultEntryKind =
  | "bank-account"
  | "payment-card"
  | "card-security-code"
  | "auth-identifier"
  | "api-token"
  | "custom"

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
  keyId?: string
  label?: string
  encryptedValue: SecureVaultEncryptedValue
  timesAutofilled: number
  timesCorrected: number
  timesLearned: number
  createdAt: string
  updatedAt: string
}

export type SecureVaultKeyCheck = {
  keyId: string
  encryptedValue: SecureVaultEncryptedValue
  createdAt: string
}

export type SecureVaultState = {
  schemaVersion: 1
  encryptionVersion: 1
  vaultId: string
  activeKeyId?: string
  keyCheck?: SecureVaultKeyCheck
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
  vaultId?: string
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

export type SecureVaultValueDelete = {
  hostname: string
  fieldSignature: string
}

export type SecureVaultApiTokenItemPayload = {
  schemaVersion: 1
  kind: "api-token"
  token: string
  serviceUrl?: string
  accountName?: string
  notes?: string
}

const RECOVERY_KEY_ITERATIONS = 600_000
const MIN_RECOVERY_KEY_ITERATIONS = 250_000
const MAX_RECOVERY_KEY_ITERATIONS = 5_000_000
const RECOVERY_PHRASE_BYTES = 32
const SECURE_VAULT_KEY_CHECK_VALUE = "secure-vault-key-check:v1"
export const MIN_VAULT_RECOVERY_PASSPHRASE_LENGTH = 24

export const createEmptySecureVault = (): SecureVaultState => ({
  schemaVersion: 1,
  encryptionVersion: 1,
  vaultId: createSecureVaultId(),
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
    "schemaVersion" | "keyId" | "algorithm" | "iterations" | "salt" | "iv" | "createdAt" | "vaultId"
  >,
  includeVaultId = Boolean(recoveryPackage.vaultId)
) => {
  const values = [
    recoveryPackage.schemaVersion,
    recoveryPackage.keyId,
    recoveryPackage.algorithm,
    recoveryPackage.iterations,
    recoveryPackage.salt,
    recoveryPackage.iv,
    recoveryPackage.createdAt
  ]

  if (includeVaultId) {
    values.push(recoveryPackage.vaultId ?? "")
  }

  return new TextEncoder().encode(JSON.stringify(values))
}

const createSecureVaultId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `vault-${Date.now()}-${Math.random()}`

export const MANUAL_SECURE_VAULT_HOSTNAME = "__manual_vault__"

export const createManualSecureVaultValueUpdate = ({
  kind,
  value,
  label
}: {
  kind: SecureVaultEntryKind
  value: string
  label?: string
}): SecureVaultValueUpdate => ({
  hostname: MANUAL_SECURE_VAULT_HOSTNAME,
  fieldSignature: `manual:${kind}:${createSecureVaultId()}`,
  kind,
  value,
  label
})

export const isManualSecureVaultItem = (entry: Pick<SecureVaultEntry, "hostname" | "fieldSignature">) =>
  entry.hostname === MANUAL_SECURE_VAULT_HOSTNAME && entry.fieldSignature.startsWith("manual:")

export const stringifySecureVaultApiTokenItemPayload = (
  payload: Omit<SecureVaultApiTokenItemPayload, "schemaVersion" | "kind">
) =>
  JSON.stringify({
    schemaVersion: 1,
    kind: "api-token",
    token: payload.token.trim(),
    ...(payload.serviceUrl?.trim() ? { serviceUrl: payload.serviceUrl.trim() } : {}),
    ...(payload.accountName?.trim() ? { accountName: payload.accountName.trim() } : {}),
    ...(payload.notes?.trim() ? { notes: payload.notes.trim() } : {})
  } satisfies SecureVaultApiTokenItemPayload)

export const parseSecureVaultApiTokenItemPayload = (value?: string): SecureVaultApiTokenItemPayload | null => {
  const trimmed = value?.trim()
  if (!trimmed) {
    return null
  }

  try {
    const parsed = JSON.parse(trimmed) as Partial<SecureVaultApiTokenItemPayload>
    if (parsed.schemaVersion === 1 && parsed.kind === "api-token" && parsed.token?.trim()) {
      return {
        schemaVersion: 1,
        kind: "api-token",
        token: parsed.token.trim(),
        ...(parsed.serviceUrl?.trim() ? { serviceUrl: parsed.serviceUrl.trim() } : {}),
        ...(parsed.accountName?.trim() ? { accountName: parsed.accountName.trim() } : {}),
        ...(parsed.notes?.trim() ? { notes: parsed.notes.trim() } : {})
      }
    }
  } catch (_error) {
    return {
      schemaVersion: 1,
      kind: "api-token",
      token: trimmed
    }
  }

  return null
}

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
    ...(recoveryPackage.vaultId?.trim() ? { vaultId: recoveryPackage.vaultId.trim() } : {}),
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

const normalizeSecureVaultKeyCheck = (value?: Partial<SecureVaultKeyCheck> | null): SecureVaultKeyCheck | undefined => {
  const encryptedValue = normalizeEncryptedValue(value?.encryptedValue)
  if (!value?.keyId || !value.createdAt || !encryptedValue) {
    return undefined
  }

  return {
    keyId: value.keyId,
    encryptedValue,
    createdAt: value.createdAt
  }
}

const normalizeEntryKind = (value: unknown): SecureVaultEntryKind =>
  value === "bank-account" ||
  value === "payment-card" ||
  value === "card-security-code" ||
  value === "auth-identifier" ||
  value === "api-token" ||
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
      keyId: entry.keyId?.trim() || undefined,
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
    vaultId: vault?.vaultId?.trim() || createSecureVaultId(),
    activeKeyId: vault?.activeKeyId?.trim() || normalizeSecureVaultKeyCheck(vault?.keyCheck)?.keyId,
    keyCheck: normalizeSecureVaultKeyCheck(vault?.keyCheck),
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
  passphrase: string,
  vaultId?: string
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
    ...(vaultId?.trim() ? { vaultId: vaultId.trim() } : {}),
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
  passphrase: string,
  expectedVault?: SecureVaultState
): Promise<SecureVaultKey | null> => {
  const normalizedRecoveryPackage = normalizeSecureVaultRecoveryPackage(recoveryPackage)
  if (!normalizedRecoveryPackage) {
    return null
  }

  if (
    expectedVault?.vaultId &&
    normalizedRecoveryPackage.vaultId &&
    expectedVault.vaultId !== normalizedRecoveryPackage.vaultId
  ) {
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
    if (recoveredKey?.keyId !== normalizedRecoveryPackage.keyId) {
      return null
    }

    if (expectedVault?.keyCheck && !(await validateSecureVaultKey(expectedVault, recoveredKey))) {
      return null
    }

    return recoveredKey
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

const buildSecureVaultKeyCheckPlaintext = (vaultId: string, keyId: string) => `${SECURE_VAULT_KEY_CHECK_VALUE}:${vaultId}:${keyId}`

export const validateSecureVaultKey = async (vault: SecureVaultState, key?: SecureVaultKey) => {
  if (!key) {
    return false
  }

  if (!vault.keyCheck) {
    return true
  }

  if (vault.keyCheck.keyId !== key.keyId) {
    return false
  }

  return (await decryptSecureValue(vault.keyCheck.encryptedValue, key)) === buildSecureVaultKeyCheckPlaintext(vault.vaultId, key.keyId)
}

export const ensureSecureVaultKeyCheck = async (vault: SecureVaultState, key: SecureVaultKey): Promise<SecureVaultState> => {
  const normalizedVault = normalizeSecureVaultState(vault)
  if (normalizedVault.keyCheck && !(await validateSecureVaultKey(normalizedVault, key))) {
    return normalizedVault
  }

  const keyCheck =
    normalizedVault.keyCheck?.keyId === key.keyId
      ? normalizedVault.keyCheck
      : {
          keyId: key.keyId,
          encryptedValue: await encryptSecureValue(buildSecureVaultKeyCheckPlaintext(normalizedVault.vaultId, key.keyId), key),
          createdAt: new Date().toISOString()
        }

  return {
    ...normalizedVault,
    activeKeyId: key.keyId,
    keyCheck
  }
}

export const decryptSecureVaultValues = async (vault: SecureVaultState, key?: SecureVaultKey) => {
  if (!key || !(await validateSecureVaultKey(vault, key))) {
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
  const checkedVault = await ensureSecureVaultKeyCheck(vault, key)
  if (checkedVault.keyCheck && !(await validateSecureVaultKey(checkedVault, key))) {
    return checkedVault
  }

  const entryKey = getSecureVaultEntryKey(update.hostname, update.fieldSignature)
  const existingEntry = checkedVault.entries[entryKey]
  const now = new Date().toISOString()

  return {
    ...checkedVault,
    entries: {
      ...checkedVault.entries,
      [entryKey]: {
        hostname: update.hostname,
        fieldSignature: update.fieldSignature,
        kind: update.kind,
        keyId: key.keyId,
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

export const deleteSecureVaultValue = (vault: SecureVaultState, deletion: SecureVaultValueDelete): SecureVaultState => {
  const normalizedVault = normalizeSecureVaultState(vault)
  const entryKey = getSecureVaultEntryKey(deletion.hostname, deletion.fieldSignature)
  const { [entryKey]: _deletedEntry, ...entries } = normalizedVault.entries

  return {
    ...normalizedVault,
    entries
  }
}
