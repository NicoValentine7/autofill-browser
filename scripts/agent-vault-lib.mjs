import { promises as fs } from "node:fs"
import { dirname, resolve } from "node:path"
import { randomUUID, webcrypto } from "node:crypto"

export const DEFAULT_AGENT_VAULT_PATH = ".local/agent-vault.json"
export const AGENT_VAULT_PASSPHRASE_ENV = "AUTOFILL_AGENT_VAULT_PASSPHRASE"
export const AGENT_VAULT_PATH_ENV = "AUTOFILL_AGENT_VAULT_PATH"

const SCHEMA_VERSION = 1
const DEFAULT_KDF_ITERATIONS = 600_000
const MIN_KDF_ITERATIONS = 250_000
const MAX_KDF_ITERATIONS = 5_000_000
const KEY_CHECK_VALUE = "agent-vault-key-check:v1"
const MAX_SECRET_BYTES = 128 * 1024
const MAX_NOTES_LENGTH = 10_000
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

const cryptoImpl = globalThis.crypto?.subtle ? globalThis.crypto : webcrypto
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

export class AgentVaultError extends Error {
  constructor(message, code = "AGENT_VAULT_ERROR") {
    super(message)
    this.name = "AgentVaultError"
    this.code = code
  }
}

const toBase64 = (bytes) => Buffer.from(bytes).toString("base64")
const fromBase64 = (value) => new Uint8Array(Buffer.from(value, "base64"))
const getBase64ByteLength = (value) => {
  try {
    return fromBase64(value).byteLength
  } catch (_error) {
    return null
  }
}
const encodeAad = (values) => textEncoder.encode(JSON.stringify(values))
const nowIso = () => new Date().toISOString()

const normalizePassphrase = (passphrase) => String(passphrase ?? "").trim()

export const resolveAgentVaultPath = (vaultPath = process.env[AGENT_VAULT_PATH_ENV] ?? DEFAULT_AGENT_VAULT_PATH) =>
  resolve(process.cwd(), vaultPath)

export const validateAgentVaultItemName = (name) => {
  const normalizedName = String(name ?? "").trim()
  if (!NAME_PATTERN.test(normalizedName)) {
    throw new AgentVaultError(
      "Vault item name must start with a letter or number and contain only letters, numbers, dot, underscore, colon, or hyphen.",
      "INVALID_ITEM_NAME"
    )
  }
  return normalizedName
}

export const validateAgentVaultEnvName = (name) => {
  const normalizedName = String(name ?? "").trim()
  if (!ENV_NAME_PATTERN.test(normalizedName)) {
    throw new AgentVaultError("Environment variable names must match [A-Za-z_][A-Za-z0-9_]*.", "INVALID_ENV_NAME")
  }
  return normalizedName
}

const assertPassphrase = (passphrase) => {
  const normalizedPassphrase = normalizePassphrase(passphrase)
  if (normalizedPassphrase.length < 24) {
    throw new AgentVaultError(
      `${AGENT_VAULT_PASSPHRASE_ENV} must be at least 24 characters for Agent Vault operations.`,
      "MISSING_PASSPHRASE"
    )
  }
  return normalizedPassphrase
}

const assertSecretSize = (value) => {
  if (textEncoder.encode(value).byteLength > MAX_SECRET_BYTES) {
    throw new AgentVaultError("Vault item value is too large.", "SECRET_TOO_LARGE")
  }
}

const importPassphraseKey = async (passphrase) =>
  cryptoImpl.subtle.importKey("raw", textEncoder.encode(passphrase), "PBKDF2", false, ["deriveKey"])

const deriveVaultKey = async (passphrase, salt, iterations) =>
  cryptoImpl.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
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

const encryptText = async (value, key, additionalData) => {
  const iv = new Uint8Array(12)
  cryptoImpl.getRandomValues(iv)
  const ciphertext = await cryptoImpl.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData
    },
    key,
    textEncoder.encode(value)
  )

  return {
    schemaVersion: SCHEMA_VERSION,
    algorithm: "AES-GCM",
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext))
  }
}

const decryptText = async (encryptedValue, key, additionalData) => {
  try {
    const plaintext = await cryptoImpl.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64(encryptedValue.iv),
        additionalData
      },
      key,
      fromBase64(encryptedValue.ciphertext)
    )
    return textDecoder.decode(plaintext)
  } catch (_error) {
    return null
  }
}

const normalizeEncryptedValue = (value) => {
  if (
    value?.schemaVersion !== SCHEMA_VERSION ||
    value.algorithm !== "AES-GCM" ||
    !value.iv ||
    !value.ciphertext ||
    getBase64ByteLength(value.iv) !== 12 ||
    (getBase64ByteLength(value.ciphertext) ?? 0) < 16
  ) {
    return null
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    algorithm: "AES-GCM",
    iv: String(value.iv),
    ciphertext: String(value.ciphertext)
  }
}

const normalizeKdf = (kdf) => {
  if (
    kdf?.name !== "PBKDF2-SHA256" ||
    typeof kdf.iterations !== "number" ||
    !Number.isFinite(kdf.iterations) ||
    kdf.iterations < MIN_KDF_ITERATIONS ||
    kdf.iterations > MAX_KDF_ITERATIONS ||
    getBase64ByteLength(kdf.salt) !== 16
  ) {
    return null
  }

  return {
    name: "PBKDF2-SHA256",
    iterations: Math.floor(kdf.iterations),
    salt: String(kdf.salt)
  }
}

export const normalizeAgentVaultFile = (value) => {
  const kdf = normalizeKdf(value?.kdf)
  const keyCheck = normalizeEncryptedValue(value?.keyCheck)
  if (value?.schemaVersion !== SCHEMA_VERSION || value.algorithm !== "PBKDF2-SHA256/AES-GCM" || !value.vaultId || !kdf || !keyCheck) {
    throw new AgentVaultError("Agent Vault file is missing required encrypted vault metadata.", "INVALID_VAULT_FILE")
  }

  const items = {}
  const rawItems = value.items && typeof value.items === "object" ? value.items : {}
  for (const [rawName, rawItem] of Object.entries(rawItems)) {
    const encryptedValue = normalizeEncryptedValue(rawItem?.encryptedValue)
    if (rawItem?.schemaVersion !== SCHEMA_VERSION || rawItem.kind !== "api-token" || !encryptedValue) {
      continue
    }

    const name = validateAgentVaultItemName(rawName)
    items[name] = {
      schemaVersion: SCHEMA_VERSION,
      kind: "api-token",
      label: rawItem.label?.trim() || name,
      encryptedValue,
      createdAt: rawItem.createdAt?.trim() || value.createdAt,
      updatedAt: rawItem.updatedAt?.trim() || rawItem.createdAt?.trim() || value.createdAt
    }
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    algorithm: "PBKDF2-SHA256/AES-GCM",
    vaultId: String(value.vaultId),
    kdf,
    keyCheck,
    items,
    createdAt: value.createdAt?.trim() || nowIso(),
    updatedAt: value.updatedAt?.trim() || value.createdAt?.trim() || nowIso()
  }
}

const buildKeyCheckAad = (vault) => encodeAad(["key-check", vault.schemaVersion, vault.algorithm, vault.vaultId, vault.kdf])
const buildItemAad = (vault, name, kind) => encodeAad(["item", vault.schemaVersion, vault.algorithm, vault.vaultId, name, kind])

const createAgentVaultFile = async (passphrase, options = {}) => {
  const vaultId = randomUUID()
  const salt = new Uint8Array(16)
  cryptoImpl.getRandomValues(salt)
  const createdAt = nowIso()
  const vault = {
    schemaVersion: SCHEMA_VERSION,
    algorithm: "PBKDF2-SHA256/AES-GCM",
    vaultId,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: options.iterations ?? DEFAULT_KDF_ITERATIONS,
      salt: toBase64(salt)
    },
    keyCheck: null,
    items: {},
    createdAt,
    updatedAt: createdAt
  }
  const key = await deriveVaultKey(passphrase, salt, vault.kdf.iterations)
  vault.keyCheck = await encryptText(`${KEY_CHECK_VALUE}:${vaultId}`, key, buildKeyCheckAad(vault))
  return vault
}

const unlockAgentVault = async (vault, passphrase) => {
  const key = await deriveVaultKey(passphrase, fromBase64(vault.kdf.salt), vault.kdf.iterations)
  const keyCheck = await decryptText(vault.keyCheck, key, buildKeyCheckAad(vault))
  if (keyCheck !== `${KEY_CHECK_VALUE}:${vault.vaultId}`) {
    throw new AgentVaultError("Agent Vault passphrase did not unlock this vault.", "INVALID_PASSPHRASE")
  }
  return key
}

export const readAgentVaultFile = async (vaultPath) => {
  try {
    const raw = await fs.readFile(vaultPath, "utf8")
    return normalizeAgentVaultFile(JSON.parse(raw))
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null
    }
    if (error instanceof AgentVaultError) {
      throw error
    }
    throw new AgentVaultError("Agent Vault file could not be read.", "READ_FAILED")
  }
}

export const writeAgentVaultFile = async (vaultPath, vault) => {
  await fs.mkdir(dirname(vaultPath), { recursive: true })
  const normalizedVault = normalizeAgentVaultFile(vault)
  const temporaryPath = `${vaultPath}.${process.pid}.${Date.now()}.tmp`
  await fs.writeFile(temporaryPath, `${JSON.stringify(normalizedVault, null, 2)}\n`, { mode: 0o600 })
  await fs.chmod(temporaryPath, 0o600)
  await fs.rename(temporaryPath, vaultPath)
  await fs.chmod(vaultPath, 0o600)
}

const normalizeApiTokenPayload = ({ token, serviceUrl, accountName, notes }) => {
  const normalizedToken = String(token ?? "").trim()
  if (!normalizedToken) {
    throw new AgentVaultError("API token value is required.", "MISSING_TOKEN")
  }
  assertSecretSize(normalizedToken)

  const normalizedNotes = String(notes ?? "").trim()
  if (normalizedNotes.length > MAX_NOTES_LENGTH) {
    throw new AgentVaultError("API token notes are too long.", "NOTES_TOO_LONG")
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    kind: "api-token",
    token: normalizedToken,
    ...(String(serviceUrl ?? "").trim() ? { serviceUrl: String(serviceUrl).trim() } : {}),
    ...(String(accountName ?? "").trim() ? { accountName: String(accountName).trim() } : {}),
    ...(normalizedNotes ? { notes: normalizedNotes } : {})
  }
}

const parseApiTokenPayload = (value) => {
  try {
    const parsed = JSON.parse(value)
    if (parsed?.schemaVersion === SCHEMA_VERSION && parsed.kind === "api-token" && String(parsed.token ?? "").trim()) {
      return normalizeApiTokenPayload(parsed)
    }
  } catch (_error) {
    return null
  }
  return null
}

export const putAgentVaultApiToken = async ({
  vault,
  passphrase,
  name,
  token,
  label,
  serviceUrl,
  accountName,
  notes,
  iterations
}) => {
  const normalizedName = validateAgentVaultItemName(name)
  const normalizedPassphrase = assertPassphrase(passphrase)
  const nextVault = vault ? normalizeAgentVaultFile(vault) : await createAgentVaultFile(normalizedPassphrase, { iterations })
  const key = await unlockAgentVault(nextVault, normalizedPassphrase)
  const payload = normalizeApiTokenPayload({ token, serviceUrl, accountName, notes })
  const existingItem = nextVault.items[normalizedName]
  const timestamp = nowIso()

  return {
    ...nextVault,
    items: {
      ...nextVault.items,
      [normalizedName]: {
        schemaVersion: SCHEMA_VERSION,
        kind: "api-token",
        label: String(label ?? "").trim() || existingItem?.label || normalizedName,
        encryptedValue: await encryptText(JSON.stringify(payload), key, buildItemAad(nextVault, normalizedName, "api-token")),
        createdAt: existingItem?.createdAt ?? timestamp,
        updatedAt: timestamp
      }
    },
    updatedAt: timestamp
  }
}

export const getAgentVaultApiToken = async ({ vault, passphrase, name }) => {
  const normalizedName = validateAgentVaultItemName(name)
  const normalizedVault = normalizeAgentVaultFile(vault)
  const key = await unlockAgentVault(normalizedVault, assertPassphrase(passphrase))
  const item = normalizedVault.items[normalizedName]
  if (!item) {
    throw new AgentVaultError(`Vault item not found: ${normalizedName}`, "ITEM_NOT_FOUND")
  }

  const plaintext = await decryptText(item.encryptedValue, key, buildItemAad(normalizedVault, normalizedName, item.kind))
  const payload = plaintext ? parseApiTokenPayload(plaintext) : null
  if (!payload) {
    throw new AgentVaultError(`Vault item could not be decrypted: ${normalizedName}`, "ITEM_DECRYPT_FAILED")
  }

  return {
    name: normalizedName,
    kind: item.kind,
    label: item.label,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    payload
  }
}

export const listAgentVaultItems = (vault) => {
  if (!vault) {
    return []
  }
  const normalizedVault = normalizeAgentVaultFile(vault)
  return Object.entries(normalizedVault.items)
    .map(([name, item]) => ({
      name,
      kind: item.kind,
      label: item.label,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    }))
    .sort((left, right) => left.name.localeCompare(right.name))
}

export const deleteAgentVaultItem = async ({ vault, passphrase, name }) => {
  const normalizedName = validateAgentVaultItemName(name)
  const normalizedVault = normalizeAgentVaultFile(vault)
  await unlockAgentVault(normalizedVault, assertPassphrase(passphrase))
  const { [normalizedName]: _deletedItem, ...items } = normalizedVault.items
  return {
    ...normalizedVault,
    items,
    updatedAt: nowIso()
  }
}
