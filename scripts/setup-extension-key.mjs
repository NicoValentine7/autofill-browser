import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const extensionDir = resolve(repoRoot, "apps/chrome-extension")
const keyDir = resolve(extensionDir, ".extension-key")
const privateKeyPath = resolve(keyDir, "autofill-browser-extension-key.pem")
const envPath = resolve(extensionDir, ".env.local")
const envName = "AUTOFILL_EXTENSION_MANIFEST_KEY"

const ensurePrivateKey = () => {
  if (existsSync(privateKeyPath)) {
    return readFileSync(privateKeyPath, "utf8")
  }

  mkdirSync(keyDir, { recursive: true })
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem"
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    }
  })

  writeFileSync(privateKeyPath, privateKey, { mode: 0o600 })
  try {
    chmodSync(privateKeyPath, 0o600)
  } catch {
    // Best effort on non-POSIX filesystems.
  }

  return privateKey
}

const deriveManifestKey = (privateKeyPem) =>
  createPublicKey(privateKeyPem)
    .export({
      type: "spki",
      format: "der"
    })
    .toString("base64")

const deriveExtensionId = (manifestKey) => {
  const digest = createHash("sha256").update(Buffer.from(manifestKey, "base64")).digest()
  const alphabet = "abcdefghijklmnop"
  return Array.from(digest.subarray(0, 16))
    .flatMap((byte) => [alphabet[byte >> 4], alphabet[byte & 0x0f]])
    .join("")
}

const updateEnvFile = (manifestKey) => {
  const lines = existsSync(envPath) ? readFileSync(envPath, "utf8").split(/\r?\n/) : []
  const nextLine = `${envName}=${manifestKey}`
  const keyPattern = new RegExp(`^${envName}=`)
  const existingIndex = lines.findIndex((line) => keyPattern.test(line))

  if (existingIndex >= 0) {
    lines[existingIndex] = nextLine
  } else {
    if (lines.length > 0 && lines.at(-1) !== "") {
      lines.push("")
    }
    lines.push(nextLine)
  }

  writeFileSync(envPath, `${lines.filter((line, index) => index < lines.length - 1 || line !== "").join("\n")}\n`)
}

const privateKey = ensurePrivateKey()
const manifestKey = deriveManifestKey(privateKey)
const extensionId = deriveExtensionId(manifestKey)
updateEnvFile(manifestKey)

console.log(`Manifest key written to ${envPath}`)
console.log(`Private key kept at ${privateKeyPath}`)
console.log(`Stable extension ID: ${extensionId}`)
