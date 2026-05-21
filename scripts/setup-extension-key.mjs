import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const extensionDir = resolve(repoRoot, "apps/chrome-extension")
const packageJsonPath = resolve(extensionDir, "package.json")
const keyDir = resolve(extensionDir, ".extension-key")
const privateKeyPath = resolve(keyDir, "autofill-browser-extension-key.pem")
const rotateRequested = process.argv.includes("--rotate")

const readPackageJson = () => JSON.parse(readFileSync(packageJsonPath, "utf8"))

const writePackageJson = (packageJson) => {
  writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`)
}

const isPlaceholderKey = (key) => typeof key === "string" && key.startsWith("$")

const readTrackedManifestKey = () => {
  const manifestKey = readPackageJson().manifest?.key
  return typeof manifestKey === "string" && manifestKey.length > 0 && !isPlaceholderKey(manifestKey) ? manifestKey : ""
}

const writeTrackedManifestKey = (manifestKey) => {
  const packageJson = readPackageJson()
  packageJson.manifest = {
    ...packageJson.manifest,
    key: manifestKey
  }
  writePackageJson(packageJson)
}

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

const trackedManifestKey = readTrackedManifestKey()

if (trackedManifestKey && !rotateRequested) {
  console.log(`Manifest key is already tracked in ${packageJsonPath}`)
  console.log(`Stable extension ID: ${deriveExtensionId(trackedManifestKey)}`)
  if (existsSync(privateKeyPath)) {
    console.log(`Private key is available at ${privateKeyPath}`)
  } else {
    console.log("Private key is not needed for unpacked Chrome builds.")
  }
  process.exit(0)
}

const privateKey = ensurePrivateKey()
const manifestKey = deriveManifestKey(privateKey)
const extensionId = deriveExtensionId(manifestKey)
writeTrackedManifestKey(manifestKey)

console.log(`Manifest key written to ${packageJsonPath}`)
console.log(`Private key kept at ${privateKeyPath}`)
console.log(`Stable extension ID: ${extensionId}`)
