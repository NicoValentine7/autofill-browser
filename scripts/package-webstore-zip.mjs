import { spawnSync } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const extensionPackagePath = resolve(repoRoot, "apps/chrome-extension/package.json")
const extensionPackage = JSON.parse(readFileSync(extensionPackagePath, "utf8"))

const usage = `Usage: pnpm package:webstore [input.zip] [output.zip] [--oauth-client-id <client-id.apps.googleusercontent.com>]

Environment:
  WEBSTORE_GOOGLE_OAUTH_CLIENT_ID  Optional OAuth client ID for the Chrome Web Store item.
`

const args = process.argv.slice(2)
let inputZip
let outputZip
let webstoreGoogleOAuthClientId = process.env.WEBSTORE_GOOGLE_OAUTH_CLIENT_ID?.trim()

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index]

  if (arg === "--help" || arg === "-h") {
    console.log(usage)
    process.exit(0)
  }

  if (arg === "--oauth-client-id") {
    webstoreGoogleOAuthClientId = args[index + 1]?.trim()
    index += 1
    continue
  }

  if (arg.startsWith("--oauth-client-id=")) {
    webstoreGoogleOAuthClientId = arg.slice("--oauth-client-id=".length).trim()
    continue
  }

  if (!inputZip) {
    inputZip = arg
    continue
  }

  if (!outputZip) {
    outputZip = arg
    continue
  }

  console.error(usage)
  process.exit(1)
}

if (webstoreGoogleOAuthClientId && !webstoreGoogleOAuthClientId.endsWith(".apps.googleusercontent.com")) {
  console.error("Web Store Google OAuth client ID must end with .apps.googleusercontent.com")
  process.exit(1)
}

const version = extensionPackage.version
const defaultInputZip = resolve(repoRoot, `dist/releases/autofill-browser-chrome-v${version}.zip`)
const resolvedInputZip = resolve(repoRoot, inputZip ?? defaultInputZip)
const resolvedOutputZip = resolve(repoRoot, outputZip ?? resolvedInputZip.replace(/\.zip$/, "-webstore.zip"))

if (!existsSync(resolvedInputZip)) {
  console.error(`Input zip not found: ${resolvedInputZip}`)
  process.exit(1)
}

const run = (command, commandArgs, options = {}) => {
  const result = spawnSync(command, commandArgs, {
    stdio: "inherit",
    ...options
  })

  if (result.status !== 0) {
    process.exit(result.status ?? 1)
  }
}

const tempDir = mkdtempSync(join(tmpdir(), "autofill-webstore-"))

try {
  run("unzip", ["-q", resolvedInputZip, "-d", tempDir])

  const manifestPath = join(tempDir, "manifest.json")
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"))
  delete manifest.key

  if (webstoreGoogleOAuthClientId) {
    manifest.oauth2 = {
      ...manifest.oauth2,
      client_id: webstoreGoogleOAuthClientId
    }
  }

  writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`)

  if (existsSync(resolvedOutputZip)) {
    unlinkSync(resolvedOutputZip)
  }

  run("zip", ["-qr", resolvedOutputZip, "."], {
    cwd: tempDir
  })

  console.log(`Web Store package written to ${resolvedOutputZip}`)
  console.log("Removed manifest.key")
  if (webstoreGoogleOAuthClientId) {
    console.log(`Set Web Store OAuth client ID: ${webstoreGoogleOAuthClientId}`)
  }
} finally {
  rmSync(tempDir, {
    recursive: true,
    force: true
  })
}
