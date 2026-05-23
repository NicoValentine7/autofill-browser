import { readFileSync, writeFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const args = process.argv.slice(2)
const mode = args.includes("--webstore") ? "webstore" : "local"
const clientId = args.find((arg) => !arg.startsWith("--"))?.trim()

if (!clientId || !clientId.endsWith(".apps.googleusercontent.com")) {
  console.error("Usage: pnpm set:google-oauth-client <client-id.apps.googleusercontent.com> [--webstore]")
  process.exit(1)
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const extensionPackagePath = resolve(repoRoot, "apps/chrome-extension/package.json")
const wranglerPath = resolve(repoRoot, "apps/log-worker/wrangler.jsonc")

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"))
const writeJson = (path, data) => {
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`)
}

const extensionPackage = readJson(extensionPackagePath)
if (mode === "local") {
  extensionPackage.manifest = {
    ...extensionPackage.manifest,
    oauth2: {
      ...extensionPackage.manifest?.oauth2,
      client_id: clientId
    }
  }
  writeJson(extensionPackagePath, extensionPackage)
}

const wranglerConfig = readJson(wranglerPath)
const existingClientIds = [
  wranglerConfig.vars?.GOOGLE_OAUTH_CLIENT_ID,
  ...(wranglerConfig.vars?.GOOGLE_OAUTH_CLIENT_IDS ?? "").split(",")
]
  .map((value) => (typeof value === "string" ? value.trim() : ""))
  .filter(Boolean)

wranglerConfig.vars = {
  ...wranglerConfig.vars,
  GOOGLE_OAUTH_CLIENT_IDS: [...new Set([...existingClientIds, clientId])].join(",")
}

if (mode === "local") {
  wranglerConfig.vars.GOOGLE_OAUTH_CLIENT_ID = clientId
}

writeJson(wranglerPath, wranglerConfig)

if (mode === "local") {
  console.log(`Google OAuth client ID written to ${extensionPackagePath}`)
} else {
  console.log("Web Store Google OAuth client ID preserved for packaging only")
}
console.log(`Google OAuth client ID written to ${wranglerPath}`)
