import { readFileSync, writeFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const clientId = process.argv[2]?.trim()

if (!clientId || !clientId.endsWith(".apps.googleusercontent.com")) {
  console.error("Usage: pnpm set:google-oauth-client <client-id.apps.googleusercontent.com>")
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
extensionPackage.manifest = {
  ...extensionPackage.manifest,
  oauth2: {
    ...extensionPackage.manifest?.oauth2,
    client_id: clientId
  }
}
writeJson(extensionPackagePath, extensionPackage)

const wranglerConfig = readJson(wranglerPath)
wranglerConfig.vars = {
  ...wranglerConfig.vars,
  GOOGLE_OAUTH_CLIENT_ID: clientId
}
writeJson(wranglerPath, wranglerConfig)

console.log(`Google OAuth client ID written to ${extensionPackagePath}`)
console.log(`Google OAuth client ID written to ${wranglerPath}`)
