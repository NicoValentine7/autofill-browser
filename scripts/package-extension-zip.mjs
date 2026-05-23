import { spawnSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const extensionPackage = JSON.parse(readFileSync(resolve(repoRoot, "apps/chrome-extension/package.json"), "utf8"))
const buildDir = resolve(repoRoot, process.argv[2] ?? "apps/chrome-extension/build/chrome-mv3-prod")
const outputZip = resolve(repoRoot, process.argv[3] ?? `dist/releases/autofill-browser-chrome-v${extensionPackage.version}.zip`)

if (!existsSync(resolve(buildDir, "manifest.json"))) {
  console.error(`Build manifest not found: ${resolve(buildDir, "manifest.json")}`)
  console.error("Run pnpm build:extension before packaging.")
  process.exit(1)
}

mkdirSync(dirname(outputZip), {
  recursive: true
})

if (existsSync(outputZip)) {
  unlinkSync(outputZip)
}

const result = spawnSync("zip", ["-qr", outputZip, "."], {
  cwd: buildDir,
  stdio: "inherit"
})

if (result.status !== 0) {
  process.exit(result.status ?? 1)
}

console.log(`Extension package written to ${outputZip}`)
