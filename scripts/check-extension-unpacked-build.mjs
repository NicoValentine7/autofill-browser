import { readdir, readFile, stat } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import { join, resolve } from "node:path"

const scriptDir = fileURLToPath(new URL(".", import.meta.url))
const repoRoot = resolve(scriptDir, "..")
const buildDir = resolve(repoRoot, "apps/chrome-extension/build/chrome-mv3-dev")
const blockedPatterns = [
  /new WebSocket\(/,
  /ws:\/\/localhost/,
  /wss:\/\/localhost/,
  /@parcel\/runtime-browser-hmr/,
  /parcel-runtime:\s*HMR/
]

async function collectJavaScriptFiles(directory) {
  const entries = await readdir(directory)
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry)
      const info = await stat(path)

      if (info.isDirectory()) {
        return collectJavaScriptFiles(path)
      }

      return path.endsWith(".js") ? [path] : []
    })
  )

  return files.flat()
}

const files = await collectJavaScriptFiles(buildDir)
const offenders = []

for (const file of files) {
  const source = await readFile(file, "utf8")
  const matchedPattern = blockedPatterns.find((pattern) => pattern.test(source))

  if (matchedPattern) {
    offenders.push(`${file.replace(`${repoRoot}/`, "")}: ${matchedPattern}`)
  }
}

if (offenders.length > 0) {
  console.error("Unpacked extension build still contains Parcel/Plasmo HMR runtime:")
  for (const offender of offenders) {
    console.error(`- ${offender}`)
  }
  process.exit(1)
}

console.log("Unpacked extension build is free of Parcel/Plasmo HMR runtime.")
