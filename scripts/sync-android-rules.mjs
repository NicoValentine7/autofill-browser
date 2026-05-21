import { copyFileSync, mkdirSync } from "node:fs"
import { dirname } from "node:path"
import { fileURLToPath } from "node:url"

const sourceUrl = new URL("../packages/autofill-core/src/autofill-rules.json", import.meta.url)
const targetUrl = new URL("../apps/android-browser/app/src/main/assets/autofill-rules.json", import.meta.url)
const targetPath = fileURLToPath(targetUrl)

mkdirSync(dirname(targetPath), { recursive: true })
copyFileSync(sourceUrl, targetUrl)
