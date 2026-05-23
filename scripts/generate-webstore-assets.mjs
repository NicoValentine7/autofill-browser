import { spawn } from "node:child_process"
import { copyFileSync, existsSync, mkdirSync, rmSync, statSync, writeFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const outputDir = resolve(repoRoot, "dist/store-assets")
const renderDir = resolve(outputDir, "_render")
const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
const extensionIconPath = resolve(repoRoot, "apps/chrome-extension/assets/icon.png")

const html = (body, size) => `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=${size.width}, initial-scale=1" />
    <style>
      * { box-sizing: border-box; }
      html, body { width: ${size.width}px; height: ${size.height}px; margin: 0; overflow: hidden; }
      body { font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      ${body.styles}
    </style>
  </head>
  <body>${body.markup}</body>
</html>
`

const iconDocument = {
  styles: `
    body {
      display: grid;
      place-items: center;
      background: #f8fafc;
    }
    .icon {
      width: 128px;
      height: 128px;
      border-radius: 30px;
      background: linear-gradient(145deg, #11243a 0%, #1e5b5f 52%, #f26b4f 100%);
      position: relative;
      overflow: hidden;
    }
    .sheet {
      position: absolute;
      left: 24px;
      top: 22px;
      width: 80px;
      height: 84px;
      border-radius: 12px;
      background: #ffffff;
      box-shadow: 0 18px 35px rgba(6, 16, 28, 0.28);
    }
    .line {
      position: absolute;
      left: 38px;
      width: 52px;
      height: 8px;
      border-radius: 999px;
      background: #dbe7ee;
    }
    .line:nth-child(2) { top: 44px; }
    .line:nth-child(3) { top: 62px; width: 40px; }
    .line:nth-child(4) { top: 80px; width: 48px; }
    .check {
      position: absolute;
      right: 18px;
      bottom: 18px;
      width: 44px;
      height: 44px;
      border-radius: 50%;
      background: #29c785;
      box-shadow: 0 12px 28px rgba(17, 36, 58, 0.26);
    }
    .check::after {
      content: "";
      position: absolute;
      left: 13px;
      top: 10px;
      width: 16px;
      height: 24px;
      border: solid #ffffff;
      border-width: 0 6px 6px 0;
      transform: rotate(42deg);
      border-radius: 2px;
    }
  `,
  markup: `
    <div class="icon">
      <div class="sheet"></div>
      <div class="line"></div>
      <div class="line"></div>
      <div class="line"></div>
      <div class="check"></div>
    </div>
  `
}

const screenshotDocument = {
  styles: `
    body {
      background: #f3f6f8;
      color: #172433;
    }
    .frame {
      width: 1280px;
      height: 800px;
      display: grid;
      grid-template-columns: 1fr 380px;
      gap: 28px;
      padding: 42px;
    }
    .browser, .panel {
      border: 1px solid #d7e1e8;
      background: #ffffff;
      box-shadow: 0 24px 70px rgba(21, 35, 50, 0.14);
    }
    .browser {
      border-radius: 8px;
      overflow: hidden;
      display: grid;
      grid-template-rows: 48px 1fr;
    }
    .topbar {
      display: flex;
      gap: 8px;
      align-items: center;
      padding: 0 18px;
      background: #eef3f6;
      border-bottom: 1px solid #d7e1e8;
    }
    .dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: #ec6b5f;
    }
    .dot:nth-child(2) { background: #f4bf50; }
    .dot:nth-child(3) { background: #61c554; }
    .address {
      margin-left: 16px;
      height: 28px;
      width: 520px;
      border-radius: 999px;
      background: #ffffff;
      color: #607080;
      display: flex;
      align-items: center;
      padding: 0 18px;
      font-size: 13px;
    }
    .content {
      padding: 44px 54px;
    }
    h1 {
      font-size: 34px;
      margin: 0 0 8px;
      letter-spacing: 0;
    }
    .sub {
      color: #617181;
      font-size: 16px;
      margin-bottom: 32px;
    }
    .form {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }
    .field {
      border: 1px solid #d8e2e8;
      border-radius: 7px;
      padding: 12px 14px;
      min-height: 68px;
      background: #fbfdfe;
    }
    .field.wide { grid-column: span 2; }
    .label {
      font-size: 12px;
      color: #657584;
      margin-bottom: 8px;
    }
    .value {
      font-size: 18px;
      font-weight: 650;
    }
    .filled {
      border-color: #38b989;
      box-shadow: 0 0 0 3px rgba(56, 185, 137, 0.12);
    }
    .panel {
      border-radius: 8px;
      padding: 24px;
      align-self: start;
    }
    .brand {
      display: flex;
      gap: 12px;
      align-items: center;
      margin-bottom: 22px;
    }
    .brand-mark {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      background: linear-gradient(145deg, #11243a, #29c785 60%, #f26b4f);
    }
    .brand-title {
      font-size: 20px;
      font-weight: 760;
    }
    .status {
      padding: 12px 14px;
      border: 1px solid #cbe7da;
      border-radius: 7px;
      background: #f1fbf6;
      color: #176648;
      font-size: 14px;
      margin-bottom: 18px;
    }
    .button {
      height: 44px;
      border-radius: 7px;
      background: #173047;
      color: #ffffff;
      display: grid;
      place-items: center;
      font-weight: 700;
      margin-bottom: 22px;
    }
    .list {
      display: grid;
      gap: 12px;
    }
    .item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid #e3eaee;
      padding-top: 12px;
      color: #415363;
      font-size: 14px;
    }
    .pill {
      border-radius: 999px;
      padding: 4px 10px;
      background: #eef4f7;
      color: #284256;
      font-size: 12px;
      font-weight: 700;
    }
  `,
  markup: `
    <main class="frame">
      <section class="browser">
        <div class="topbar">
          <div class="dot"></div>
          <div class="dot"></div>
          <div class="dot"></div>
          <div class="address">https://checkout.example</div>
        </div>
        <div class="content">
          <h1>Checkout details</h1>
          <div class="sub">Reusable fields are filled from the local profile and secure vault.</div>
          <div class="form">
            <div class="field filled">
              <div class="label">Full name</div>
              <div class="value">Taro Yamada</div>
            </div>
            <div class="field filled">
              <div class="label">Email</div>
              <div class="value">taro@example.com</div>
            </div>
            <div class="field wide filled">
              <div class="label">Address</div>
              <div class="value">1-2-3 Shibuya, Tokyo</div>
            </div>
            <div class="field">
              <div class="label">Branch number</div>
              <div class="value">Protected</div>
            </div>
            <div class="field">
              <div class="label">Account number</div>
              <div class="value">Protected</div>
            </div>
          </div>
        </div>
      </section>
      <aside class="panel">
        <div class="brand">
          <div class="brand-mark"></div>
          <div class="brand-title">Autofill Browser</div>
        </div>
        <div class="status">Google sync is active</div>
        <div class="button">Fill visible form</div>
        <div class="list">
          <div class="item"><span>Profile</span><span class="pill">Cloud</span></div>
          <div class="item"><span>Secure Vault</span><span class="pill">Local key</span></div>
          <div class="item"><span>Domain rules</span><span class="pill">Synced</span></div>
          <div class="item"><span>Activity log</span><span class="pill">D1</span></div>
        </div>
      </aside>
    </main>
  `
}

const captureScreenshot = (args, outputPath) =>
  new Promise((resolve, reject) => {
    const child = spawn(chromePath, args, {
      stdio: ["ignore", "ignore", "pipe"]
    })
    let stderr = ""
    let stopping = false
    let forceKillTimeout

    const stop = () => {
      if (stopping) {
        return
      }

      stopping = true
      child.kill("SIGTERM")
      forceKillTimeout = setTimeout(() => {
        child.kill("SIGKILL")
      }, 2000)
    }

    const interval = setInterval(() => {
      if (existsSync(outputPath) && statSync(outputPath).size > 0) {
        stop()
      }
    }, 250)

    const timeout = setTimeout(() => {
      stop()
    }, 15000)

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString()
    })

    child.on("error", (error) => {
      clearInterval(interval)
      clearTimeout(timeout)
      reject(error)
    })

    child.on("exit", (code, signal) => {
      clearInterval(interval)
      clearTimeout(timeout)
      clearTimeout(forceKillTimeout)

      if (existsSync(outputPath) && statSync(outputPath).size > 0) {
        resolve()
        return
      }

      reject(new Error(`Chrome screenshot failed with code ${code ?? signal ?? "unknown"}\n${stderr}`))
    })
  })

if (!existsSync(chromePath)) {
  console.error(`Google Chrome not found at ${chromePath}`)
  process.exit(1)
}

mkdirSync(renderDir, {
  recursive: true
})

const iconHtmlPath = resolve(renderDir, "icon.html")
const screenshotHtmlPath = resolve(renderDir, "screenshot.html")
const iconOutputPath = resolve(outputDir, "icon-128.png")
const screenshotOutputPath = resolve(outputDir, "screenshot-1280x800.png")
const userDataDir = resolve(outputDir, ".chrome-user-data")

writeFileSync(iconHtmlPath, html(iconDocument, { width: 128, height: 128 }))
writeFileSync(screenshotHtmlPath, html(screenshotDocument, { width: 1280, height: 800 }))
rmSync(userDataDir, {
  recursive: true,
  force: true
})

const chromeArgs = [
  "--headless=new",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-default-apps",
  "--disable-extensions",
  "--disable-gpu",
  "--hide-scrollbars",
  "--no-first-run",
  "--no-default-browser-check",
  `--user-data-dir=${userDataDir}`
]

await captureScreenshot(
  [...chromeArgs, "--window-size=128,128", `--screenshot=${iconOutputPath}`, `file://${iconHtmlPath}`],
  iconOutputPath
)
await captureScreenshot([
  ...chromeArgs,
  "--window-size=1280,800",
  `--screenshot=${screenshotOutputPath}`,
  `file://${screenshotHtmlPath}`
], screenshotOutputPath)

copyFileSync(iconOutputPath, extensionIconPath)
console.log(`Extension icon written to ${extensionIconPath}`)
console.log(`Web Store icon written to ${iconOutputPath}`)
console.log(`Web Store screenshot written to ${screenshotOutputPath}`)
