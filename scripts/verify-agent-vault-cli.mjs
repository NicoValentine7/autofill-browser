#!/usr/bin/env node

import { mkdtemp, readFile, rm, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawnSync } from "node:child_process"

const passphrase = "codex-agent-vault-passphrase-for-e2e"
const token = "agent_vault_dummy_secret"
const cloudflareToken = "cloudflare_agent_vault_dummy_secret"

const runCli = (args, options = {}) =>
  spawnSync("node", ["scripts/agent-vault.mjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    input: options.input,
    env: {
      ...process.env,
      AUTOFILL_AGENT_VAULT_PASSPHRASE: passphrase,
      ...(options.env ?? {})
    }
  })

const assertSuccess = (result, label) => {
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr || result.stdout}`)
  }
}

const tempDir = await mkdtemp(join(tmpdir(), "autofill-agent-vault-"))
const vaultPath = join(tempDir, "agent-vault.json")

try {
  const putResult = runCli(
    [
      "--vault-path",
      vaultPath,
      "put",
      "github",
      "--value-stdin",
      "--label",
      "GitHub",
      "--service-url",
      "https://api.github.com",
      "--account",
      "deploy-bot",
      "--notes",
      "dummy verification token"
    ],
    { input: token }
  )
  assertSuccess(putResult, "put")

  const putPresetResult = runCli(["--vault-path", vaultPath, "put", "cloudflare"], {
    env: {
      CLOUDFLARE_API_TOKEN: cloudflareToken
    }
  })
  assertSuccess(putPresetResult, "put preset")

  const rawVault = await readFile(vaultPath, "utf8")
  if (
    rawVault.includes(token) ||
    rawVault.includes(cloudflareToken) ||
    rawVault.includes("https://api.github.com") ||
    rawVault.includes("https://api.cloudflare.com") ||
    rawVault.includes("deploy-bot")
  ) {
    throw new Error("vault file contains plaintext token payload")
  }

  const mode = (await stat(vaultPath)).mode & 0o777
  if (mode !== 0o600) {
    throw new Error(`vault file permissions are ${mode.toString(8)}, expected 600`)
  }

  const readResult = runCli(["--vault-path", vaultPath, "read", "github"])
  assertSuccess(readResult, "read")
  if (readResult.stdout.trim() !== token) {
    throw new Error("read did not return the saved API token")
  }

  const listResult = runCli(["--vault-path", vaultPath, "list", "--json"])
  assertSuccess(listResult, "list")
  if (listResult.stdout.includes(token)) {
    throw new Error("list leaked token plaintext")
  }
  const listed = JSON.parse(listResult.stdout)
  if (!listed.items?.some((item) => item.name === "github" && item.label === "GitHub")) {
    throw new Error("list did not return saved item metadata")
  }
  if (!listed.items.some((item) => item.name === "cloudflare" && item.label === "Cloudflare")) {
    throw new Error("list did not return saved preset metadata")
  }

  const runResult = runCli([
    "--vault-path",
    vaultPath,
    "run",
    "--env",
    "GITHUB_TOKEN=github",
    "--",
    "node",
    "-e",
    "process.stdout.write([process.env.GITHUB_TOKEN, process.env.AUTOFILL_AGENT_VAULT_PASSPHRASE || ''].join('|'))"
  ])
  assertSuccess(runResult, "run")
  if (runResult.stdout !== `${token}|`) {
    throw new Error("run did not inject only the requested token env")
  }

  const runPresetResult = runCli([
    "--vault-path",
    vaultPath,
    "run",
    "cloudflare",
    "--",
    "node",
    "-e",
    "process.stdout.write(process.env.CLOUDFLARE_API_TOKEN || '')"
  ])
  assertSuccess(runPresetResult, "run preset")
  if (runPresetResult.stdout !== cloudflareToken) {
    throw new Error("run preset did not inject CLOUDFLARE_API_TOKEN")
  }

  const presetsResult = runCli(["presets", "--json"])
  assertSuccess(presetsResult, "presets")
  const presets = JSON.parse(presetsResult.stdout)
  if (!presets.presets?.some((preset) => preset.name === "cloudflare" && preset.envName === "CLOUDFLARE_API_TOKEN")) {
    throw new Error("presets did not include cloudflare")
  }

  const deleteResult = runCli(["--vault-path", vaultPath, "delete", "github"])
  assertSuccess(deleteResult, "delete")
  assertSuccess(runCli(["--vault-path", vaultPath, "delete", "cloudflare"]), "delete preset")

  const emptyListResult = runCli(["--vault-path", vaultPath, "list", "--json"])
  assertSuccess(emptyListResult, "empty list")
  if (JSON.parse(emptyListResult.stdout).items.length !== 0) {
    throw new Error("delete did not remove the item")
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        checks: ["put", "put-preset", "encrypted-file", "0600", "read", "list-redacted", "run-env", "run-preset", "presets", "delete"]
      },
      null,
      2
    )
  )
} finally {
  await rm(tempDir, { recursive: true, force: true })
}
