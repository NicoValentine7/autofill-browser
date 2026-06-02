import { mkdtemp, readFile, rm, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { describe, expect, it } from "vitest"

import {
  deleteAgentVaultItem,
  getAgentVaultApiToken,
  listAgentVaultItems,
  putAgentVaultApiToken,
  readAgentVaultFile,
  writeAgentVaultFile
} from "../../../scripts/agent-vault-lib.mjs"

const passphrase = "test-agent-vault-passphrase"

const withTempVault = async (fn) => {
  const tempDir = await mkdtemp(join(tmpdir(), "agent-vault-lib-test-"))
  try {
    return await fn(join(tempDir, "agent-vault.json"))
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
}

describe("agent vault library", () => {
  it("stores API token payloads encrypted and reads them with the passphrase", async () =>
    withTempVault(async (vaultPath) => {
      const vault = await putAgentVaultApiToken({
        vault: null,
        passphrase,
        name: "github",
        token: "agent_vault_test_secret",
        label: "GitHub",
        serviceUrl: "https://api.github.com",
        accountName: "deploy-bot",
        notes: "repo deploy scope",
        iterations: 250_000
      })

      await writeAgentVaultFile(vaultPath, vault)
      const raw = await readFile(vaultPath, "utf8")
      expect(raw).not.toContain("agent_vault_test_secret")
      expect(raw).not.toContain("https://api.github.com")
      expect(raw).not.toContain("deploy-bot")
      expect((await stat(vaultPath)).mode & 0o777).toBe(0o600)

      const loaded = await readAgentVaultFile(vaultPath)
      const item = await getAgentVaultApiToken({ vault: loaded, passphrase, name: "github" })
      expect(item).toMatchObject({
        name: "github",
        kind: "api-token",
        label: "GitHub",
        payload: {
          token: "agent_vault_test_secret",
          serviceUrl: "https://api.github.com",
          accountName: "deploy-bot",
          notes: "repo deploy scope"
        }
      })
    }))

  it("lists only non-secret metadata", async () => {
    const vault = await putAgentVaultApiToken({
      vault: null,
      passphrase,
      name: "github",
      token: "agent_vault_test_secret",
      label: "GitHub",
      iterations: 250_000
    })

    expect(JSON.stringify(listAgentVaultItems(vault))).not.toContain("agent_vault_test_secret")
    expect(listAgentVaultItems(vault)).toMatchObject([
      {
        name: "github",
        kind: "api-token",
        label: "GitHub"
      }
    ])
  })

  it("rejects the wrong passphrase and can delete an item", async () => {
    const vault = await putAgentVaultApiToken({
      vault: null,
      passphrase,
      name: "github",
      token: "agent_vault_test_secret",
      iterations: 250_000
    })

    await expect(getAgentVaultApiToken({ vault, passphrase: "wrong-passphrase-value-123", name: "github" })).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE"
    })

    const deletedVault = await deleteAgentVaultItem({ vault, passphrase, name: "github" })
    expect(listAgentVaultItems(deletedVault)).toEqual([])
  })
})
