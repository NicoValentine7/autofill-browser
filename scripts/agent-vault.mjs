#!/usr/bin/env node

import { spawn } from "node:child_process"
import { stdin as input, stdout as output, stderr as errorOutput } from "node:process"

import {
  AGENT_VAULT_PASSPHRASE_ENV,
  AgentVaultError,
  DEFAULT_AGENT_VAULT_PATH,
  deleteAgentVaultItem,
  getAgentVaultApiToken,
  listAgentVaultItems,
  putAgentVaultApiToken,
  readAgentVaultFile,
  resolveAgentVaultPath,
  validateAgentVaultEnvName,
  writeAgentVaultFile
} from "./agent-vault-lib.mjs"

const AGENT_VAULT_PRESETS = {
  cloudflare: {
    name: "cloudflare",
    envName: "CLOUDFLARE_API_TOKEN",
    label: "Cloudflare",
    serviceUrl: "https://api.cloudflare.com/client/v4"
  },
  github: {
    name: "github",
    envName: "GITHUB_TOKEN",
    label: "GitHub",
    serviceUrl: "https://api.github.com"
  }
}

const usage = `Usage:
  pnpm agent-vault put cloudflare
  pnpm agent-vault put <name> --value-stdin [--label <label>] [--service-url <url>] [--account <name>] [--notes <text>]
  pnpm agent-vault put <name> --value-env <ENV_NAME> [--label <label>]
  pnpm agent-vault read <name>
  pnpm agent-vault list [--json]
  pnpm agent-vault delete <name>
  pnpm agent-vault run cloudflare -- <command> [args...]
  pnpm agent-vault run --env <ENV_NAME>=<item-name> [--env <ENV_NAME>=<item-name>] -- <command> [args...]
  pnpm agent-vault presets [--json]

Options:
  --vault-path <path>   Agent Vault file path. Defaults to ${DEFAULT_AGENT_VAULT_PATH}

Required env:
  ${AGENT_VAULT_PASSPHRASE_ENV} must be set for put/read/delete/run.
`

const getAgentVaultPreset = (name) => AGENT_VAULT_PRESETS[String(name ?? "").trim().toLowerCase()] ?? null
const listAgentVaultPresets = () => Object.values(AGENT_VAULT_PRESETS).sort((left, right) => left.name.localeCompare(right.name))

const takeOptionValue = (args, index, optionName) => {
  const value = args[index + 1]
  if (!value || value.startsWith("--")) {
    throw new AgentVaultError(`${optionName} requires a value.`, "MISSING_OPTION_VALUE")
  }
  return value
}

const parseGlobalOptions = (argv) => {
  const args = [...argv]
  let vaultPath = process.env.AUTOFILL_AGENT_VAULT_PATH ?? DEFAULT_AGENT_VAULT_PATH

  while (args[0]?.startsWith("--")) {
    const option = args.shift()
    if (option === "--vault-path") {
      vaultPath = args.shift()
      if (!vaultPath || vaultPath.startsWith("--")) {
        throw new AgentVaultError(`${option} requires a value.`, "MISSING_OPTION_VALUE")
      }
    } else if (option === "--help" || option === "-h") {
      return { command: "help", args: [], vaultPath }
    } else {
      throw new AgentVaultError(`Unknown option before command: ${option}`, "UNKNOWN_OPTION")
    }
  }

  return {
    command: args.shift() ?? "help",
    args,
    vaultPath
  }
}

const parseCommandOptions = (args, allowedOptions) => {
  const values = {}
  const positional = []
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (!arg.startsWith("--")) {
      positional.push(arg)
      continue
    }

    const optionConfig = allowedOptions[arg]
    if (!optionConfig) {
      throw new AgentVaultError(`Unknown option: ${arg}`, "UNKNOWN_OPTION")
    }

    if (optionConfig.type === "boolean") {
      values[optionConfig.name] = true
      continue
    }

    values[optionConfig.name] = takeOptionValue(args, index, arg)
    index += 1
  }

  return { positional, values }
}

const readStdin = async () => {
  if (input.isTTY) {
    throw new AgentVaultError("Pipe the token value to stdin when using --value-stdin.", "STDIN_REQUIRED")
  }

  let value = ""
  input.setEncoding("utf8")
  for await (const chunk of input) {
    value += chunk
  }
  return value
}

const requirePassphrase = () => process.env[AGENT_VAULT_PASSPHRASE_ENV]

const handlePut = async (args, vaultPath) => {
  const { positional, values } = parseCommandOptions(args, {
    "--value-stdin": { name: "valueStdin", type: "boolean" },
    "--value-env": { name: "valueEnv", type: "string" },
    "--label": { name: "label", type: "string" },
    "--service-url": { name: "serviceUrl", type: "string" },
    "--account": { name: "accountName", type: "string" },
    "--notes": { name: "notes", type: "string" }
  })
  const name = positional[0]
  if (!name) {
    throw new AgentVaultError("put requires an item name.", "MISSING_ITEM_NAME")
  }
  const preset = getAgentVaultPreset(name)

  if (values.valueStdin && values.valueEnv) {
    throw new AgentVaultError("Use either --value-stdin or --value-env, not both.", "AMBIGUOUS_TOKEN_SOURCE")
  }

  const inferredEnvName = values.valueEnv ? validateAgentVaultEnvName(values.valueEnv) : preset?.envName
  const token = values.valueStdin
    ? await readStdin()
    : inferredEnvName
      ? process.env[inferredEnvName]
      : null

  if (inferredEnvName && !token) {
    throw new AgentVaultError(`Environment variable is empty or missing: ${inferredEnvName}`, "MISSING_TOKEN_ENV")
  }

  const currentVault = await readAgentVaultFile(vaultPath)
  const nextVault = await putAgentVaultApiToken({
    vault: currentVault,
    passphrase: requirePassphrase(),
    name,
    token,
    label: values.label ?? preset?.label,
    serviceUrl: values.serviceUrl ?? preset?.serviceUrl,
    accountName: values.accountName,
    notes: values.notes
  })
  await writeAgentVaultFile(vaultPath, nextVault)
  output.write(`saved ${name}\n`)
}

const handleRead = async (args, vaultPath) => {
  const name = args[0]
  if (!name) {
    throw new AgentVaultError("read requires an item name.", "MISSING_ITEM_NAME")
  }

  const vault = await readAgentVaultFile(vaultPath)
  if (!vault) {
    throw new AgentVaultError("Agent Vault file does not exist.", "VAULT_NOT_FOUND")
  }

  const item = await getAgentVaultApiToken({
    vault,
    passphrase: requirePassphrase(),
    name
  })
  output.write(`${item.payload.token}\n`)
}

const handleList = async (args, vaultPath) => {
  const { values } = parseCommandOptions(args, {
    "--json": { name: "json", type: "boolean" }
  })
  const vault = await readAgentVaultFile(vaultPath)
  const items = listAgentVaultItems(vault)
  if (values.json) {
    output.write(`${JSON.stringify({ items }, null, 2)}\n`)
    return
  }

  if (items.length === 0) {
    output.write("No Agent Vault items.\n")
    return
  }

  for (const item of items) {
    output.write(`${item.name}\t${item.kind}\t${item.label}\t${item.updatedAt}\n`)
  }
}

const handleDelete = async (args, vaultPath) => {
  const name = args[0]
  if (!name) {
    throw new AgentVaultError("delete requires an item name.", "MISSING_ITEM_NAME")
  }

  const vault = await readAgentVaultFile(vaultPath)
  if (!vault) {
    throw new AgentVaultError("Agent Vault file does not exist.", "VAULT_NOT_FOUND")
  }

  const nextVault = await deleteAgentVaultItem({
    vault,
    passphrase: requirePassphrase(),
    name
  })
  await writeAgentVaultFile(vaultPath, nextVault)
  output.write(`deleted ${name}\n`)
}

const parseRunArgs = (args) => {
  const envMappings = []
  let separatorIndex = args.indexOf("--")
  if (separatorIndex === -1) {
    separatorIndex = args.length
  }

  for (let index = 0; index < separatorIndex; index += 1) {
    if (args[index] !== "--env") {
      const preset = getAgentVaultPreset(args[index])
      if (!preset) {
        throw new AgentVaultError(`Unknown run preset: ${args[index]}. Use --env ENV_NAME=item for custom items.`, "UNKNOWN_RUN_PRESET")
      }
      envMappings.push({
        envName: preset.envName,
        itemName: preset.name
      })
      continue
    }
    const mapping = args[index + 1]
    if (!mapping) {
      throw new AgentVaultError("--env requires ENV_NAME=item-name.", "MISSING_OPTION_VALUE")
    }
    const [envName, itemName, ...extra] = mapping.split("=")
    if (!envName || !itemName || extra.length > 0) {
      throw new AgentVaultError("--env must be formatted as ENV_NAME=item-name.", "INVALID_ENV_MAPPING")
    }
    envMappings.push({
      envName: validateAgentVaultEnvName(envName),
      itemName
    })
    index += 1
  }

  const command = args.slice(separatorIndex + 1)
  if (command.length === 0) {
    throw new AgentVaultError("run requires a command after --.", "MISSING_RUN_COMMAND")
  }

  return { envMappings, command }
}

const handleRun = async (args, vaultPath) => {
  const { envMappings, command } = parseRunArgs(args)
  if (envMappings.length === 0) {
    throw new AgentVaultError("run requires at least one --env mapping.", "MISSING_ENV_MAPPING")
  }

  const vault = await readAgentVaultFile(vaultPath)
  if (!vault) {
    throw new AgentVaultError("Agent Vault file does not exist.", "VAULT_NOT_FOUND")
  }

  const injectedEnv = {}
  for (const mapping of envMappings) {
    const item = await getAgentVaultApiToken({
      vault,
      passphrase: requirePassphrase(),
      name: mapping.itemName
    })
    injectedEnv[mapping.envName] = item.payload.token
  }

  const childEnv = {
    ...process.env,
    ...injectedEnv
  }
  delete childEnv[AGENT_VAULT_PASSPHRASE_ENV]

  const child = spawn(command[0], command.slice(1), {
    stdio: "inherit",
    env: childEnv
  })

  await new Promise((resolve, reject) => {
    child.on("error", (error) => {
      reject(new AgentVaultError(`run command failed to start: ${error.message}`, "RUN_COMMAND_FAILED"))
    })
    child.on("exit", (code, signal) => {
      if (signal) {
        process.kill(process.pid, signal)
        return
      }
      process.exitCode = code ?? 1
      resolve()
    })
  })
}

const handlePresets = (args) => {
  const { values } = parseCommandOptions(args, {
    "--json": { name: "json", type: "boolean" }
  })
  const presets = listAgentVaultPresets()
  if (values.json) {
    output.write(`${JSON.stringify({ presets }, null, 2)}\n`)
    return
  }

  for (const preset of presets) {
    output.write(`${preset.name}\t${preset.envName}\t${preset.label}\n`)
  }
}

const main = async () => {
  const { command, args, vaultPath } = parseGlobalOptions(process.argv.slice(2))
  const resolvedVaultPath = resolveAgentVaultPath(vaultPath)

  switch (command) {
    case "help":
      output.write(usage)
      break
    case "put":
      await handlePut(args, resolvedVaultPath)
      break
    case "read":
      await handleRead(args, resolvedVaultPath)
      break
    case "list":
      await handleList(args, resolvedVaultPath)
      break
    case "delete":
      await handleDelete(args, resolvedVaultPath)
      break
    case "run":
      await handleRun(args, resolvedVaultPath)
      break
    case "presets":
      handlePresets(args)
      break
    default:
      throw new AgentVaultError(`Unknown command: ${command}`, "UNKNOWN_COMMAND")
  }
}

try {
  await main()
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  errorOutput.write(`${message}\n`)
  process.exitCode = 1
}
