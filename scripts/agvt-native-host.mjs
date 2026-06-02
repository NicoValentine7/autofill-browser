#!/usr/bin/env node

import { spawnSync } from "node:child_process"

const AGVT_BIN = process.env.AGVT_BIN || "agvt"
const ITEM_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

const readNativeMessage = async () => {
  const chunks = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk)
  }
  const input = Buffer.concat(chunks)
  if (input.length < 4) {
    throw new Error("native message is missing length header")
  }
  const length = input.readUInt32LE(0)
  const body = input.subarray(4, 4 + length)
  if (body.length !== length) {
    throw new Error("native message body is truncated")
  }
  return JSON.parse(body.toString("utf8"))
}

const writeNativeMessage = (message) => {
  const body = Buffer.from(JSON.stringify(message), "utf8")
  const header = Buffer.alloc(4)
  header.writeUInt32LE(body.length, 0)
  process.stdout.write(Buffer.concat([header, body]))
}

const asTrimmedString = (value) => String(value ?? "").trim()

const assertItemName = (value) => {
  const item = asTrimmedString(value)
  if (!ITEM_NAME_PATTERN.test(item)) {
    throw new Error("Agent Vault item name is invalid")
  }
  return item
}

const pushOption = (args, name, value) => {
  const normalized = asTrimmedString(value)
  if (normalized) {
    args.push(name, normalized)
  }
}

const upsertApiToken = (message) => {
  const item = assertItemName(message.item)
  const token = asTrimmedString(message.token)
  if (!token) {
    throw new Error("API token is required")
  }

  const args = ["add", item, "--from-stdin"]
  pushOption(args, "--label", message.label)
  pushOption(args, "--service-url", message.serviceUrl)
  pushOption(args, "--account", message.accountName)
  pushOption(args, "--account-id", message.accountId)
  pushOption(args, "--notes", message.notes)

  const result = spawnSync(AGVT_BIN, args, {
    encoding: "utf8",
    input: token,
    env: {
      ...process.env
    }
  })

  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || "agvt failed").trim())
  }

  return {
    ok: true,
    message: `saved agvt://${item}/token`
  }
}

try {
  const message = await readNativeMessage()
  if (message?.type === "upsert-api-token") {
    writeNativeMessage(upsertApiToken(message))
  } else if (message?.type === "status") {
    writeNativeMessage({ ok: true, message: "agvt native host ready" })
  } else {
    writeNativeMessage({ ok: false, message: "unknown native message type" })
  }
} catch (error) {
  writeNativeMessage({
    ok: false,
    message: error instanceof Error ? error.message : String(error)
  })
}
