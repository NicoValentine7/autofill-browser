import { cleanup } from "@testing-library/react"
import { webcrypto } from "node:crypto"
import { afterEach, beforeEach } from "vitest"

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  })
}

beforeEach(() => {
  document.body.innerHTML = ""
})

afterEach(() => {
  cleanup()
})
