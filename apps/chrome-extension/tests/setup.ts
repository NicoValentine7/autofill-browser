import { cleanup } from "@testing-library/react"
import { afterEach, beforeEach } from "vitest"

beforeEach(() => {
  document.body.innerHTML = ""
})

afterEach(() => {
  cleanup()
})
