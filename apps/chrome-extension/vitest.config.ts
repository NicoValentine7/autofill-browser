import { resolve } from "node:path"

import { defineConfig } from "vitest/config"

export default defineConfig({
  resolve: {
    alias: {
      "@autofill-browser/autofill-core": resolve(__dirname, "../../packages/autofill-core/src/index.ts"),
      "~lib": resolve(__dirname, "./lib")
    }
  },
  test: {
    environment: "jsdom",
    environmentOptions: {
      jsdom: {
        url: "https://example.com/"
      }
    },
    setupFiles: ["./tests/setup.ts"]
  }
})
