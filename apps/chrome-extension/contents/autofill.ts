import type { PlasmoCSConfig } from "plasmo"

import { createAutofillController } from "../lib/content-controller"

export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"]
}

const controller = createAutofillController()

void controller.initialize()
