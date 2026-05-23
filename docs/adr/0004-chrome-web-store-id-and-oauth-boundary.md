# Chrome Web Store ID and OAuth boundary

Status: Accepted

## Context

Autofill Browser uses a fixed `manifest.key` for unpacked local builds so the extension ID stays stable across machines. The Chrome Web Store package upload rejects `manifest.key`, and the store-created draft has its own item ID. Chrome Extension OAuth clients are bound to an extension item ID, so the unpacked fixed-ID build and the Chrome Web Store build cannot reliably share one OAuth client.

Current IDs:

- Unpacked fixed-ID build: `cjdfbkbfiengbkpejnjecgdgagipjkdk`
- Chrome Web Store draft: `baanlacmimdcafhjondbnjnigjglmcph`

## Decision

Keep the source manifest optimized for unpacked local builds, including the fixed `manifest.key` and the local fixed-ID OAuth client. Generate a separate Chrome Web Store zip for dashboard upload that removes `manifest.key` and can patch `oauth2.client_id` to the Web Store OAuth client.

The Worker accepts a comma-separated `GOOGLE_OAUTH_CLIENT_IDS` list in addition to the legacy `GOOGLE_OAUTH_CLIENT_ID` value so both the unpacked fixed-ID build and the Chrome Web Store build can authenticate against the same backend.

## Why

This preserves the low-friction developer and second-PC install workflow while allowing Web Store distribution to follow Chrome Web Store package rules. It also avoids forcing a breaking OAuth migration for already-loaded local fixed-ID installs.

## Consequences

Release packaging must use `pnpm package:webstore` for Web Store uploads. If the Web Store OAuth client changes, the Web Store zip must be regenerated with that client ID and the Worker must be deployed with both allowed OAuth client IDs.

## Verification Expectations

- The uploaded Web Store zip must not contain `manifest.key`.
- The Web Store zip manifest must contain the OAuth client created for `baanlacmimdcafhjondbnjnigjglmcph`.
- Worker Google token verification must pass for either the local fixed-ID client ID or the Web Store client ID and reject unknown client IDs.
