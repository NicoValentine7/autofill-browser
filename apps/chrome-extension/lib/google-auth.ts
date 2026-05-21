import type { GoogleAuthUser } from "./storage"

const GOOGLE_AUTH_SCOPES = ["openid", "email", "profile"]

export const getGoogleAccessToken = async (interactive = false) => {
  try {
    const result = await chrome.identity.getAuthToken({
      interactive,
      scopes: GOOGLE_AUTH_SCOPES
    })

    if (typeof result === "string") {
      return result
    }

    return result.token ?? null
  } catch (_error) {
    return null
  }
}

export const clearGoogleAuthTokens = async () => {
  try {
    await chrome.identity.clearAllCachedAuthTokens()
  } catch (_error) {
    // Older Chrome builds can fail here; local sign-out still clears our stored user.
  }
}

export const normalizeGoogleAuthUser = (user: Partial<GoogleAuthUser>): GoogleAuthUser | null => {
  const sub = user.sub?.trim()
  const email = user.email?.trim()

  if (!sub || !email) {
    return null
  }

  return {
    sub,
    email,
    name: user.name?.trim() || undefined,
    picture: user.picture?.trim() || undefined,
    signedInAt: user.signedInAt?.trim() || new Date().toISOString()
  }
}
