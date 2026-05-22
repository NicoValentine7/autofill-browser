import { normalizeText, type FieldDescriptor } from "@autofill-browser/autofill-core"

export type FieldSecurityClassification = "normal" | "secure-vault" | "secure-vault-confirm" | "blocked"

const BLOCKED_FIELD_TOKENS = [
  "captcha",
  "recaptcha",
  "h captcha",
  "g recaptcha",
  "apbct",
  "honeypot",
  "csrf",
  "xsrf",
  "token",
  "otp",
  "one time code",
  "one time password",
  "2fa",
  "mfa",
  "totp",
  "verification code",
  "authentication code",
  "auth code",
  "login code",
  "sms code",
  "passcode",
  "password",
  "passwd",
  "pwd",
  "login id",
  "login user id",
  "user id",
  "userid",
  "username",
  "user name",
  "iam username",
  "secret word",
  "secret answer",
  "security word",
  "security answer",
  "security question",
  "pin",
  "pincode",
  "pinnumber",
  "pin code",
  "pin number",
  "暗証番号",
  "確認コード",
  "認証コード",
  "ワンタイム",
  "ログインid",
  "ユーザーid",
  "合言葉",
  "秘密の質問"
]

const GENERIC_SECURITY_CODE_TOKENS = ["security code", "security number"]

const SECURE_VAULT_CONFIRM_FIELD_TOKENS = [
  "cvv",
  "cvv2",
  "cvc",
  "cvc2",
  "csc",
  "cc csc",
  "cid",
  "card security code",
  "card verification",
  "セキュリティコード",
  "カード確認コード"
]

const SECURE_VAULT_FIELD_TOKENS = [
  "card number",
  "cardnumber",
  "card no",
  "cardno",
  "credit card",
  "creditcard",
  "cc number",
  "cc-number",
  "ccnum",
  "cc num",
  "cc name",
  "cc-name",
  "cardholder",
  "card holder",
  "name on card",
  "expiry",
  "expiration",
  "expires",
  "exp date",
  "expdate",
  "cc exp",
  "cc-exp",
  "branch code",
  "branch number",
  "account number",
  "account no",
  "bank account",
  "カード番号",
  "カード名義",
  "名義人",
  "有効期限",
  "支店番号",
  "支店コード",
  "口座番号"
]

export const getDescriptorIdentity = (descriptor: FieldDescriptor) =>
  normalizeText(
    [
      descriptor.name,
      descriptor.id,
      descriptor.autocomplete,
      descriptor.placeholder,
      descriptor.ariaLabel,
      descriptor.labelText
    ].join(" ")
  )

export const hasIdentityToken = (identity: string, tokens: string[]) =>
  tokens.some((token) => {
    const normalizedToken = normalizeText(token)
    return normalizedToken.length > 0 && ` ${identity} `.includes(` ${normalizedToken} `)
  })

export const classifyFieldSecurity = (
  descriptor: FieldDescriptor,
  remoteBlockedTokens: string[] = []
): FieldSecurityClassification => {
  const identity = getDescriptorIdentity(descriptor)

  if (hasIdentityToken(identity, [...BLOCKED_FIELD_TOKENS, ...remoteBlockedTokens])) {
    return "blocked"
  }

  if (hasIdentityToken(identity, GENERIC_SECURITY_CODE_TOKENS) && !hasIdentityToken(identity, SECURE_VAULT_CONFIRM_FIELD_TOKENS)) {
    return "blocked"
  }

  if (hasIdentityToken(identity, SECURE_VAULT_CONFIRM_FIELD_TOKENS)) {
    return "blocked"
  }

  if (hasIdentityToken(identity, SECURE_VAULT_FIELD_TOKENS)) {
    return "secure-vault"
  }

  return "normal"
}

export const shouldRedactFieldEventValues = (classification: FieldSecurityClassification) =>
  classification !== "normal"

export const isSecureVaultField = (classification: FieldSecurityClassification) =>
  classification === "secure-vault" || classification === "secure-vault-confirm"

export const requiresSecureAutofillConfirmation = (classification: FieldSecurityClassification) =>
  classification === "secure-vault-confirm"
