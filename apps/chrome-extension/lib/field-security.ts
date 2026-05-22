import { normalizeText, type FieldDescriptor } from "@autofill-browser/autofill-core"

export type FieldSecurityClassification = "normal" | "sensitive-fillable" | "blocked"

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
  "2fa",
  "mfa",
  "verification code",
  "passcode",
  "password",
  "passwd",
  "pwd",
  "username",
  "user name",
  "iam username",
  "secret word",
  "secret answer",
  "security word",
  "security answer",
  "security question",
  "cvv",
  "cvv2",
  "cvc",
  "cvc2",
  "csc",
  "cc csc",
  "cid",
  "card security code",
  "card verification",
  "security code",
  "security number",
  "pin",
  "pincode",
  "pinnumber",
  "pin code",
  "pin number",
  "セキュリティコード",
  "カード確認コード",
  "暗証番号",
  "合言葉",
  "秘密の質問"
]

const SENSITIVE_FILLABLE_FIELD_TOKENS = [
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
  "login user id",
  "user id",
  "userid",
  "customer id",
  "カード番号",
  "カード名義",
  "名義人",
  "有効期限",
  "支店番号",
  "支店コード",
  "口座番号",
  "ログインid",
  "ユーザーid"
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

  if (hasIdentityToken(identity, SENSITIVE_FILLABLE_FIELD_TOKENS)) {
    return "sensitive-fillable"
  }

  return "normal"
}

export const shouldRedactFieldEventValues = (classification: FieldSecurityClassification) =>
  classification !== "normal"
