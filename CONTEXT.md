# Autofill Browser

Autofill Browser is the domain of saving, synchronizing, and applying user-owned form data across browser surfaces. This language separates reusable secrets from one-time challenges so sensitive inputs can be discussed without ambiguity.

## Language

**Secure Vault**:
The user's protected collection of reusable sensitive autofill values. It may contain many **Vault Entries**, each tied to a form field identity and owned by one **System Account**.
_Avoid_: field memory, log storage, plain sync

**Vault Key**:
The cryptographic key material used to protect one **System Account**'s **Secure Vault**. A **Vault Key** belongs to exactly one **System Account** and must not be shared across **System Accounts** on the same device.
_Avoid_: device key, global vault key, extension key

**Zero-Knowledge Vault**:
A **Secure Vault** arrangement where the service stores synchronized vault data but cannot decrypt **Vault Entry** values because it never receives the **Vault Key**. The service may authenticate the user and move encrypted vault data, but it is not trusted with reusable sensitive values.
_Avoid_: server-encrypted vault, cloud-readable vault, trusted-server vault

**Recovery Phrase**:
A high-entropy client-generated phrase used only on the client to wrap or unwrap a **Vault Key**. A **Recovery Phrase** must not be sent to the service, stored in D1, or written to logs.
_Avoid_: cloud password, bearer token, Google password

**Vault Recovery Package**:
An encrypted package stored with the sync snapshot that contains a **Vault Key** wrapped by a **Recovery Phrase**. The service may store and move this package, but cannot unwrap it without the user's **Recovery Phrase**.
_Avoid_: synced vault key, server recovery key, backup password

**System Account**:
The account inside Autofill Browser that owns profiles, domain policies, logs, sync snapshots, and the **Secure Vault**. A **System Account** may have many linked identity providers, including many **Linked Google Accounts**, and is established when the first identity is attached.
_Avoid_: Google account, Chrome profile, browser profile

**Linked Google Account**:
A Google account connected to exactly one **System Account** for sign-in or account recovery. It is one of potentially many identity links on that **System Account**, not the owner of the user's Autofill Browser data.
_Avoid_: system account, vault owner, sync account

**Identity Migration**:
An explicit recovery or transfer process that moves a **Linked Google Account** from one **System Account** to another. It is never triggered implicitly by normal sign-in.
_Avoid_: automatic relink, silent account switch

**Local Vault Transfer**:
An explicit process that attaches unsynced vault data on a device to a different **System Account**. Normal sign-in never transfers or merges local vault data into another **System Account** implicitly.
_Avoid_: automatic vault merge, silent local import

**Card Security Code**:
A reusable payment-card verification value such as CVC, CVV, CID, or card security code. It belongs in the **Secure Vault**, but it is more sensitive than ordinary card details and requires an explicit user action before filling.
_Avoid_: confirmation code, verification code, OTP

**TOTP Secret**:
A reusable authenticator setup secret, usually obtained from a QR code or manual setup key, that can generate short-lived authentication codes. It belongs in the **Secure Vault**; the generated code is not itself the stored secret.
_Avoid_: one-time code, SMS code, email code

**API Token**:
A reusable bearer token, API key, or provider access token that a user explicitly saves as a copy-only **Vault Entry**. It belongs in the **Secure Vault** only when the user manually creates it; token-looking form fields are not learned or autofilled automatically.
_Avoid_: CSRF token, one-time token, OAuth access token captured from a page

**Secret Note**:
A copy-only **Vault Entry** for arbitrary sensitive text that does not have a safer specialized type yet, such as recovery instructions or short private setup notes. It should be manually created, encrypted as a vault value, and never inferred from page fields.
_Avoid_: field memory, clipboard history, raw note sync

**One-Time Verification Code**:
A short-lived code sent or shown for a single challenge, such as an SMS code, email code, or bank challenge code. It is not reusable and should not be learned as a **Vault Entry**.
_Avoid_: TOTP secret, card security code, saved code

## Flagged Ambiguities

**"Confirmation Code"**:
This phrase is ambiguous and should not be used as a canonical term. Use **Card Security Code**, **TOTP Secret**, or **One-Time Verification Code** depending on whether the value is a payment-card verifier, a reusable authenticator seed, or a single-use challenge response.

**"Account"**:
This phrase is ambiguous and should not be used alone. Use **System Account** for the Autofill Browser account that owns data, or **Linked Google Account** for the external Google identity connected to it.

**"Switch Account"**:
This phrase is ambiguous and should not be used alone. Use **Identity Migration** when moving a linked identity between **System Accounts**, or use "sign in with a different Linked Google Account" when selecting another identity that is already linked to the same **System Account**.

**"Local Data"**:
This phrase is ambiguous around sensitive values. Use **Local Vault Transfer** when discussing unsynced **Secure Vault** data that might be moved between **System Accounts**.

**"Vault Backup"**:
This phrase is ambiguous because it can imply the cloud can read or restore the vault by itself. Use **Vault Recovery Package** when the cloud stores only an encrypted wrapper, and **Recovery Phrase** when referring to the user-held secret needed to unwrap it.

**"Token"**:
This phrase is ambiguous and should not be used alone. Use **API Token** for an explicitly saved reusable provider credential, **TOTP Secret** for an authenticator setup seed, or **One-Time Verification Code** for a challenge response. Anti-CSRF and page-generated tokens must not become **Vault Entries**.

## Example Dialogue

Dev: "Should we save this confirmation code?"

Domain expert: "Which one? If it is a card CVC, it is a Card Security Code and belongs in Secure Vault with explicit fill. If it is an authenticator setup key, it is a TOTP Secret. If it came by SMS or email for this login, it is a One-Time Verification Code and must not become a Vault Entry."

Dev: "Does the Google account own the Secure Vault?"

Domain expert: "No. The System Account owns the Secure Vault. The Linked Google Account is only a way to sign in to that System Account."

Dev: "Can the same Google account point to two System Accounts?"

Domain expert: "No. A Linked Google Account points to exactly one System Account unless the user performs an explicit Identity Migration."

Dev: "If a device has unsynced card details, should they follow the next login?"

Domain expert: "No. A new sign-in loads the target System Account's Secure Vault. Moving unsynced vault data requires an explicit Local Vault Transfer."

Dev: "Can two System Accounts on the same device use the same Vault Key?"

Domain expert: "No. Each System Account has its own Vault Key because each System Account owns a separate Secure Vault."

Dev: "Can the cloud restore my Secure Vault by itself?"

Domain expert: "No. The cloud can return the Vault Recovery Package, but the user must enter the Recovery Phrase locally to recover the Vault Key."

Dev: "Should we learn this `api_token` field?"

Domain expert: "No. Token-looking form fields stay blocked. If the user wants to keep a reusable API Token, they create a copy-only Secure Vault item explicitly."
