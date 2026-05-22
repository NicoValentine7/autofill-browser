# Secure Vault uses zero-knowledge value storage

Autofill Browser treats the Secure Vault as zero-knowledge for Vault Entry values: clients may sync encrypted vault data through the Worker, but the Vault Key is not sent to or returned from the Worker. This keeps Cloudflare useful for authentication and synchronization while avoiding a trusted-server model for reusable sensitive values such as card details, bank details, and TOTP Secrets.
