use std::env;

use crate::error::{AgvtError, Result};

const HELP_EN: &str = r#"agvt - Agent Vault CLI

Common flows:
  agvt keychain set
      Store the vault passphrase in macOS Keychain.

  agvt add cloudflare
      Save CLOUDFLARE_API_TOKEN and optional CLOUDFLARE_ACCOUNT_ID.

  agvt run cloudflare -- npx wrangler whoami
      Run a command with Cloudflare env vars injected.

  GITHUB_TOKEN=agvt://github/token agvt run -- gh auth status
      Resolve agvt:// refs already present in the environment.

  agvt read agvt://cloudflare/account-id
      Print one field from one item.

Commands:
  agvt add <item> [options]
      Save a secret. Default kind is api-token.
      Token input: --from-env ENV, --from-stdin, or a preset env var.
      Metadata: --label TEXT --service-url URL --account TEXT --account-id ID --notes TEXT.
      Other kinds: --kind totp|ssh-key|login|custom with --field NAME=VALUE,
      --field-env NAME=ENV, or --field-stdin NAME.

  agvt read <item-or-ref> [field]
      Read a field. Examples: cloudflare token, agvt://github/token,
      agvt://github-ssh/private-key.

  agvt run [preset] [--env ENV=ref] [safety options] -- <command> [args...]
      Inject selected secrets into a child process.
      Presets: cloudflare, github. Custom: --env TOKEN=agvt://item/token.
      Safety: --clean-env --redact-output --sandbox no-network.

  agvt inject [--redact-output] [template-file|-]
      Replace agvt:// refs in a template and print the result.
      Use --redact-output to preview without printing secret values.

  agvt totp <item-or-ref> [--digits 6|7|8] [--period SECONDS]
      Generate a TOTP code from a totp item.

  agvt cloudflare create-token <item> --name TEXT --policy-file FILE [options]
      Create a Cloudflare API token and save it without printing the token.
      Factory token: --factory-token-env ENV, --factory-token-ref ref,
      CLOUDFLARE_TOKEN_FACTORY_TOKEN, or CLOUDFLARE_API_TOKEN.

  agvt keychain set|status|delete
      Manage the macOS Keychain passphrase for this vault path.

  agvt ls [--json]
      List non-secret metadata only.

  agvt delete <item-or-ref>
      Delete an item.

  agvt presets [--json]
      Show built-in presets and injected fields.

Secret refs:
  agvt://dev/cloudflare/token
  agvt://cloudflare/token        # short form defaults to the dev vault
  agvt://github-ssh/private-key

Environment:
  AGVT_PASSPHRASE      Vault passphrase. Keychain is used if absent on macOS.
  AGVT_PATH            Vault file path. Default: .local/agent-vault.json
  AGVT_KEYCHAIN=0      Disable Keychain lookup.
  AGVT_LANG=ja|en      Choose help language.

Language:
  agvt help ja
  agvt help en
"#;

const HELP_JA: &str = r#"agvt - Agent Vault CLI

よく使う流れ:
  agvt keychain set
      macOS Keychain にVault passphraseを保存する

  agvt add cloudflare
      CLOUDFLARE_API_TOKEN と、任意で CLOUDFLARE_ACCOUNT_ID を保存する

  agvt run cloudflare -- npx wrangler whoami
      Cloudflare用の環境変数を注入してコマンドを実行する

  GITHUB_TOKEN=agvt://github/token agvt run -- gh auth status
      環境変数に入っている agvt:// 参照を実行時だけ解決する

  agvt read agvt://cloudflare/account-id
      1つのitemから1つのfieldだけ読む

コマンド一覧:
  agvt add <item> [options]
      secretを保存する。何も指定しない場合は api-token
      token入力: --from-env ENV、--from-stdin、またはpresetの環境変数
      metadata: --label TEXT --service-url URL --account TEXT --account-id ID --notes TEXT
      他のkind: --kind totp|ssh-key|login|custom と
      --field NAME=VALUE、--field-env NAME=ENV、--field-stdin NAME

  agvt read <item-or-ref> [field]
      fieldを読む。例: cloudflare token、agvt://github/token、
      agvt://github-ssh/private-key

  agvt run [preset] [--env ENV=ref] [safety options] -- <command> [args...]
      選んだsecretだけを子プロセスへ渡す
      preset: cloudflare, github。custom: --env TOKEN=agvt://item/token
      safety: --clean-env --redact-output --sandbox no-network

  agvt inject [--redact-output] [template-file|-]
      template内の agvt:// 参照を置換して出力する
      secret値を出さずに確認する場合は --redact-output を使う

  agvt totp <item-or-ref> [--digits 6|7|8] [--period SECONDS]
      totp itemから現在のTOTP codeを生成する

  agvt cloudflare create-token <item> --name TEXT --policy-file FILE [options]
      Cloudflare API tokenを作成して、token値を表示せずに保存する
      factory token: --factory-token-env ENV、--factory-token-ref ref、
      CLOUDFLARE_TOKEN_FACTORY_TOKEN、または CLOUDFLARE_API_TOKEN

  agvt keychain set|status|delete
      このvault path用のmacOS Keychain passphraseを管理する

  agvt ls [--json]
      secret値を出さずにmetadataだけ一覧する

  agvt delete <item-or-ref>
      itemを削除する

  agvt presets [--json]
      built-in presetと注入されるfieldを見る

secret reference:
  agvt://dev/cloudflare/token
  agvt://cloudflare/token        # 短縮形は dev vault 扱い
  agvt://github-ssh/private-key

環境変数:
  AGVT_PASSPHRASE      Vault passphrase。macOSでは未指定時にKeychainを見る
  AGVT_PATH            Vault file path。default: .local/agent-vault.json
  AGVT_KEYCHAIN=0      Keychain lookupを無効化
  AGVT_LANG=ja|en      help languageを選ぶ

言語切替:
  agvt help ja
  agvt help en
"#;

pub fn help_text(args: &[String]) -> Result<&'static str> {
    match requested_language(args)?.as_deref() {
        Some("ja") => Ok(HELP_JA),
        Some("en") => Ok(HELP_EN),
        Some(language) => Err(AgvtError::new(format!(
            "unsupported help language: {language}. Use ja or en."
        ))),
        None => Ok(match detected_language().as_deref() {
            Some("ja") => HELP_JA,
            _ => HELP_EN,
        }),
    }
}

fn requested_language(args: &[String]) -> Result<Option<String>> {
    let Some(first) = args.first() else {
        return Ok(None);
    };
    if first == "--lang" {
        return args
            .get(1)
            .map(|value| Ok(Some(normalize_language(value)?)))
            .unwrap_or_else(|| Err(AgvtError::new("--lang requires ja or en.")));
    }
    if let Some(value) = first.strip_prefix("--lang=") {
        return Ok(Some(normalize_language(value)?));
    }
    Ok(Some(normalize_language(first)?))
}

fn detected_language() -> Option<String> {
    env::var("AGVT_LANG")
        .ok()
        .and_then(|value| normalize_language(&value).ok())
        .or_else(|| {
            env::var("LANG")
                .ok()
                .and_then(|value| normalize_language(&value).ok())
        })
}

fn normalize_language(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.starts_with("ja") {
        return Ok("ja".to_owned());
    }
    if normalized.starts_with("en") || normalized == "c" || normalized == "posix" {
        return Ok("en".to_owned());
    }
    Err(AgvtError::new(format!(
        "unsupported help language: {value}. Use ja or en."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_explicit_languages() {
        assert!(help_text(&["ja".to_owned()])
            .unwrap()
            .contains("よく使う流れ"));
        assert!(help_text(&["en".to_owned()])
            .unwrap()
            .contains("Common flows"));
        assert!(help_text(&["--lang=ja".to_owned()])
            .unwrap()
            .contains("コマンド一覧"));
    }
}
