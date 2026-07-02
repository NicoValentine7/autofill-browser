use std::env;

use crate::error::{AgvtError, Result};

const HELP_EN: &str = r#"agvt - Agent Vault CLI

Common flows:
  agvt keychain set
      Store the vault passphrase in macOS Keychain.

  agvt add cloudflare
      Save CLOUDFLARE_API_TOKEN and optional CLOUDFLARE_ACCOUNT_ID.

  agvt add openai
      Save OPENAI_API_KEY for later command injection.

  agvt import-env --dry-run
      Preview importable preset and secret-like env vars without printing values.

  agvt prepare --dry-run
      Diagnose required repo secrets without saving, creating, or printing values.

  agvt run cloudflare -- npx wrangler whoami
      Run a command with Cloudflare env vars injected.

  GITHUB_TOKEN=agvt://global/github/token agvt run -- gh auth status
      Resolve agvt:// refs already present in the environment.

  agvt read agvt://global/cloudflare/account-id
      Print one field from one item.

Commands:
  agvt add <item-or-ref> [options]
      Save a secret. Default kind is api-token.
      Vault scope comes from the reference: `agvt add agvt://global/<item>/token`
      saves under the global vault tag. A bare item name saves under the
      default vault tag (dev) and is read back as agvt://dev/<item>/<field>.
      Token input: --from-env ENV, --from-stdin, or a preset env var.
      Metadata: --label TEXT --service-url URL --account TEXT --account-id ID --notes TEXT.
      Other kinds: --kind totp|ssh-key|login|file|custom with --field NAME=VALUE,
      --field-env NAME=ENV, or --field-stdin NAME.
      Key files (.p8/.p12 etc): --from-file PATH stores the file base64-encoded
      in the `content` field (kind file is implied) and records `filename`.
      Read it back with `agvt read <ref-to-content> --decode`.

  agvt read <item-or-ref> [field] [--decode]
      Read a field. Examples: cloudflare token, agvt://global/github/token,
      agvt://repo/github-ssh/private-key.
      --decode base64-decodes the value and writes raw bytes, for file items.

  agvt run [preset] [--env ENV=ref] [safety options] -- <command> [args...]
      Inject selected secrets into a child process.
      Presets: cloudflare, openai, anthropic, vercel, stripe, slack, github.
      Custom: --env TOKEN=agvt://global/item/token.
      Safety: --clean-env --redact-output --sandbox no-network.

  agvt inject [--redact-output] [template-file|-]
      Replace agvt:// refs in a template and print the result.
      Use --redact-output to preview without printing secret values.

  agvt import-env [preset...] [--dry-run] [--env-file FILE] [--preset-only] [--json]
      Import matching env vars into the vault without printing values.
      By default, reads the current process environment plus local .env.local,
      .env.development, .env.production, and .env when present.
      Built-in presets use their provider item names; other secret-like names
      such as *_TOKEN, *_API_KEY, *_SECRET, *_SECRET_KEY,
      *_SERVICE_ROLE_KEY, *_PASSWORD, and DATABASE_URL are imported as custom
      api-token items unless --preset-only is set.

  agvt prepare [preset...] [--dry-run] [--manifest FILE] [--env-file FILE] [--json]
      Diagnose repo secret readiness without mutating the vault.
      Reads agvt.toml when present, otherwise detects known repo/provider hints.
      Output lists present, importable, missing, or unchecked fields only.

  agvt totp <item-or-ref> [--digits 6|7|8] [--period SECONDS]
      Generate a TOTP code from a totp item.

  agvt cloudflare create-token <item> --name TEXT --policy-file FILE [options]
      Create a Cloudflare API token and save it without printing the token.
      Automatic token creation is Cloudflare-only; other presets store existing tokens.
      Factory token: --factory-token-env ENV, --factory-token-ref ref,
      CLOUDFLARE_TOKEN_FACTORY_TOKEN, or CLOUDFLARE_API_TOKEN.

  agvt keychain set|status|delete
      Manage the macOS Keychain passphrase for this vault path.

  agvt ls [--json]
      List non-secret metadata only.

  agvt delete <item-or-ref>
      Delete an item. Use a full reference such as agvt://global/<item>/token
      to target a non-default vault tag; a bare name targets the dev tag.

  agvt presets [--json]
      Show built-in presets and injected fields.

Secret refs:
  agvt://global/cloudflare/token
  agvt://repo/cloudflare/token
  agvt://repo/github-ssh/private-key
  Short refs such as agvt://cloudflare/token are disabled.

Environment:
  AGVT_PASSPHRASE      Vault passphrase. Keychain is used if absent on macOS.
  AGVT_PATH            Repo-local vault path. Default: .local/agent-vault.json
  AGVT_GLOBAL_PATH     Global vault path. Default: ~/.local/share/agvt/agent-vault.json
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

  agvt add openai
      OPENAI_API_KEY を保存して、あとでコマンドに注入できるようにする

  agvt import-env --dry-run
      importできるpreset/env名だけを見る。secret値は表示しない

  agvt prepare --dry-run
      repoに必要なsecretを、保存・発行・値表示なしで診断する

  agvt run cloudflare -- npx wrangler whoami
      Cloudflare用の環境変数を注入してコマンドを実行する

  GITHUB_TOKEN=agvt://global/github/token agvt run -- gh auth status
      環境変数に入っている agvt:// 参照を実行時だけ解決する

  agvt read agvt://global/cloudflare/account-id
      1つのitemから1つのfieldだけ読む

コマンド一覧:
  agvt add <item-or-ref> [options]
      secretを保存する。何も指定しない場合は api-token
      vault scopeは参照で指定する: `agvt add agvt://global/<item>/token` は
      global vault tagに保存する。item名だけならdefault vault tag（dev）に
      保存され、agvt://dev/<item>/<field> で読む
      token入力: --from-env ENV、--from-stdin、またはpresetの環境変数
      metadata: --label TEXT --service-url URL --account TEXT --account-id ID --notes TEXT
      他のkind: --kind totp|ssh-key|login|file|custom と
      --field NAME=VALUE、--field-env NAME=ENV、--field-stdin NAME
      鍵ファイル（.p8/.p12等）: --from-file PATH でbase64化して `content`
      fieldに保存する（kind fileが自動で選ばれ、`filename` も記録する）
      読み出しは `agvt read <contentへのref> --decode`

  agvt read <item-or-ref> [field] [--decode]
      fieldを読む。例: cloudflare token、agvt://global/github/token、
      agvt://repo/github-ssh/private-key
      --decode はbase64をdecodeして生bytesを出力する（file item用）

  agvt run [preset] [--env ENV=ref] [safety options] -- <command> [args...]
      選んだsecretだけを子プロセスへ渡す
      preset: cloudflare, openai, anthropic, vercel, stripe, slack, github
      custom: --env TOKEN=agvt://global/item/token
      safety: --clean-env --redact-output --sandbox no-network

  agvt inject [--redact-output] [template-file|-]
      template内の agvt:// 参照を置換して出力する
      secret値を出さずに確認する場合は --redact-output を使う

  agvt import-env [preset...] [--dry-run] [--env-file FILE] [--preset-only] [--json]
      env varをVaultへ取り込む。secret値は表示しない
      defaultでは現在の環境変数に加えて、存在する .env.local、
      .env.development、.env.production、.env を読む
      built-in presetはprovider item名で保存する。それ以外の *_TOKEN、
      *_API_KEY、*_SECRET、*_SECRET_KEY、*_SERVICE_ROLE_KEY、*_PASSWORD、
      DATABASE_URL はcustom api-tokenとして保存する
      custom importを避ける場合は --preset-only を使う

  agvt prepare [preset...] [--dry-run] [--manifest FILE] [--env-file FILE] [--json]
      Vaultを書き換えずにrepoのsecret readinessを診断する
      agvt.toml があれば読み、なければ既知のrepo/provider hintを見る
      出力は present、importable、missing、unchecked のfield名だけ

  agvt totp <item-or-ref> [--digits 6|7|8] [--period SECONDS]
      totp itemから現在のTOTP codeを生成する

  agvt cloudflare create-token <item> --name TEXT --policy-file FILE [options]
      Cloudflare API tokenを作成して、token値を表示せずに保存する
      token自動発行はCloudflare専用。他presetは既存tokenの保存・注入のみ
      factory token: --factory-token-env ENV、--factory-token-ref ref、
      CLOUDFLARE_TOKEN_FACTORY_TOKEN、または CLOUDFLARE_API_TOKEN

  agvt keychain set|status|delete
      このvault path用のmacOS Keychain passphraseを管理する

  agvt ls [--json]
      secret値を出さずにmetadataだけ一覧する

  agvt delete <item-or-ref>
      itemを削除する。default以外のvault tagは agvt://global/<item>/token の
      ようなフル参照で指定する。item名だけならdev tagを対象にする

  agvt presets [--json]
      built-in presetと注入されるfieldを見る

secret reference:
  agvt://global/cloudflare/token
  agvt://repo/cloudflare/token
  agvt://repo/github-ssh/private-key
  agvt://cloudflare/token のような短縮形は無効

環境変数:
  AGVT_PASSPHRASE      Vault passphrase。macOSでは未指定時にKeychainを見る
  AGVT_PATH            repo-local Vault path。default: .local/agent-vault.json
  AGVT_GLOBAL_PATH     global Vault path。default: ~/.local/share/agvt/agent-vault.json
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
