# autofill-browser

Chrome拡張の自動入力機能と、Android向け自動入力専用ブラウザを同じリポジトリで育てるための初期土台です。

## ねらい

- Chrome拡張で、デスクトップ上のフォーム自動入力を早めに検証する
- Android側で、WebViewベースの専用ブラウザを薄く立ち上げる
- 将来的に、入力ルールや保存データの扱いを共有できる構成に寄せる

## 現在の構成

```text
.
├── apps
│   ├── android-browser
│   │   └── app
│   ├── chrome-extension
│   └── log-worker
├── packages
│   └── autofill-core
├── docs
│   └── product-outline.md
├── package.json
└── pnpm-workspace.yaml
```

## ディレクトリ説明

- `apps/chrome-extension`
  - Plasmoベースの最低限の拡張機能雛形
  - コンテンツスクリプトとポップアップUIを配置
- `apps/android-browser`
  - Kotlin + Android WebView の最低限のアプリ雛形
  - まだ AutofillService 連携までは入れていない
- `apps/log-worker`
  - Cloudflare Workers + D1 のログ保存API
  - Chrome拡張から送られたイベントログを `event_logs` に保存する
- `packages/autofill-core`
  - 自動入力ルールと判定ロジックの共有パッケージ
  - `src/autofill-rules.json` を Android 用 asset と同期して使う
- `docs/product-outline.md`
  - 解像度低めの要求整理と今後の叩き台

## 使い方

### Chrome拡張

```bash
cd apps/chrome-extension
pnpm install
pnpm dev
```

Plasmo のビルド出力は `build/chrome-mv3-dev/` または `build/chrome-mv3-prod/` に出ます。Chrome の拡張機能管理画面から「パッケージ化されていない拡張機能を読み込む」で対象ディレクトリを指定してください。

現在の Chrome 拡張は、`packages/autofill-core` のルールを読んで手動トリガーでフォーム入力を試す最小構成です。

popup の「クラウドログ」から Cloudflare Worker の `https://.../logs` と Bearer token を設定すると、ローカル履歴に加えてイベントログをCloudflare D1へPOSTできます。endpoint未設定時はローカル履歴だけに保存します。

#### 拡張IDを固定する

別PCでも同じ拡張IDで読み込みたい場合は、manifest `key` 用のローカル鍵を作ります。秘密鍵と `.env.local` は git 管理しません。

```bash
pnpm setup:extension-key
pnpm build:extension
```

このコマンドは `apps/chrome-extension/.extension-key/` に秘密鍵を作り、`apps/chrome-extension/.env.local` に公開鍵だけを書きます。別PCで同じ拡張IDにする場合は、秘密鍵ファイルを安全な方法でコピーしてから `pnpm setup:extension-key` を実行してください。

### CloudflareログAPI

Cloudflare側は `apps/log-worker` にあります。D1 databaseを作り、`apps/log-worker/wrangler.jsonc` の `database_id` を差し替えてからmigrationとsecret設定を行ってください。

```bash
npx wrangler d1 create autofill-browser-logs
pnpm --dir apps/log-worker migrate:remote
npx wrangler secret put CLOUD_LOG_INGEST_TOKEN --config apps/log-worker/wrangler.jsonc
pnpm deploy:log-worker
```

localで試す場合は `apps/log-worker/.dev.vars` に `CLOUD_LOG_INGEST_TOKEN=local-dev-token` を置き、以下を実行します。

```bash
pnpm --dir apps/log-worker migrate:local
pnpm dev:log-worker
```

ログ受け口は `POST /logs`、最近のログ確認は `GET /logs?limit=50` です。どちらも `Authorization: Bearer <token>` が必要です。

### テストサイト

```bash
pnpm serve:test-site
```

そのあと [http://localhost:4173](http://localhost:4173) を開くと、以下をまとめて試せます。

- 日本語の基本プロフィールフォーム
- 姓 / 名 / 市町村 / 住所欄1 / 住所欄2 が分離された checkout
- 英語ラベルの checkout と `street-address`
- 分割郵便番号 / 分割電話番号
- placeholder や `aria-label` しか無い legacy フォーム
- username / nickname / cardholder name みたいな誤爆トラップ
- MutationObserver 向けの遅延表示フォーム

### Androidブラウザ

Android Studio で `apps/android-browser` を開いてください。

このマシンでは Java / Gradle がまだ入っていないため、CLIビルド検証は未実施です。

共有ルールを Android asset に反映する場合は以下を実行してください。

```bash
pnpm sync:android-rules
```

## 次にやると良さそうなこと

1. Android 側で共有ルール JSON を読み込む repository を追加する
2. Android 側の対象を「一般ブラウザ」ではなく「自動入力専用フロー」に絞って画面遷移を定義する
3. Chrome拡張のフォーム検出ロジックを段階的に増やす
