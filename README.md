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

Chrome拡張は標準でこのリポジトリの Cloudflare Worker に接続するため、保存先URLの入力は不要です。Googleログインすると、ローカル履歴に加えてイベントログと設定snapshotをCloudflare D1へ保存できます。

#### 拡張IDを固定する

manifest `key` の公開鍵は `apps/chrome-extension/package.json` に入れてあるため、別PCでも clone して build するだけで同じ拡張IDになります。秘密鍵のコピーは不要です。

```bash
pnpm build:extension
```

固定IDを確認したい場合は以下を実行してください。

```bash
pnpm setup:extension-key
```

`pnpm setup:extension-key` は、公開鍵が既に repo にある場合は固定IDを表示するだけです。CRX署名用の秘密鍵を作り直したい場合だけ `pnpm setup:extension-key -- --rotate` を使ってください。秘密鍵は `apps/chrome-extension/.extension-key/` に置かれ、git 管理しません。

#### 別PCに入れる

別PCでは秘密鍵や `.env.local` を同期しなくて大丈夫です。repo に固定ID用の公開 manifest key が入っているため、clone して build するだけで同じ拡張IDになります。

```bash
git clone https://github.com/NicoValentine7/autofill-browser.git
cd autofill-browser
pnpm install
pnpm build:extension
```

Chrome の拡張機能管理画面で「デベロッパーモード」をONにし、「パッケージ化されていない拡張機能を読み込む」から `apps/chrome-extension/build/chrome-mv3-prod/` を選んでください。

固定される拡張IDは `cjdfbkbfiengbkpejnjecgdgagipjkdk` です。標準のCloudflare Worker URLは拡張側に入っているため、別PCで最初に必要なのは基本的にGoogleログインだけです。ログイン後に「クラウドから復元」を押すと、プロフィール、自動入力設定、ドメイン制御を復元できます。

#### Googleログインと設定同期

Googleログインを使うと、プロフィール、自動入力設定、ドメイン制御をGoogleアカウント単位でCloudflare D1へ保存できます。v1では同期データはD1に平文保存します。Worker URLは拡張側の標準値を使います。

Google OAuth client は Google Cloud Console で1回作成します。Application type は `Chrome extension`、Item ID は固定拡張IDの `cjdfbkbfiengbkpejnjecgdgagipjkdk` を指定してください。

client ID を作成したら、repo内のmanifestとWorker設定へ反映します。

```bash
pnpm set:google-oauth-client <client-id.apps.googleusercontent.com>
```

その後、拡張とWorkerをbuild/deployします。

```bash
pnpm build:extension
pnpm --dir apps/log-worker migrate:remote
pnpm deploy:log-worker
```

標準のWorker URLは `apps/chrome-extension/lib/storage.ts` に入っています。Googleログイン時は、同じWorkerから `/auth/me` と `/sync/settings` も使います。Googleログイン済みのログ送信はGoogle tokenで認証します。

### CloudflareログAPI

Cloudflare側は `apps/log-worker` にあります。D1 databaseを作り、`apps/log-worker/wrangler.jsonc` の `database_id` と `GOOGLE_OAUTH_CLIENT_ID` を差し替えてからmigrationとsecret設定を行ってください。

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

ログ受け口は `POST /logs`、最近のログ確認は `GET /logs?limit=50` です。設定同期は `GET /sync/settings` と `PUT /sync/settings`、ログイン確認は `GET /auth/me` です。いずれも `Authorization` ヘッダーが必要で、値には共有トークンまたはGoogle access tokenを使います。

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
