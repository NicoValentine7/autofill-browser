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
  - Cloudflare Workers + D1 のログ保存・Google同期API
  - Chrome拡張から送られたイベントログ、設定snapshot、Remote rules、日次解析レポートを保存する
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

Chrome拡張は標準でこのリポジトリの Cloudflare Worker に接続するため、保存先URLの入力は不要です。Googleログインすると、Cloudflare D1を正本としてプロフィール、自動入力設定、ドメイン制御、イベントログ、Remote rulesを自動同期します。Chromeのローカルstorageはオフライン用キャッシュです。

#### 開発中の読み込み運用

普段の開発中は `pnpm dev:extension` を常駐させ、Chrome では一度だけ `apps/chrome-extension/build/chrome-mv3-dev/` を読み込んでください。Plasmo dev が変更を監視して dev build を再生成するため、毎回 `chrome://extensions` を開いてリロード操作する必要は基本ありません。

```bash
pnpm dev:extension
```

本番相当の最終確認や別PC配布前だけ、`pnpm build:extension` を実行して `apps/chrome-extension/build/chrome-mv3-prod/` を使います。開発中の操作奪われ対策としては、dev版を読みっぱなしにするのが標準運用です。

#### 機密フィールドの扱い

自動入力は、通常プロフィール、学習済み任意フィールド、銀行/カード系フィールドを同じ候補収集層で扱います。ただし、機密度で保存・ログ出力の扱いを分けます。

- 支店番号、口座番号、カード番号、有効期限、カード名義は Secure Vault に学習し、popupからの手動実行時に入力できます
- CVC/CVV/CID/セキュリティコードは将来利用のために保存せず、学習も自動入力もしません
- 銀行/カード系の `field_learned_from_user` / `field_filled` / `field_corrected_by_user` イベントは、`previousValue` / `nextValue` を保存せず `values:redacted` だけ残します
- API tokenは、ユーザーがpopupで明示作成したcopy-onlyのSecure Vault itemとして保存・更新・コピー・削除できます。token本体、サービスURL、アカウント、メモは暗号化値として保存し、`token` っぽいフォームフィールドからの自動学習・自動入力はしません
- PIN、パスワード、OTP、captcha、CSRF token、合言葉/秘密の質問系は学習も自動入力もしません
- Secure Vault は通常の `fieldMemory` と分離し、ローカルでは AES-GCM で暗号化して保存します。Google同期では暗号化済みのVault dataだけをD1へ保存し、Vault KeyはWorkerにもD1にも送信しません。Vault Keyは `chrome.storage.session` にだけ保持し、過去版の `chrome.storage.local` に残ったキーは起動時にsessionへ移してlocal側を空にします
- API tokenのコピーはpopupの明示操作だけで実行し、manifestでは `clipboardWrite` を要求します。clipboardからの読み取りはしません
- 別PCでは、Googleログイン後にSecure Vaultの回復フレーズを入力すると、D1上のVault Recovery PackageからVault Keyをこの端末へ復元できます。回復フレーズは拡張側で高エントロピー生成し、PBKDF2-SHA256 600k iterations + AES-GCM AADでVault Keyを包み、保存・送信しません
- Secure Vaultには `vaultId`, `activeKeyId`, encrypted key-check canary を持たせ、復元時はVault Recovery Packageの `vaultId` とcanary検証に通ったVault Keyだけを端末sessionへ保存します

#### 拡張IDを固定する

manifest `key` の公開鍵は `apps/chrome-extension/package.json` に入れてあるため、別PCでも clone して build するだけで同じ拡張IDになります。これは「unpackedで読み込むローカル版」のための固定IDです。秘密鍵のコピーは不要です。

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

固定される拡張IDは `cjdfbkbfiengbkpejnjecgdgagipjkdk` です。標準のCloudflare Worker URLは拡張側に入っているため、別PCで最初に必要なのは基本的にGoogleログインだけです。ログインすると、Cloudflare D1の最新snapshotが自動で反映されます。Secure Vaultの値を復号するには、popupで生成・保存した回復フレーズを入力してVault Keyを復元してください。

#### Chrome Web Store に出す

Chrome Web Store にアップロードするzipには manifest `key` を含められません。Web Store版はStore側で別のIDが割り当てられるため、unpacked固定ID版とは別のGoogle OAuth clientを使います。

- unpacked固定ID: `cjdfbkbfiengbkpejnjecgdgagipjkdk`
- Chrome Web Store draft ID: `baanlacmimdcafhjondbnjnigjglmcph`

Web Store用の素材とzipは以下で作ります。

```bash
pnpm assets:webstore
pnpm build:extension
pnpm package:extension
WEBSTORE_GOOGLE_OAUTH_CLIENT_ID=<web-store-client-id.apps.googleusercontent.com> pnpm package:webstore
```

生成される `dist/releases/autofill-browser-chrome-v<version>-webstore.zip` をDeveloper Dashboardへアップロードしてください。`pnpm package:webstore` はzip内の `manifest.key` を削除し、`WEBSTORE_GOOGLE_OAUTH_CLIENT_ID` が指定されていればzip内の `oauth2.client_id` だけWeb Store用client IDへ差し替えます。ソース側のmanifestはunpacked固定ID版のまま維持します。

Developer Dashboard のプライバシーポリシーURLには、Workerが公開する `https://autofill-browser-log-worker.y-elucidator.workers.dev/privacy` を指定します。このページは認証なしで表示でき、拡張の同期・ログ・Secure Vaultの扱いをWeb Store審査向けに説明します。

#### Googleログインと設定同期

Googleログインを使うと、初回ログイン時にAutofill Browser側のSystem Accountを作成し、そのGoogleアカウントをLinked Google Accountとして紐づけます。プロフィール、自動入力設定、ドメイン制御はSystem Account単位でCloudflare D1へ保存します。Googleアカウントはログイン手段であり、データの所有者はSystem Accountです。

プロフィールとログの入力値はWorker secretの `CLOUD_DATA_ENCRYPTION_KEY` でAES-GCM暗号化してD1へ保存します。Secure VaultはZero-Knowledge Vaultとして扱い、クライアントで暗号化済みのVault dataだけを同期します。Vault Keyは端末の `chrome.storage.session` にだけ保持し、同期snapshotやWorker保存データには含めません。Secure Vault rootには `vaultId`, `activeKeyId`, encrypted key-check canary を持たせ、別Vaultや別KeyのRecovery Packageを誤って復元しないようにします。Workerは inbound payload に `secureVaultKey` が残っている場合は `400` で拒否します。Worker URLや共有トークンはユーザー設定に含めません。

別PCではGoogleログインでプロフィールや設定を復元できます。Secure Vaultの値は暗号化済みdataとして同期され、Vault Keyは拡張側で生成した回復フレーズで包まれたVault Recovery Packageとして同期されます。別PCのpopupで回復フレーズを入力すると、その端末のsession storageへVault Keyを復元します。

旧実装で万一 `secureVaultKey` を含む同期rowが残っている場合は、admin token付きで `POST /admin/sync-vault-scrub` を実行すると、current/history rowのlegacy keyを再暗号化または削除してscrubできます。

同期snapshotには `deviceId`, `baseRevision`, `changedFields` が含まれます。別PCで同時編集が起きた場合、変更フィールドが被らなければWorker側で差分マージし、同じフィールドが競合した場合はクラウド側snapshotを返して拡張側が反映します。

Google OAuth client は Google Cloud Console で作成します。Application type は `Chrome extension` です。Item ID は、対象に応じて以下を指定します。

- unpacked固定ID版: `cjdfbkbfiengbkpejnjecgdgagipjkdk`
- Chrome Web Store版: `baanlacmimdcafhjondbnjnigjglmcph`

unpacked固定ID版のclient IDを作成したら、repo内のmanifestとWorker設定へ反映します。

```bash
pnpm set:google-oauth-client <client-id.apps.googleusercontent.com>
```

Web Store版のclient IDを作成したら、Workerの許可リストへ追加します。ソースmanifestは更新せず、Web Store zip作成時にだけclient IDを差し替えます。

```bash
pnpm set:google-oauth-client <web-store-client-id.apps.googleusercontent.com> --webstore
WEBSTORE_GOOGLE_OAUTH_CLIENT_ID=<web-store-client-id.apps.googleusercontent.com> pnpm package:webstore
```

その後、拡張とWorkerをbuild/deployします。

```bash
pnpm build:extension
pnpm --dir apps/log-worker migrate:remote
pnpm deploy:log-worker
```

標準のWorker URLは `apps/chrome-extension/lib/cloud-config.ts` に入っています。Googleログイン時は `/me` と `/me/settings` を使い、ログ送信は `/me/events` にGoogle tokenでPOSTします。

### CloudflareログAPI

Cloudflare側は `apps/log-worker` にあります。D1 databaseを作り、`apps/log-worker/wrangler.jsonc` の `database_id` と `GOOGLE_OAUTH_CLIENT_ID` を差し替えてからmigrationとsecret設定を行ってください。

```bash
npx wrangler d1 create autofill-browser-logs
pnpm --dir apps/log-worker migrate:remote
npx wrangler secret put CLOUD_DATA_ENCRYPTION_KEY --config apps/log-worker/wrangler.jsonc
npx wrangler secret put CLOUD_LOG_INGEST_TOKEN --config apps/log-worker/wrangler.jsonc
pnpm deploy:log-worker
```

localで試す場合は `apps/log-worker/.dev.vars` に `CLOUD_DATA_ENCRYPTION_KEY=local-dev-encryption-key` と `CLOUD_LOG_INGEST_TOKEN=local-dev-token` を置き、以下を実行します。

```bash
pnpm --dir apps/log-worker migrate:local
pnpm dev:log-worker
```

ユーザー向けAPIは、ログイン確認が `GET /me`、設定同期が `GET /me/settings` と `PUT /me/settings`、ログが `POST /me/events` と `GET /me/events?limit=50`、Remote rulesが `GET /me/rules`、ログ解析が `GET /me/log-analysis?limit=7` です。いずれもGoogle access tokenの `Authorization` ヘッダーが必要です。

共有トークンで使う管理用APIは `GET /admin/logs?limit=50`、`GET/PUT /admin/rules`、`GET /admin/log-analysis?limit=7` です。`wrangler.jsonc` には毎日 15:00 UTC、つまり日本時間 00:00 のCron Triggerを設定しており、直近24時間の全体ログ解析を `log_analysis_reports` に保存します。

管理画面は Worker 内蔵の `GET /admin` です。画面に `CLOUD_LOG_INGEST_TOKEN` を入力すると、最近のログ、日次ログ解析、Remote rules、同期履歴を確認できます。tokenはブラウザのlocalStorageにだけ保存されます。

この端末では管理用tokenを `.local/cloud-admin-token.txt` に置いています。`.local/` はgit管理外です。

設定同期は最新snapshotを `user_sync_snapshots` に持ちつつ、保存・restoreの履歴を `user_sync_snapshot_history` に残します。Googleユーザー向けには `GET /me/settings/history?limit=20` と `POST /me/settings/history` があり、`POST` bodyに `{ "revision": 1 }` のように指定すると、そのrevisionのsnapshotへ巻き戻せます。

Google同期の実Worker E2Eは以下で実行できます。`VERIFY_D1_RAW=1` を付けるとWranglerでD1の生値も確認し、テスト用markerが暗号化済みprofileに平文で残っていないことを検査します。

```bash
GOOGLE_ACCESS_TOKEN=<google-access-token> pnpm verify:google-sync-e2e
GOOGLE_ACCESS_TOKEN=<google-access-token> VERIFY_D1_RAW=1 pnpm verify:google-sync-e2e
```

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
