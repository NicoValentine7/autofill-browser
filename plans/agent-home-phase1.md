# Agent Home Phase 1 構築計画

作成: 2026-07-02（敵対的レビュー1巡反映済み）／ 対象リポジトリ: `/Users/nico/projects/autofill-browser` ／ モード: branch + PR（gh 利用可）

**ステータス: Phase 1 全ユニット完了（2026-07-02）** — U0/U0b/U1(+PR #11)/U2〜U9 すべて main マージ済み（PR #10〜#21）。未消化のユーザーゲート: ①iam の .mcp.json/.agent-home.md コミット（新セッション試用後）、②crates.io publish + リポジトリ public 化、③sync-worker 本番デプロイ（手順は PR #21 本文）。

## Context Brief（コールドスタート用 — 前提知識ゼロでここから読む）

**製品ビジョン**: Agent Home は「調教済みの自分を AI エージェントに一発注入する」製品。3層構造 — ① **Vault**（認証情報・鍵 = 既存の agvt CLI）、② **Dossier**（構造化された個人/会社コンテキスト。会社の課題・機器の型番・税務状況など。感度ティア付き）、③ **Charter**（エージェントの権限・自律性規定）。MCP サーバー + CLI でローカル/クラウドどのエージェント環境にも注入する。戦略は agent-first（human-first パスワードマネージャとの正面戦争はしない）。安全性は「やらない理由」ではなく感度ティア等の**製品機能**として織り込む。

**現有資産**:
- `crates/agvt/` — Rust CLI 約4200行。モジュール: main.rs(1437), vault.rs(783), prepare.rs(648), keychain.rs(374), help.rs(279), cloudflare.rs(260), reference.rs(173), totp.rs(96), presets.rs(108), error.rs(36)。テストは `cd crates/agvt && cargo test`。TOTP 実装済み。hybrid vault（global: `~/.local/share/agvt/agent-vault.json` / repo: `.local/agent-vault.json`）、参照形式 `agvt://<vault>/<item>/<field>`、macOS Keychain 統合、`run --redact-output`、`prepare` 診断
- **注意: `agvt inject` は既存コマンド**（main.rs:88 → handle_inject）。テンプレート中の secret ref を解決して**生の秘密値を stdout に出す**用途。本計画の環境配線コマンドは名前衝突とセキュリティ混同を避けるため **`agvt wire`** とする
- `docs/adr/` — 主要: Zero-Knowledge Vault(0002)、Recovery Phrase ラップ(0003)、agent-facing 原則(0011)、Agent Home 3層(0013)、感度ティア(0014)。旧 0010 番号衝突は U0 で解消済み（prepare-dry-run は 0012 に renumber）。**新規設計は必ず既存 ADR と整合させる**
- `apps/log-worker/` — Cloudflare Workers + D1。構成の雛形: `wrangler.jsonc`・`migrations/`・`tests/`
- `apps/chrome-extension/` — Plasmo 製、agvt への native messaging bridge あり（Phase 1 スコープ外）
- CI は**未整備**（`.github/workflows/` なし）→ U0b で整備する

**ドッグフーディング先**: `/Users/nico/projects/iam`。`context/packs/`（agent-operating-style.md, corporate-bookkeeping.md, finance-and-spending.md）→ Dossier へ、`context/repo-orchestration/repositories.json` の autonomy フィールド → Charter へ移行する。

**運用ルール**（リポジトリ AGENTS.md より）: コミット自律性 auto（build/test GREEN で commit→push 可）。vault/sync/OAuth 境界の変更はコミット前にセキュリティ自己レビュー。コミットメッセージは日本語。破壊的 git 操作禁止。

**進行中の外部作業**: 別セッションのタスク task_b917ab8a が「agvt add の vault スコープ UX 改善（AGVT_PATH モードで dev タグになる罠の修正＋file kind 検討）」を実施中。U1 着手前に main を pull して重複を避けること。

**セキュリティ不変条件（全ユニット共通）**: 秘密値・locked ティアの本文は、stdout・MCP レスポンス・audit log・生成断片のいずれにも**決して含めない**。値の受け渡しは常に `agvt://` 参照 + `agvt run` の env 注入で行う（ADR 0011）。

## DAG

```
U0 (設計ADR) ──┬→ U3 (Dossier core) ──┬→ U5 (MCP) ──────┬→ U8 (iamドッグフード)
               └→ U4 (Charter core) ──┼→ U6 (wire CLI) ──┘
U2 (audit API) ─→ U3, U4, U5          └→ U7 (ZK sync) ← U1, U3, U4
U0b (CI整備) — 独立・最優先
U1 (file kind) — 独立（外部タスク b917ab8a と整合）→ U7, U9
U9 (OSS準備) ← U1, U2
```

キュー順: [U0, U0b, U1, U2 並列] → [U3, U4 並列] → [U5, U6, U7 並列] → U8 → U9

並列条件: **main.rs のディスパッチ部に触る全ユニット（U1〜U7）は同時マージ禁止**。並列に開発してよいが、キューには1つずつ入れ、マージ前に main へリベースして全テストを再実行する。

---

## U0 — Agent Home アーキテクチャ ADR

- id: `u0-adr-agent-home`
- goal: ADR「Agent Home 3層アーキテクチャ」と ADR「感度ティアモデル」を書き、以降の全ユニットの設計基準を固定する
- depends_on: なし
- scope: まず既存の番号衝突を解消（`0010-agvt-prepare-dry-run-diagnostics.md` → `0012-...` に renumber、参照箇所を更新）。その上で新規 `docs/adr/0013-agent-home-three-layers.md`, `docs/adr/0014-sensitivity-tiers.md`
- 決めること:
  1. Dossier エントリのスキーマ（topic/body/tags/tier/updatedAt）と保存先（`~/.local/share/agvt/dossier.json`）
  2. ティア定義 — `open`（摩擦ゼロで任意エージェントに渡る: 会社の課題・型番・好み）/ `standard`（ローカル環境のみ既定で渡る: 取引先名・売上規模）/ `locked`（vault と同じ暗号化・明示参照必須: 認証情報・口座番号）
  3. Charter スキーマ（capability/scope/autonomy: auto|branch-auto|confirm/conditions）— iam の repositories.json autonomy 台帳の一般化。**Charter 改ざんの脅威モデルを明記**: エージェント自身が charter を書き換えて自己昇格する経路に対し、Phase 1 は「全 write の audit 記録による検知」まで、write のユーザーゲートは Phase 2 で扱う
  4. MCP サーフェス（公開ツール名と境界）: **locked の生値は MCP レスポンスに決して含めない**。locked への参照要求には ref（`agvt://...`）を返し、消費は `agvt run` 経由に限定する（ADR 0011 整合）。例外経路は作らない
  5. 命名: CLI サブコマンドは `agvt dossier` / `agvt charter` / `agvt mcp` / **`agvt wire`**（既存 `agvt inject` と衝突するため inject の名は使わない。両者の役割差も ADR に明記）
- acceptance_tests: ADR 2本が既存 ADR（特に 0002 zero-knowledge、0011 agent-facing）と矛盾しない。ユーザーの3ユースケース（会社税務の委任、証券口座管理、会社固有情報の蓄積）がティアモデルで表現できることを ADR 内の例で示す。体裁は 0011 準拠（`Status: Accepted` 行 + Context/Decision/Why/Consequences 構成）
- verification_commands: docs のみ。renumber に伴う参照更新は `grep -rn "0010-agvt-prepare" docs/ crates/ apps/` が旧参照ゼロであること
- risk_level: Tier 3（以降全部の土台）／ model: strongest
- rollback_plan: ADR を Superseded にして書き直し
- merge_readiness: **ユーザーが ADR 要旨に合意**（このユニットのみユーザー確認ゲートあり — 設計は話し合いで決める原則）

## U0b — CI 整備

- id: `u0b-ci`
- goal: `.github/workflows/agvt-ci.yml` を新設し、push/PR で `cd crates/agvt && cargo build && cargo test` を実行。以降のユニットの「CI GREEN」を機械判定可能にする
- depends_on: なし（最優先で入れる）
- scope: `.github/workflows/agvt-ci.yml` のみ
- acceptance_tests: main への push と PR で workflow が走り GREEN になる（gh run list で確認）
- verification_commands: `gh run watch` または `gh run list --limit 1`
- risk_level: Tier 1
- rollback_plan: workflow ファイル削除
- merge_readiness: workflow 実行成功

## U1 — Vault: file kind

- id: `u1-file-kind`
- goal: 鍵ファイル（.p8/.p12 等）を第一級で保存できる `--kind file` を追加（内部 base64、`agvt read <ref> --out FILE` で復元、メタデータに元ファイル名・サイズ・sha256）
- depends_on: なし。**着手前に main を pull し task_b917ab8a の成果を取り込む**（同タスクが file kind まで実装済みなら本ユニットは差分補完に縮小）
- scope: `crates/agvt/src/main.rs`, `vault.rs`, `help.rs`, `reference.rs`
- 互換性設計（必須）: `validate_item_kind`（vault.rs:155 付近）は閉集合検証で、**読み取りパスでも kind を検証する**ため、file kind 追加後に revert すると旧バイナリが該当 item を読めなくなる。対策として、読み取り時の未知 kind は「エラー」ではなく「警告 + 汎用扱い」に緩和する変更を本ユニットに含める（前方互換の確保）
- acceptance_tests: file kind の add→read --out 往復で sha256 一致／`ls --json` に kind と元ファイル名が出る（値は出ない）／**file item が混在した vault で既存 kind の全操作が動く**／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo build --release && cargo test`
- risk_level: Tier 1
- rollback_plan: PR revert。revert 前に file kind item が存在する場合は `agvt read --out` で退避 → `agvt delete` する手順を PR 本文に明記
- merge_readiness: CI GREEN + セキュリティ自己レビュー（値の stdout 漏れがないこと）

## U2 — Vault: audit API + vault 操作の記録

- id: `u2-audit-log`
- goal: 公開 audit API（`audit::record(op, ref, caller)`）を新設し、**vault 操作**（add/read/run/delete/import-env/inject）を append-only JSONL（`~/.local/share/agvt/audit.jsonl`）に記録。`agvt audit ls [--json]` で閲覧。**秘密値・本文は記録しない**（ref・item 名・操作・時刻・呼び出しコマンド名のみ）。dossier/charter の記録は本ユニットではなく、audit API を使う側（U3/U4/U5）の受け入れ条件とする
- depends_on: なし
- scope: `crates/agvt/src/` 新規 `audit.rs` + vault 系操作へのフック
- acceptance_tests: 各 vault 操作でエントリが増える／エントリに秘密値が含まれないことをテストでアサート／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo test`
- risk_level: Tier 1
- rollback_plan: PR revert（audit.jsonl は残っても無害）
- merge_readiness: CI GREEN

## U3 — Dossier core

- id: `u3-dossier-core`
- goal: Dossier の保存・CRUD。`agvt dossier add|ls|show|edit|rm|search`。ティア（open/standard/locked）を持ち、locked は vault と同じ passphrase 暗号化、open/standard は平文 JSON（ADR 0014 に従う）。全 write と locked read を U2 の audit API で記録
- depends_on: U0, U2
- scope: `crates/agvt/src/` 新規 `dossier.rs` + main.rs ディスパッチ + help.rs
- acceptance_tests: add→search→show 往復／tier=locked が暗号化保存されることをファイル内容の検査で確認／`show --tier open` フィルタが locked を返さない／dossier の write と locked read が audit に記録される／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo test`
- risk_level: Tier 2 ／ model: strongest（スキーマは以降の互換性を縛る）
- rollback_plan: PR revert。dossier.json はスタンドアロンなので vault に影響なし
- merge_readiness: CI GREEN + セキュリティ自己レビュー（locked の平文漏れなし）

## U4 — Charter core

- id: `u4-charter-core`
- goal: Charter の保存・CRUD。`agvt charter add|ls|show|check`。`check <capability> <scope>` が autonomy 判定（auto/branch-auto/confirm/deny）を機械可読で返す。**全 write を U2 の audit API で記録**（自己昇格の検知線 — ADR 0013 の脅威モデル参照）
- depends_on: U0, U2
- scope: `crates/agvt/src/` 新規 `charter.rs` + main.rs + help.rs。保存先 `~/.local/share/agvt/charter.json`（平文 — 権限規定は秘密ではなく監査可能であるべき）
- acceptance_tests: iam の repositories.json の autonomy 3種（auto/branch-auto/confirm）を Charter で表現し `check` が正答／未定義 capability は confirm にフォールバック／charter write が audit に記録される／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo test`
- risk_level: Tier 2
- rollback_plan: PR revert
- merge_readiness: CI GREEN

## U5 — MCP サーバー

- id: `u5-mcp-server`
- goal: `agvt mcp`（stdio）で MCP サーバーを起動。ツール: `dossier_search`/`dossier_read`（ティアフィルタ付き）、`charter_check`、`vault_ls`（item 名のみ）、`secret_handoff`（ref を返す）。**locked の生値は MCP レスポンスに決して含めない**: locked への read 要求には本文ではなく ref（`agvt://...`）と「`agvt run` で消費せよ」の指示を返す。unlock して生値を返す例外経路は実装しない（ADR 0011/0013 整合）。MCP 経由の全アクセスを audit 記録
- depends_on: U2, U3, U4
- scope: `crates/agvt/src/` 新規 `mcp.rs`（JSON-RPC 2.0 over stdio。外部 SDK 依存は最小に — serde のみで実装可）+ main.rs
- acceptance_tests: MCP initialize/tools-list/tools-call の JSON-RPC 往復テスト／locked の dossier_read が**本文を含まず ref のみ返す**ことをテストでアサート／MCP アクセスが audit に記録される／Claude Code に `.mcp.json` で接続して手動スモーク（dossier_search が実データを返す）— 手順を PR 本文に記録／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo test`
- risk_level: Tier 3 ／ model: strongest
- rollback_plan: PR revert（新規コマンドなので既存機能に影響なし）
- merge_readiness: CI GREEN + セキュリティ自己レビュー（MCP 経由で locked 生値・秘密値が出ないこと）

## U6 — wire CLI（環境配線）

- id: `u6-wire-cli`
- goal: `agvt wire [--target DIR] [--print]` — 対象環境に (1) `.mcp.json` への `agvt mcp` サーバー登録、(2) CLAUDE.md/AGENTS.md に貼る接続ブートストラップ断片（open ティアの要約 + MCP 接続方法 + Charter 要旨）を生成。`--print` はクラウド環境へのコピペ用。**既存の `agvt inject`（secret ref 解決・値出力）とは別コマンド**であり、wire の出力に秘密値・standard/locked 本文は含めない
- depends_on: U0, U3, U4（U5 と並列開発可。ただし**生成した設定の実配布・実使用は U5 マージ後** — 生成物が `agvt mcp` コマンドを指すため）
- scope: `crates/agvt/src/` 新規 `wire.rs` + main.rs
- acceptance_tests: `--target` で .mcp.json が正しくマージされる（既存設定を壊さないことをテストで確認）／生成断片に standard/locked ティアの内容・秘密値が含まれないことをアサート／本ユニットの検証は**生成物の構造の正しさのみ**（サーバー起動の検証は U8 で行う）／main の全既存テスト GREEN
- verification_commands: `cd crates/agvt && cargo test`
- risk_level: Tier 2
- rollback_plan: PR revert
- merge_readiness: CI GREEN

## U7 — Zero-knowledge sync MVP

- id: `u7-zk-sync`
- goal: ADR 0002/0003 の実装第一歩。`agvt sync push|pull` — vault + dossier + charter の暗号化スナップショット（schemaVersion 付き）を Cloudflare Workers + D1 へ。Vault Key を Recovery Phrase でラップした Vault Recovery Package を同梱。サーバーは復号不能（zero-knowledge）
- depends_on: U1（file kind のデータ形式確定後）, U3, U4
- **pull の安全設計（必須仕様）**: pull は (1) 既存ローカルファイルのバックアップ作成（`agent-vault.json.bak` 等）→ (2) 一時ファイルへダウンロード・復号検証 → (3) 検証成功後に atomic rename、の3段で行う。途中失敗時に既存 vault/dossier/charter が無傷で残ること
- コールドスタート補足: Cloudflare 認証は `agvt://global/cloudflare/token` 経由（`crates/agvt/src/cloudflare.rs` に既存の解決実装あり）。Worker の構成は `apps/log-worker/` の `wrangler.jsonc`・`migrations/`・`tests/` を雛形として `apps/sync-worker/` を新設。D1 database の作成は `wrangler d1 create`（ローカル開発は `wrangler dev` + ローカル D1 で完結させる）
- acceptance_tests: push→空環境（HOME を隔離した一時ディレクトリ）で pull→Recovery Phrase で復元→全 item の復号往復一致／**既存 vault がある環境への pull を途中失敗させ、元 vault が無傷であることをテストで確認**／サーバー側 D1 に平文が存在しないことをダンプ検査で確認／Recovery Phrase なしでは pull データが復号不能／schemaVersion 不一致時は明示エラー（黙って上書きしない）
- verification_commands: `cd crates/agvt && cargo test` + `cd apps/sync-worker && npm test`（**本番デプロイはユーザー確認ゲート**）
- risk_level: Tier 3 ／ model: strongest ／ セキュリティ自己レビュー必須
- rollback_plan: PR revert。Worker 未デプロイなら影響なし。デプロイ済みなら wrangler rollback + **D1 上の暗号化スナップショット行のパージ手順**（`DELETE FROM snapshots WHERE ...`）を PR 本文に記載。ローカル側は .bak からの復元手順を明記
- merge_readiness: CI GREEN + セキュリティ自己レビュー + 暗号設計が ADR 0002/0003 と一致することの明記

## U8 — iam ドッグフーディング移行

- id: `u8-iam-dogfood`
- goal: iam の context packs 3本（agent-operating-style / corporate-bookkeeping / finance-and-spending）を Dossier エントリ（ティア付与）へ、repositories.json の autonomy を Charter へ移行。iam のセッションが `agvt mcp` 経由でこれらを読める状態にし、`agvt wire --target /Users/nico/projects/iam` で配線
- depends_on: U5, U6
- scope: **2 PR に分割** — (a) autofill-browser 側: 移行スクリプト `scripts/migrate-iam-dossier.sh`、(b) iam 側: wire 生成物の配線 + 移行記録。iam 側コミットは iam の autonomy 規定に従う（ユーザー確認）
- acceptance_tests（機械判定）: iam の新規セッションで MCP 経由の dossier_search が corporate-bookkeeping の内容を返す／charter_check が repositories.json と同じ判定を返す／**元ファイルは削除しない**（移行後も正として残し、二重管理解消は Phase 2 で判断）
- ユーザーゲート（主観・acceptance とは別）: ユーザーが1セッション使って違和感がないこと
- verification_commands: 手動スモーク（手順を PR 本文に記録）
- risk_level: Tier 2
- rollback_plan: iam 側変更の revert（元ファイル無傷なので実害なし）
- merge_readiness: スモーク成功 + ユーザーゲート通過

## U9 — OSS 公開準備

- id: `u9-oss-prep`
- goal: agvt crate を世界に出す準備 — LICENSE（MIT or Apache-2.0 デュアル）、英語 README（agent-first の売り文句込み）、SECURITY.md、cargo publish dry-run、リポジトリ公開範囲の確認
- depends_on: U1, U2（コア安定後）。U5〜U8 と並列可だが公開ボタンは最後
- scope: `crates/agvt/README.md`, `LICENSE`, `SECURITY.md`, `crates/agvt/Cargo.toml`。**現状 Cargo.toml は `publish = false` / `license = "UNLICENSED"` のため dry-run は失敗する** — この2フィールドの反転を本ユニットに含める。事前に crates.io で `agvt` 名の空きを確認し、取られていれば代替名（`agent-vault` 等）をユーザーと相談
- acceptance_tests: `cargo publish --dry-run` が通る／README の Quick Start を新規一時環境（クリーンな HOME）で上から実行して全コマンド成功
- verification_commands: `cd crates/agvt && cargo publish --dry-run`
- risk_level: Tier 1（ただし**実際の公開はユーザー確認ゲート** — 外部公開範囲の拡大）
- rollback_plan: 公開前なら revert のみ
- merge_readiness: CI GREEN + ユーザーの公開 GO

---

## マージキュー規則

- 依存が未マージ/失敗中のユニットはキューに入れない
- マージ前に必ず main へリベースし、`cd crates/agvt && cargo test` を再実行
- **main.rs に触る全ユニット（U1〜U7）は同時マージ禁止**（1つずつキューに入れる）
- あるユニットのマージが下流の前提を壊したら、キューを止めて該当 unit spec を再生成する

## 停滞時の回復

- 停滞ユニットはキューから外し、発見事項・ブロッカー・部分決定をこのファイル末尾の「## 停滞ログ」節（停滞発生時に新設）へ記録
- スコープを狭めた unit を再生成して再投入（例: U5 が重ければ「dossier_search のみの MCP」に縮小）

## 確認ゲート（ユーザー判断が必要な点）

1. U0 の ADR 要旨合意（設計は話し合いで決める原則）
2. U7 sync-worker の本番デプロイ
3. U9 の実際の OSS 公開（外部公開範囲の拡大）と crate 名の最終決定
4. iam 側のコミット（iam の autonomy 規定に従う）

それ以外は autofill-browser の autonomy: auto に従い、build/test GREEN で commit→push まで自走する。

## レビュー履歴

- 2026-07-02: 敵対的レビュー1巡（CRITICAL 4 / MAJOR 7 / MINOR 7）→ 全 CRITICAL・全 MAJOR・全 MINOR を反映。主な変更: locked の MCP unlock 例外経路を廃止（ref 返却に統一）、`agvt inject` 名前衝突回避のため `agvt wire` に改名、U7 に U4 依存追加と pull 3段安全設計、U2 を audit API + vault 記録に再スコープし U3/U4/U5 に依存辺追加、U0b（CI 整備）新設、ADR 番号衝突（0010×2）の renumber を U0 に組み込み
