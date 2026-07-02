# autofill-browser — エージェント運用ルール

Chrome拡張自動入力＋Android自動入力ブラウザの初期土台。本番デプロイ連動なし。

## コミット自律性: auto

- 検証（build / test / lint）が通れば commit → push まで自走してよい
- vault・sync・OAuth 境界（資格情報を扱う箇所）に触れる変更は、コミット前にセキュリティ観点のセルフレビューを行う
- 破壊的 git 操作（force push / reset --hard / 履歴改変）は禁止

## 検証

変更後は build と既存テストを実行して GREEN を確認してからコミットする。
