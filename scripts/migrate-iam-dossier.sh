#!/usr/bin/env bash
# migrate-iam-dossier.sh — iam context packs / autonomy 台帳の Agent Home 移行 (U8a)
#
# /Users/nico/projects/iam の
#   - context/packs/agent-operating-style.md   -> agvt dossier (tier=open)
#   - context/packs/corporate-bookkeeping.md   -> agvt dossier (tier=standard)
#   - context/packs/finance-and-spending.md    -> agvt dossier (tier=standard)
#   - context/repo-orchestration/repositories.json の autonomy
#                                              -> agvt charter (capability=repo-commit)
# を投入する。
#
# ティア割り当ては ADR 0014（感度ティアモデル）準拠:
#   open     = 非特定・摩擦ゼロ（作業スタイルの好み）
#   standard = 当事者・規模が特定される業務コンテキスト（税務・経理、支出・資産方針）
#
# 冪等性:
#   - dossier: --id 固定。既存 id は `agvt dossier edit` で上書き（add は既存 id を拒否するため）
#   - charter: `agvt charter add` は同一 capability/scope を upsert するため素で冪等
#
# 原本ファイルは読み取りのみで、削除・変更しない（二重管理解消は Phase 2 で判断）。
#
# 使い方:
#   bash scripts/migrate-iam-dossier.sh
#
# ドライラン（実データを触らず一時パスへ投入して検証）:
#   T=$(mktemp -d)
#   AGVT_DOSSIER_PATH=$T/dossier.json AGVT_CHARTER_PATH=$T/charter.json \
#   AGVT_AUDIT_PATH=$T/audit.jsonl bash scripts/migrate-iam-dossier.sh
#
# 環境変数:
#   IAM_ROOT  移行元 iam リポジトリ（default: /Users/nico/projects/iam）
#   AGVT_BIN  agvt バイナリ（default: PATH 上の agvt）
set -euo pipefail

IAM_ROOT="${IAM_ROOT:-/Users/nico/projects/iam}"
PACKS_DIR="$IAM_ROOT/context/packs"
REPOS_JSON="$IAM_ROOT/context/repo-orchestration/repositories.json"
AGVT_BIN="${AGVT_BIN:-agvt}"

# --- 前提チェック ---------------------------------------------------------
command -v "$AGVT_BIN" >/dev/null 2>&1 || {
    echo "error: agvt binary not found: $AGVT_BIN" >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    echo "error: jq is required" >&2
    exit 1
}
[ -f "$REPOS_JSON" ] || {
    echo "error: repositories.json not found: $REPOS_JSON" >&2
    exit 1
}
for f in agent-operating-style.md corporate-bookkeeping.md finance-and-spending.md; do
    [ -f "$PACKS_DIR/$f" ] || {
        echo "error: pack file not found: $PACKS_DIR/$f" >&2
        exit 1
    }
done

# --- dossier upsert -------------------------------------------------------
# upsert_dossier <id> <topic> <tier> <tags> <source-file>
# 本文は stdin 経由で渡し、標準出力には一切出さない。
upsert_dossier() {
    local id="$1" topic="$2" tier="$3" tags="$4" file="$5"
    if "$AGVT_BIN" dossier ls --json |
        jq -e --arg id "$id" '.entries[] | select(.id == $id) | .id' >/dev/null; then
        "$AGVT_BIN" dossier edit "$id" \
            --topic "$topic" --tier "$tier" --tags "$tags" --body-stdin <"$file"
        echo "upserted (edit): $id (tier=$tier)"
    else
        "$AGVT_BIN" dossier add "$topic" \
            --id "$id" --tier "$tier" --tags "$tags" --body-stdin <"$file"
        echo "upserted (add): $id (tier=$tier)"
    fi
}

echo "== dossier: iam context packs =="
upsert_dossier iam-pack-agent-operating-style \
    "agent-operating-style: 作業スタイル・エージェント運用の好み (iam context pack)" \
    open "iam,context-pack,operating-style" \
    "$PACKS_DIR/agent-operating-style.md"
upsert_dossier iam-pack-corporate-bookkeeping \
    "corporate-bookkeeping: 会社の税務・経理事情 (iam context pack)" \
    standard "iam,context-pack,accounting,tax" \
    "$PACKS_DIR/corporate-bookkeeping.md"
upsert_dossier iam-pack-finance-and-spending \
    "finance-and-spending: 支出・資産方針 (iam context pack)" \
    standard "iam,context-pack,finance" \
    "$PACKS_DIR/finance-and-spending.md"

# --- charter: repositories.json autonomy ----------------------------------
# scope は charter の規約（repo:<id>、wildcard は repo:*）に合わせる。
# charter add は同一 capability/scope を上書きするため再実行安全。
echo "== charter: repo-commit autonomy rules =="
rule_count=0
while IFS=$'\t' read -r repo_id autonomy note; do
    if [ -n "$note" ]; then
        "$AGVT_BIN" charter add repo-commit "repo:$repo_id" "$autonomy" --notes "$note"
    else
        "$AGVT_BIN" charter add repo-commit "repo:$repo_id" "$autonomy"
    fi
    rule_count=$((rule_count + 1))
done < <(jq -r '.repositories[] | [.id, .autonomy, (.autonomy_note // "")] | @tsv' "$REPOS_JSON")

# --- サマリ（メタデータのみ。本文は表示しない） -----------------------------
echo "== summary =="
"$AGVT_BIN" dossier ls --json |
    jq -r '.entries | group_by(.tier) | map("dossier tier=\(.[0].tier): \(length) entries") | .[]'
echo "charter rules upserted this run: $rule_count"
"$AGVT_BIN" charter ls --json | jq -r '"charter rules total: \(.rules | length)"'
echo "done."
