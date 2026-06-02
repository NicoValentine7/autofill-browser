#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_host_path="$repo_root/scripts/agvt-native-host.mjs"
host_path="${AGVT_NATIVE_HOST_PATH:-$HOME/.local/bin/agvt-native-host.mjs}"
chrome_host_dir="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
manifest_path="$chrome_host_dir/io.nico.agvt.json"
extension_id="${AGVT_CHROME_EXTENSION_ID:-cjdfbkbfiengbkpejnjecgdgagipjkdk}"

mkdir -p "$(dirname -- "$host_path")"
cp "$source_host_path" "$host_path"
chmod 755 "$host_path"

mkdir -p "$chrome_host_dir"
cat > "$manifest_path" <<EOF
{
  "name": "io.nico.agvt",
  "description": "Agent Vault native bridge for Autofill Browser",
  "path": "$host_path",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$extension_id/"
  ]
}
EOF
chmod 644 "$manifest_path"

printf '%s\n' "$manifest_path"
