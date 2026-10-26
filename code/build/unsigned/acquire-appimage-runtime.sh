#!/usr/bin/env bash
set -euo pipefail

build_dir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$build_dir/../.." && pwd)
target=${1:?linux_amd64 or linux_arm64}
(cd "$root/backend" && go run ./tools/targetverify --target "$target" >&2)
release_commit=fedfad51acc2860b2916a1eef32ba4a500ff31ef
case "$target" in
  linux_amd64)
    asset_id=657374641
    expected=617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46
    ;;
  linux_arm64)
    asset_id=657373827
    expected=9a72a744d221576c9347ec074243acc5c3c7568896b12714e0e82e9f0bf47900
    ;;
  *) echo "target must be linux_amd64 or linux_arm64" >&2; exit 2 ;;
esac

url="https://api.github.com/repos/AppImage/type2-runtime/releases/assets/$asset_id"
tools_dir="${REPLICARO_TARGET_OUT:?target-contained output root is required}/tools"
runtime="$tools_dir/appimage-runtime-$release_commit-$target"
mkdir -p "$tools_dir"
if [[ -f "$runtime" ]] && [[ "$(sha256sum "$runtime" | awk '{print $1}')" == "$expected" ]]; then
  chmod 600 "$runtime"
  printf '%s\n' "$runtime"
  exit 0
fi
if [[ -e "$runtime" ]]; then
  unlink "$runtime"
fi
temporary=$(mktemp "$tools_dir/.appimage-runtime.XXXXXX")
cleanup() { [[ ! -e "$temporary" ]] || unlink "$temporary"; }
trap cleanup EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --max-redirs 5 \
  -H 'Accept: application/octet-stream' -H 'X-GitHub-Api-Version: 2022-11-28' \
  --output "$temporary" "$url"
actual=$(sha256sum "$temporary" | awk '{print $1}')
if [[ "$actual" != "$expected" ]]; then
  echo "AppImage runtime checksum mismatch: $actual" >&2
  exit 1
fi
chmod 600 "$temporary"
mv "$temporary" "$runtime"
trap - EXIT
printf '%s\n' "$runtime"
