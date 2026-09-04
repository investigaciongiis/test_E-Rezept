#!/usr/bin/env bash
set -euo pipefail

# Build the unsigned per-commit device IPA used by MobSF static analysis.
# Distribution signing and dynamic execution are outside this pipeline profile.

output_path="${1:-build/mobsf/App.ipa}"
container="${IOS_XCODE_CONTAINER:-}"
scheme="${IOS_SCHEME:-}"

if [[ -z "$container" ]]; then
  container="$(find . -maxdepth 4 -type d -name '*.xcworkspace' ! -path '*/Pods/*' ! -path '*/.build/*' -print | sort | head -n1)"
fi
if [[ -z "$container" ]]; then
  container="$(find . -maxdepth 4 -type d -name '*.xcodeproj' ! -path '*/Pods/*' ! -path '*/.build/*' -print | sort | head -n1)"
fi
[[ -n "$container" && -d "$container" ]] || {
  echo "No .xcworkspace or .xcodeproj found. Set IOS_XCODE_CONTAINER." >&2
  exit 1
}

case "$container" in
  *.xcworkspace) container_arg=(-workspace "$container") ;;
  *.xcodeproj) container_arg=(-project "$container") ;;
  *) echo "IOS_XCODE_CONTAINER must be an .xcworkspace or .xcodeproj." >&2; exit 1 ;;
esac

if [[ -z "$scheme" ]]; then
  scheme="$(xcodebuild "${container_arg[@]}" -skipPackagePluginValidation -skipMacroValidation -list -json | python3 -c '
import json, sys
d = json.load(sys.stdin)
root = d.get("workspace") or d.get("project") or {}
schemes = root.get("schemes") or []
if len(schemes) != 1:
    raise SystemExit("Unable to select a unique scheme; set IOS_SCHEME.")
print(schemes[0])
')"
fi

build_root="build/mobsf"
derived_data="$build_root/DerivedData"
rm -rf "$derived_data" "$build_root/Payload"
mkdir -p "$build_root/Payload" "$(dirname "$output_path")"
output_dir="$(cd "$(dirname "$output_path")" && pwd)"
output_abs="$output_dir/$(basename "$output_path")"

set +e
xcodebuild "${container_arg[@]}" \
  -scheme "$scheme" \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -skipPackagePluginValidation \
  -skipMacroValidation \
  -derivedDataPath "$derived_data" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY='' \
  build
build_status=$?
set -e

if (( build_status != 0 )); then
  while IFS= read -r generated_file; do
    echo "=== $generated_file ==="
    nl -ba "$generated_file" | sed -n '1,120p'
  done < <(find "$derived_data" -path '*BuildToolPluginIntermediates*' \
    -name 'Accessibility+Generated.swift' -type f -print 2>/dev/null || true)
  echo '=== SwiftGen accessibility inputs ==='
  find . -type f \( -name 'AccessibilityIdentifier.yaml' -o -name 'accessibility.stencil' \) \
    -not -path './.git/*' -print -exec sh -c 'nl -ba "$1" | sed -n "1,200p"' _ {} \;
  exit "$build_status"
fi

app_path="$(find "$derived_data/Build/Products" -type d -path '*Release-iphoneos/*.app' -print | sort | head -n1)"
[[ -n "$app_path" && -d "$app_path" ]] || {
  echo "The build completed but no Release-iphoneos .app was found." >&2
  exit 1
}

cp -R "$app_path" "$build_root/Payload/"
rm -f "$output_path"
(
  cd "$build_root"
  /usr/bin/zip -qry "$output_abs" Payload
)

[[ -s "$output_path" ]] || { echo "IPA creation failed: $output_path" >&2; exit 1; }
echo "$output_path"
