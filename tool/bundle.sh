#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?Specify a local staging output directory}
sequence=${SHINPHONY_RELEASE_SEQUENCE:-0}
[[ "$sequence" =~ ^[0-9]{1,15}$ ]] || { echo 'Invalid release sequence' >&2; exit 1; }
mkdir -p "$out" build/bundle
entries=()
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  binary="build/bundle/$os-$arch"
  # These extensionless platform keys are the existing signed-download wire
  # format, not a CLI name. Also expose a correctly named executable per OS.
  name=shinphony-hook
  [[ "$os" != windows ]] || name+=.exe
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w -X main.releaseSequence=$sequence" -o "$binary" .
  mkdir -p "build/bin/$os-$arch"
  cp "$binary" "build/bin/$os-$arch/$name"
  gzip -n -c "$binary" > "$out/$os-$arch.gz"
  hash=$(shasum -a 256 "$binary" | awk '{print $1}')
  entries+=("$(jq -n --arg target "$os-$arch" --arg hash "$hash" '{key:$target,value:$hash}')")
done
printf '%s\n' "${entries[@]}" | jq -s 'from_entries' > "$out/manifest.json"
