#!/usr/bin/env bash
# Verify that the released binaries can be rebuilt bit for bit.
#
#   tool/verify_reproducible.sh <sequence>
#
# 1. fetches the published TUF metadata and verifies it against the pinned root
#    (deploy/root.json) with cmd/verifyrelease;
# 2. rebuilds all six targets with the release flags (the same -trimpath,
#    -buildvcs=false and -ldflags as tool/bundle.sh) in a clean temporary
#    GOPATH and GOCACHE;
# 3. prints MATCH or MISMATCH per target and exits non-zero on any mismatch.
#
# The first run downloads the Go module cache into the temporary GOPATH, so it
# needs network access and a little patience. Override the metadata origin for
# a staging or local release:
#
#   SHINPHONY_METADATA_URL=http://127.0.0.1:8788/agent/stable/metadata \
#     tool/verify_reproducible.sh 2026111303
set -euo pipefail
cd "$(dirname "$0")/.."

seq=${1:?usage: tool/verify_reproducible.sh SEQUENCE (for example 2026111303)}
[[ "$seq" =~ ^[0-9]{10}$ ]] || { echo "Invalid release sequence: $seq" >&2; exit 2; }
metadata_url=${SHINPHONY_METADATA_URL:-https://downloads.potafree.net/agent/stable/metadata}

work=$(mktemp -d "${TMPDIR:-/tmp}/shinphony-repro.XXXXXXXX")
cleanup() {
  # The Go module cache is read-only; make it removable first.
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf -- "$work" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

echo "Verifying signed metadata from $metadata_url"
go run ./cmd/verifyrelease --metadata-url "$metadata_url" --pinned-root-file deploy/root.json > "$work/verified.json"
published=$(jq -r '.sequence' "$work/verified.json")
if [ "$published" != "$seq" ]; then
  echo "Sequence $seq is not the current signed release (current: $published)." >&2
  echo 'Pass the current sequence, or use the release that sequence was published for.' >&2
  exit 1
fi

mkdir -p build/reproducible
cp "$work/verified.json" build/reproducible/verified.json

# A clean module cache and build cache make the result depend only on the
# sources, the pinned toolchain and the release flags. The build cache is fresh
# per target (and removed afterwards) so six architectures do not pile up on a
# small temporary volume; the module cache is downloaded once.
export GOPATH="$work/gopath"
export GOFLAGS=""
unset GOMODCACHE
mkdir -p "$GOPATH"

hash_file() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

echo "Toolchain: $(go version)"
failed=0
results=()
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  key="$os-$arch"
  binary="build/reproducible/$key"
  export GOCACHE="$work/gocache-$key"
  export GOTMPDIR="$work/gotmp-$key"
  mkdir -p "$GOCACHE" "$GOTMPDIR"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.releaseSequence=$seq" -o "$binary" .
  rm -rf -- "$GOCACHE" "$GOTMPDIR"
  actual=$(hash_file "$binary")
  expected=$(jq -r --arg key "$key" '.targets[$key].sha256 // empty' "$work/verified.json")
  if [ -z "$expected" ]; then
    echo "MISMATCH $key: no signed hash in metadata" >&2
    results+=("MISMATCH $key missing")
    failed=1
  elif [ "$actual" = "$expected" ]; then
    printf 'MATCH    %-14s %s\n' "$key" "$actual"
    results+=("MATCH $key $actual")
  else
    printf 'MISMATCH %-14s built %s, signed %s\n' "$key" "$actual" "$expected" >&2
    results+=("MISMATCH $key $actual")
    failed=1
  fi
done

{
  echo "sequence $seq"
  printf '%s\n' "${results[@]}"
} > build/reproducible/result.txt

if [ "$failed" != 0 ]; then
  echo
  echo "Some targets did not match. Releases built before -buildvcs=false embedded" >&2
  echo "the git commit and cannot be reproduced from a different checkout. Check" >&2
  echo "that the release was built from this exact source tree with the pinned" >&2
  echo "Go toolchain before treating a mismatch as a supply-chain problem." >&2
  exit 1
fi
echo "All six targets match the signed release $seq."