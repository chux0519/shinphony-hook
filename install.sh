#!/bin/sh
# This downloader is pinned by the App's SHA-256, and every executable hash is
# taken from the manifest signature verified by the App. Do not curl|sh an
# unpinned copy: a public key embedded in an untrusted script is not a trust root.
set -eu
umask 077
pair=0; dry=0; offline=; da=; dx=; la=; lx=; expires=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pair) pair=1; shift ;;
    --dry-run) dry=1; shift ;;
    --offline) offline=${2:?offline file required}; shift 2 ;;
    --expires) expires=${2:?expiry required}; shift 2 ;;
    --darwin-arm64) da=${2:?hash required}; shift 2 ;;
    --darwin-amd64) dx=${2:?hash required}; shift 2 ;;
    --linux-arm64) la=${2:?hash required}; shift 2 ;;
    --linux-amd64) lx=${2:?hash required}; shift 2 ;;
    *) echo 'Unsupported install option' >&2; exit 2 ;;
  esac
done
[ "$(id -u)" != 0 ] || { echo 'Run as your normal SSH user; do not use sudo.' >&2; exit 2; }
case "$expires" in ''|*[!0-9]*) echo 'Use a fresh verified command from Shinphony.' >&2; exit 2 ;; esac
[ "${#expires}" = 13 ] || exit 2
now=$(date +%s)
until=$((expires / 1000))
[ "$until" -gt "$now" ] && [ "$until" -le "$((now + 310))" ] || { echo 'Installation invitation expired. Get a new command from your phone.' >&2; exit 2; }
os=$(uname -s); arch=$(uname -m)
case "$os:$arch" in
  Darwin:arm64) platform=darwin-arm64; expected=$da ;;
  Darwin:x86_64) platform=darwin-amd64; expected=$dx ;;
  Linux:aarch64|Linux:arm64) platform=linux-arm64; expected=$la ;;
  Linux:x86_64) platform=linux-amd64; expected=$lx ;;
  *) echo 'SSH key pairing supports macOS and Linux.' >&2; exit 2 ;;
esac
case "$expected" in ''|*[!a-f0-9]*) echo 'Use a fresh verified command from Shinphony.' >&2; exit 2 ;; esac
[ "${#expected}" = 64 ] || exit 2
printf '%s\n' "Download: https://downloads.potafree.net/agent/targets/agent/$expected.$platform" \
  "Install: ~/.shinphony-agent/shinphony-hook-$expected" \
  'Only after approval on your phone: add its marked public key to ~/.ssh/authorized_keys.' \
  'Existing keys are kept. Notification hooks and services require a separate setup confirmation.'
[ "$dry" = 0 ] || exit 0
work=$(mktemp -d "${TMPDIR:-/tmp}/shinphony-install.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
if [ -n "$offline" ]; then
  [ -f "$offline" ] && [ ! -L "$offline" ] || exit 2
  cp -- "$offline" "$work/hook"
else
  curl --fail --silent --show-error --proto '=https' --connect-timeout 15 --max-time 210 --max-filesize 67108864 \
    "https://downloads.potafree.net/agent/targets/agent/$expected.$platform" -o "$work/hook"
fi
if [ "$os" = Darwin ]; then actual=$(shasum -a 256 "$work/hook" | cut -d ' ' -f 1)
else actual=$(sha256sum "$work/hook" | cut -d ' ' -f 1); fi
[ "$actual" = "$expected" ] || { echo 'Artifact hash mismatch. Nothing installed.' >&2; exit 3; }
dest="$HOME/.shinphony-agent"
[ ! -L "$dest" ] || exit 3
if [ ! -e "$dest" ]; then mkdir "$dest"; fi
[ -d "$dest" ] || exit 3
if [ "$os" = Darwin ]; then mode=$(stat -f %Lp "$dest"); owner=$(stat -f %u "$dest")
else mode=$(stat -c %a "$dest"); owner=$(stat -c %u "$dest"); fi
[ "$mode" = 700 ] && [ "$owner" = "$(id -u)" ] || { echo 'Unsafe helper directory.' >&2; exit 3; }
binary="$dest/shinphony-hook-$expected"
if [ -e "$binary" ] || [ -L "$binary" ]; then
  [ -f "$binary" ] && [ ! -L "$binary" ] || exit 3
  if [ "$os" = Darwin ]; then actual=$(shasum -a 256 "$binary" | cut -d ' ' -f 1); mode=$(stat -f %Lp "$binary"); owner=$(stat -f %u "$binary")
  else actual=$(sha256sum "$binary" | cut -d ' ' -f 1); mode=$(stat -c %a "$binary"); owner=$(stat -c %u "$binary"); fi
  [ "$actual" = "$expected" ] || exit 3
  [ "$mode" = 700 ] && [ "$owner" = "$(id -u)" ] || exit 3
else
  # The directory is private and owner-checked. Never overwrite an existing path.
  staging=$(mktemp "$dest/.install.XXXXXXXX")
  cp "$work/hook" "$staging"; chmod 700 "$staging"
  if ! ln "$staging" "$binary"; then rm -f "$staging"; exit 3; fi
  rm -f "$staging"
fi
if [ "$pair" = 1 ]; then "$binary" pair --invitation-stdin; fi
if ! "$binary" doctor; then
  echo 'Helper installed. Doctor could not reach a configured notification service. Finish optional notification setup on your phone.'
fi
