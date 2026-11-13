#!/bin/sh
# Tests the bootstrap script served at /pair (site/pair.sh.tmpl).
#
# Fake curl/uname/id stand in for the real commands, so nothing here uses the
# network or touches the real ~/.shinphony-agent. The script only runs its
# install path when it can open a terminal, so interactive cases run under a
# pseudo-terminal (`script`) and the "no terminal" case runs in a new session
# with no controlling terminal (perl's setsid).
set -u

here=$(cd "$(dirname "$0")" && pwd)
template=$here/../pair.sh.tmpl
work=$(mktemp -d "${TMPDIR:-/tmp}/shinphony-pair-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

passed=0
failed=0
ok() { passed=$((passed + 1)); printf 'ok   %s\n' "$1"; }
not_ok() { failed=$((failed + 1)); printf 'FAIL %s%s\n' "$1" "${2:+ ($2)}"; }

if command -v shasum >/dev/null 2>&1; then
  digest_of() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  digest_of() { sha256sum "$1" | cut -d ' ' -f 1; }
fi
if [ "$(uname -s)" = Darwin ]; then
  mode_of() { stat -f %Lp "$1"; }
  script_kind=bsd
else
  mode_of() { stat -c %a "$1"; }
  script_kind=util
fi

# --- fake commands -------------------------------------------------------

fakebin=$work/bin
mkdir -p "$fakebin"
cat > "$fakebin/id" <<'EOF'
#!/bin/sh
[ "${FAKE_ROOT:-0}" = 1 ] && { echo 0; exit 0; }
command -p id "$@"
EOF
cat > "$fakebin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf '%s\n' "${FAKE_OS:-$(command -p uname -s)}" ;;
  -m) printf '%s\n' "${FAKE_ARCH:-$(command -p uname -m)}" ;;
  *) command -p uname "$@" ;;
esac
EOF
cat > "$fakebin/curl" <<'EOF'
#!/bin/sh
out=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    --proto|--connect-timeout|--max-time|--max-filesize) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "${FAKE_CURL_LOG:-/dev/null}"
[ "${FAKE_CURL_FAIL:-0}" = 0 ] || { printf '%s\n' 'curl: (22) The requested URL returned error: 404' >&2; exit 22; }
[ -n "$out" ] || exit 2
cp "${FAKE_PAYLOAD:?FAKE_PAYLOAD is not set}" "$out"
EOF
chmod +x "$fakebin"/*

# The "helper" the fake curl downloads / the fake installed helper.
payload=$work/helper
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "${HELPER_LOG:-/dev/null}"\necho FAKE_PAIR\n' > "$payload"
chmod +x "$payload"
digest=$(digest_of "$payload")

mkdir -p "$work/tmp"

build_script() { # build_script <hash> [download base] -> filled script on stdout
  sed -e "s#@@DARWIN_ARM64@@#$1#g" -e "s#@@DARWIN_AMD64@@#$1#g" \
      -e "s#@@LINUX_ARM64@@#$1#g" -e "s#@@LINUX_AMD64@@#$1#g" \
      -e "s#@@SEQUENCE@@#2026111201#g" \
      -e "s#@@DOWNLOAD_BASE@@#${2:-https://downloads.potafree.net}#g" "$template"
}

script=$work/pair.sh
build_script "$digest" > "$script"
chmod +x "$script"

# --- runners -------------------------------------------------------------

runs=0
run_id() { runs=$((runs + 1)); printf '%s' "$runs"; }

# run_plain <script> <home> [VAR=value ...]
run_plain() {
  script_path=$1; home=$2; shift 2
  id=$(run_id)
  code_file=$work/code.$id
  out_file=$work/out.$id
  env -i PATH="$fakebin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" TMPDIR="$work/tmp" \
    FAKE_PAYLOAD="$payload" PAIR_SCRIPT="$script_path" PAIR_CODE="$code_file" \
    "$@" sh "$script_path" > "$out_file" 2>&1
  run_code=$?
  run_out=$(cat "$out_file")
}

# run_tty <script> <home> [VAR=value ...] — same, under a pseudo-terminal.
run_tty() {
  script_path=$1; home=$2; shift 2
  id=$(run_id)
  code_file=$work/code.$id
  out_file=$work/out.$id
  inner='sh "$PAIR_SCRIPT"; printf "%s" $? > "$PAIR_CODE"'
  if [ "$script_kind" = bsd ]; then
    env -i PATH="$fakebin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" TMPDIR="$work/tmp" \
      FAKE_PAYLOAD="$payload" PAIR_SCRIPT="$script_path" PAIR_CODE="$code_file" \
      "$@" script -q /dev/null sh -c "$inner" < /dev/null > "$out_file" 2>&1
  else
    env -i PATH="$fakebin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" TMPDIR="$work/tmp" \
      FAKE_PAYLOAD="$payload" PAIR_SCRIPT="$script_path" PAIR_CODE="$code_file" \
      "$@" script -q -e -c "$inner" /dev/null < /dev/null > "$out_file" 2>&1
  fi
  run_code=$(cat "$code_file" 2>/dev/null || echo missing)
  run_out=$(cat "$out_file")
}

# run_no_tty <script> <home> [VAR=value ...] — new session, no /dev/tty.
run_no_tty() {
  script_path=$1; home=$2; shift 2
  id=$(run_id)
  out_file=$work/out.$id
  env -i PATH="$fakebin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" TMPDIR="$work/tmp" \
    FAKE_PAYLOAD="$payload" PAIR_SCRIPT="$script_path" "$@" \
    perl -MPOSIX -e 'POSIX::setsid() or die "setsid: $!"; my $status = system("sh", $ENV{PAIR_SCRIPT}); exit($status == -1 ? 127 : $status >> 8)' \
    < /dev/null > "$out_file" 2>&1
  run_code=$?
  run_out=$(cat "$out_file")
}

home_for() {
  dir=$work/home.$1
  mkdir -m 700 "$dir"
  printf '%s' "$dir"
}

expect_code() { if [ "$run_code" = "$2" ]; then ok "$1"; else not_ok "$1" "exit $run_code, want $2; output: $run_out"; fi; }
expect_text() { case $run_out in *"$2"*) ok "$1" ;; *) not_ok "$1" "missing [$2]; output: $run_out" ;; esac; }
expect_file() { if [ -f "$2" ]; then ok "$1"; else not_ok "$1" "no file $2"; fi; }
expect_no_file() { if [ -e "$2" ] || [ -L "$2" ]; then not_ok "$1" "unexpected $2"; else ok "$1"; fi; }
expect_empty_dir() {
  if [ -d "$2" ] && [ -z "$(ls -A "$2" 2>/dev/null)" ]; then ok "$1"; else not_ok "$1" "expected empty $2"; fi
}

default_path=/usr/bin:/bin:/usr/sbin:/sbin
# The script picks its stat/shasum flavour from uname -s, so only the
# architecture is faked: the host OS must stay real for those commands.
if [ "$(uname -s)" = Darwin ]; then label='macOS arm64'; test_arch=arm64; test_platform=darwin-arm64; else label='Linux arm64'; test_arch=aarch64; test_platform=linux-arm64; fi

# --- the template itself -------------------------------------------------

if [ "$(wc -c < "$template" | tr -d ' ')" -lt 8192 ]; then ok 'template is under 8 KiB'; else not_ok 'template is under 8 KiB'; fi
if sh -n "$template"; then ok 'template parses with sh -n'; else not_ok 'template parses with sh -n'; fi
if sh -n "$script"; then ok 'filled script parses with sh -n'; else not_ok 'filled script parses with sh -n'; fi
case $(cat "$script") in *'@@'*) not_ok 'filled script has no placeholder left' ;; *) ok 'filled script has no placeholder left' ;; esac
if grep -q -- '--progress-bar' "$script" && ! grep -q -- '--silent' "$script"; then
  ok 'the download shows progress'
else
  not_ok 'the download shows progress'
fi
if [ "$(wc -c < "$script" | tr -d ' ')" -lt 8192 ]; then ok 'filled script is under 8 KiB'; else not_ok 'filled script is under 8 KiB'; fi

# --- refusals before any download ---------------------------------------

home=$(home_for root)
log=$work/curl.root
run_plain "$script" "$home" FAKE_ROOT=1 FAKE_CURL_LOG="$log"
expect_code 'root is refused' 2
expect_text 'root refusal explains sudo' 'without sudo'
expect_no_file 'root refusal writes nothing' "$home/.shinphony-agent"
[ -s "$log" ] && not_ok 'root refusal never downloads' || ok 'root refusal never downloads'

home=$(home_for unsupported)
log=$work/curl.unsupported
run_plain "$script" "$home" FAKE_OS=FreeBSD FAKE_CURL_LOG="$log"
expect_code 'unsupported OS is refused' 2
expect_text 'unsupported OS points at the phone command' 'On Windows use Shinphony -> Add server'
expect_no_file 'unsupported OS writes nothing' "$home/.shinphony-agent"
[ -s "$log" ] && not_ok 'unsupported OS never downloads' || ok 'unsupported OS never downloads'

home=$(home_for notty)
log=$work/curl.notty
run_no_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG="$log"
expect_code 'no terminal exits 2' 2
expect_text 'no terminal tells the user to open one' 'Run this in a terminal'
expect_no_file 'no terminal writes nothing' "$home/.shinphony-agent"
[ -s "$log" ] && not_ok 'no terminal never downloads' || ok 'no terminal never downloads'

bad=$work/bad-hash.sh
build_script 'not-a-verified-hash' > "$bad"
home=$(home_for badhash)
run_plain "$bad" "$home" FAKE_ARCH="$test_arch"
expect_code 'a malformed embedded hash is refused' 3
expect_text 'malformed hash points at a fresh installer' 'not from a verified release'

plain_http=$work/plain-http.sh
build_script "$digest" 'http://example.com' > "$plain_http"
home=$(home_for http)
run_plain "$plain_http" "$home" FAKE_ARCH="$test_arch"
expect_code 'a non-loopback http download base is refused' 3

# --- install failures ----------------------------------------------------

home=$(home_for download-fail)
log=$work/curl.fail
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG="$log" FAKE_CURL_FAIL=1
expect_code 'a failed download exits 4' 4
expect_text 'a failed download says nothing was installed' 'Download failed. Nothing installed.'
if grep -q "agent/targets/agent/$digest.$test_platform" "$log" 2>/dev/null; then
  ok 'the download URL is the verified target'
else
  not_ok 'the download URL is the verified target' "$(cat "$log" 2>/dev/null)"
fi
expect_empty_dir 'a failed download leaves no helper' "$home/.shinphony-agent"

other=$work/other-helper
printf '#!/bin/sh\nexit 0\n' > "$other"
home=$(home_for mismatch)
log=$work/curl.mismatch
run_tty "$script" "$home" FAKE_ARCH=x86_64 FAKE_CURL_LOG="$log" FAKE_PAYLOAD="$other"
expect_code 'a hash mismatch exits 3' 3
expect_text 'a hash mismatch says nothing was installed' 'does not match the verified release. Nothing installed.'
expect_empty_dir 'a hash mismatch leaves no helper or staging file' "$home/.shinphony-agent"

home=$(home_for unsafe)
mkdir -m 755 "$home/.shinphony-agent"
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG=/dev/null
expect_code 'an unsafe directory is refused' 3
expect_text 'an unsafe directory is explained' 'Unsafe helper directory'

home=$(home_for linkdir)
mkdir -m 700 "$work/elsewhere"
ln -s "$work/elsewhere" "$home/.shinphony-agent"
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG=/dev/null
expect_code 'a linked helper directory is refused' 3
expect_text 'a linked helper directory is explained' 'linked ~/.shinphony-agent'

home=$(home_for foreign)
mkdir -m 700 "$home/.shinphony-agent"
printf '#!/bin/sh\nexit 0\n' > "$home/.shinphony-agent/shinphony-hook-$digest"
chmod 700 "$home/.shinphony-agent/shinphony-hook-$digest"
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG=/dev/null
expect_code 'a different helper at the target path is never overwritten' 3
expect_text 'the different helper is explained' 'not this verified release'

home=$(home_for symlink)
mkdir -m 700 "$home/.shinphony-agent"
ln -s "$other" "$home/.shinphony-agent/shinphony-hook-$digest"
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG=/dev/null
expect_code 'a symlink at the target path is refused' 3
expect_text 'the symlink is explained' 'Refusing to replace an unexpected file'

# --- installs and reuse --------------------------------------------------

home=$(home_for install)
log=$work/curl.install
helper_log=$work/helper.install
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG="$log" HELPER_LOG="$helper_log" TMPDIR="$work/tmp"
expect_code 'a verified helper installs' 0
expect_text 'the platform is named' "installing helper ($label)"
expect_text 'the script says pairing is starting' 'Shinphony: starting pairing…'
case $run_out in
  *'Scan the code below'*) not_ok 'the script leaves the scan instruction to the Hook' 'the script printed its own scan instruction' ;;
  *) ok 'the script leaves the scan instruction to the Hook' ;;
esac
expect_text 'pair runs on the terminal' 'FAKE_PAIR'
installed=$home/.shinphony-agent/shinphony-hook-$digest
expect_file 'the helper is installed under its hash' "$installed"
if [ "$(digest_of "$installed")" = "$digest" ]; then ok 'the installed helper matches the embedded hash'; else not_ok 'the installed helper matches the embedded hash'; fi
if [ "$(mode_of "$installed")" = 700 ]; then ok 'the installed helper is mode 700'; else not_ok 'the installed helper is mode 700'; fi
if [ -f "$helper_log" ] && [ "$(cat "$helper_log")" = 'pair' ]; then ok 'the installed helper is exec-ed as "pair"'; else not_ok 'the installed helper is exec-ed as "pair"' "$(cat "$helper_log" 2>/dev/null)"; fi
if [ -z "$(find "$home/.shinphony-agent" -name '.install.*' 2>/dev/null)" ]; then ok 'no staging file is left behind'; else not_ok 'no staging file is left behind'; fi
leftover=$(find "$work/tmp" -maxdepth 1 -name 'shinphony-pair.*' 2>/dev/null)
if [ -z "$leftover" ]; then ok 'the download temp directory is removed'; else not_ok 'the download temp directory is removed' "$leftover"; fi

downloads=$( [ -f "$log" ] && wc -l < "$log" | tr -d ' ' || echo 0 )
run_tty "$script" "$home" FAKE_ARCH="$test_arch" FAKE_CURL_LOG="$log" HELPER_LOG="$helper_log" TMPDIR="$work/tmp"
expect_code 'a second run reuses the installed helper' 0
expect_text 'reuse is reported' "reusing the installed helper ($label)"
after=$( [ -f "$log" ] && wc -l < "$log" | tr -d ' ' || echo 0 )
if [ "$after" = "$downloads" ]; then ok 'a second run downloads nothing'; else not_ok 'a second run downloads nothing' "$downloads -> $after"; fi
if [ "$( [ -f "$helper_log" ] && wc -l < "$helper_log" | tr -d ' ' || echo 0 )" = 2 ]; then ok 'the reused helper still runs pair'; else not_ok 'the reused helper still runs pair'; fi

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" = 0 ]