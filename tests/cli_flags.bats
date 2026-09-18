#!/usr/bin/env bats
# Проверяет неинтерактивный режим (--domain/--yes/--output), добавленный
# специально для того, чтобы скрипт можно было гонять в CI и в bats без
# участия человека за консолью.

load 'lib/extract'

setup() {
  OUT_FILE="$(mktemp -u)/ci_report.txt"
  mkdir -p "$(dirname "$OUT_FILE")"
}

teardown() {
  rm -f "$OUT_FILE"
}

@test "--help prints usage and exits 0" {
  run bash "$SCRIPT_UNDER_TEST" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage: macos-dns-test.sh"* ]]
}

@test "unknown flag is rejected with exit code 2" {
  run bash "$SCRIPT_UNDER_TEST" --nonsense </dev/null
  [ "$status" -eq 2 ]
}

@test "--domain with invalid format is rejected with exit code 2, no hang" {
  run timeout 10 bash "$SCRIPT_UNDER_TEST" --domain=notadomain --yes </dev/null
  [ "$status" -eq 2 ]
  [[ "$output" == *"Некорректный --domain"* ]]
}

@test "full non-interactive run completes and produces a well-formed report" {
  run timeout 90 bash "$SCRIPT_UNDER_TEST" --domain=example.com --yes --output="$OUT_FILE" < /dev/null
  [ "$status" -eq 0 ]
  [ -f "$OUT_FILE" ]
  grep -q '>> DNS_ONLY_RESULT' "$OUT_FILE"
  grep -q '>> E2E_RESULT' "$OUT_FILE"
  grep -q '>> PRIMARY_CLASSIFICATION' "$OUT_FILE"
  grep -q '>> EVIDENCE_MATRIX' "$OUT_FILE"
  grep -q 'PRIMARY_CLASSIFICATION=' "$OUT_FILE"
}

@test "--output writes to the exact path given, not \$(pwd)" {
  run timeout 90 bash "$SCRIPT_UNDER_TEST" --domain=example.com --yes --output="$OUT_FILE" < /dev/null
  [ "$status" -eq 0 ]
  [ -f "$OUT_FILE" ]
}
