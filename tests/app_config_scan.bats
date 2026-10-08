#!/usr/bin/env bats
# Шаг 7/12 (поиск конфигов приложений в ~/Library): обход не должен заходить в
# системные/TCC-папки (из-за этого macOS спрашивала доступ к Apple Music/медиатеке),
# а если macOS всё же не пустила в какие-то папки — отчёт помечается как неполный.

load 'lib/extract'

APPS_RE='clash|wireguard|tailscale'

setup() {
  source_fns emit_fact has_fact join_by_semicolon scan_app_config_paths terminal_app_name tcc_recovery_hint report_app_scan_access print_app_scan_denied print_app_scan_denied_paths request_app_scan_access info warn ok
  # Цвета отключены, чтобы проверять чистый текст.
  BOLD="" CYAN="" GREEN="" YELLOW="" RED="" MAGENTA="" DETAIL="" RESET=""
  # Однострочные определения из скрипта extract_fn не вытащит — дублируем.
  add_coverage_gap() { COVERAGE_GAPS+=("$1"); }
  APP_SCAN_PRUNE_NAMES=('com.apple.*' AddressBook Calendars CallHistoryDB CallHistoryTransactions CloudDocs FaceTime Knowledge Mail Messages MobileSync Safari)
  COVERAGE_GAPS=()
  FACTS_FILE="$(mktemp)"
  OUT="$(mktemp)"
  ROOT="$(mktemp -d)"
  mkdir -p "$ROOT/Application Support/ClashX/profiles" \
           "$ROOT/Application Support/com.apple.Music/clash-inside" \
           "$ROOT/Application Support/AddressBook/wireguard-inside" \
           "$ROOT/Application Support/Vendor/Tailscale"
}

teardown() {
  chmod -R u+rwx "$ROOT" 2>/dev/null || true
  rm -rf "$ROOT" "$FACTS_FILE" "$OUT"
}

fact_value() {
  awk -F'\t' -v l="$1" -v k="$2" '$2==l && $3==k {v=$4} END{print v}' "$FACTS_FILE"
}

@test "scan: находит конфиги приложений, в т.ч. на глубине 2 под несовпадающей папкой" {
  scan_app_config_paths "$APPS_RE" "$ROOT"
  [[ "$APP_CONFIG_PATHS" == *"/ClashX"* ]]
  [[ "$APP_CONFIG_PATHS" == *"/Vendor/Tailscale"* ]]
  [ "${#APP_SCAN_DENIED[@]}" -eq 0 ]
}

@test "scan: не заходит в com.apple.* и TCC-папки (источник запроса Apple Music/медиатеки)" {
  scan_app_config_paths "$APPS_RE|com\.apple\.Music|AddressBook" "$ROOT"
  [[ "$APP_CONFIG_PATHS" != *"clash-inside"* ]]
  [[ "$APP_CONFIG_PATHS" != *"wireguard-inside"* ]]
  # Имена самих папок остаются в выводе, как и раньше.
  [[ "$APP_CONFIG_PATHS" == *"/com.apple.Music"* ]]
  [[ "$APP_CONFIG_PATHS" == *"/AddressBook"* ]]
}

@test "scan: папки без доступа попадают в APP_SCAN_DENIED" {
  [ "$(id -u)" -ne 0 ] || skip "root игнорирует права доступа"
  mkdir -p "$ROOT/Application Support/Locked/clash"
  chmod 000 "$ROOT/Application Support/Locked"
  scan_app_config_paths "$APPS_RE" "$ROOT"
  [ "${#APP_SCAN_DENIED[@]}" -eq 1 ]
  [ "${APP_SCAN_DENIED[0]}" = "$ROOT/Application Support/Locked" ]
}

@test "report: без отказов — access=ok, отчёт не помечается неполным" {
  APP_SCAN_DENIED=()
  report_app_scan_access
  grep -q '^>> APP_CONFIG_SCAN_ACCESS$' "$OUT"
  grep -q '^access=ok$' "$OUT"
  [ "$(fact_value coverage app_config_scan)" = "complete" ]
  [ "${#COVERAGE_GAPS[@]}" -eq 0 ]
}

@test "report: при отказе macOS — access=denied, факт incomplete, подсказка про «Полный доступ к диску»" {
  APP_SCAN_DENIED=("/Users/u/Library/Application Support/X" "/Users/u/Library/Caches/Y")
  __CFBundleIdentifier=com.apple.Terminal TERM_PROGRAM=Apple_Terminal report_app_scan_access
  grep -q '^access=denied denied_count=2$' "$OUT"
  grep -q '^denied: /Users/u/Library/Caches/Y$' "$OUT"
  grep -q 'Полный доступ к диску» → включить Terminal' "$OUT"
  grep -q 'tccutil reset All com.apple.Terminal' "$OUT"
  ! grep -q 'Apple_Terminal' "$OUT"
  [ "$(fact_value coverage app_config_scan)" = "incomplete" ]
  [ "${#COVERAGE_GAPS[@]}" -eq 1 ]
  [[ "${COVERAGE_GAPS[0]}" == *"Шаг 7/12"*"не дала доступ"* ]]
  [[ "${COVERAGE_GAPS[0]}" == *"включить Terminal"* ]]
}

@test "report: длинный список отказов сокращается" {
  APP_SCAN_DENIED=()
  for i in $(seq 1 12); do APP_SCAN_DENIED+=("/p/$i"); done
  report_app_scan_access
  [ "$(grep -c '^denied: /p/' "$OUT")" -eq 10 ]
  grep -q '^denied: ... и ещё 2$' "$OUT"
  [[ "${COVERAGE_GAPS[0]}" == *"(всего 12)"* ]]
}

@test "console: показывает недоступные папки (с ~ вместо \$HOME) и подсказку; без отказов — молчит" {
  stop_step_spinner() { :; }
  YELLOW=""; RESET=""
  APP_SCAN_DENIED=()
  run print_app_scan_denied
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  APP_SCAN_DENIED=("$HOME/Library/Caches/X" "/Library/Y")
  TERM_PROGRAM=Apple_Terminal run print_app_scan_denied
  [[ "$output" == *"(2 шт.)"* ]]
  [[ "$output" == *"~/Library/Caches/X"* ]]
  [[ "$output" != *"\\~"* ]]
  [[ "$output" == *"/Library/Y"* ]]
  [[ "$output" == *"включить Terminal"* ]]
  [[ "$output" != *"Apple_Terminal"* ]]
}

@test "terminal_app_name: Apple_Terminal -> Terminal, iTerm.app -> iTerm" {
  [ "$(TERM_PROGRAM=Apple_Terminal terminal_app_name)" = "Terminal" ]
  [ "$(TERM_PROGRAM=iTerm.app terminal_app_name)" = "iTerm" ]
  [ "$(TERM_PROGRAM= terminal_app_name)" = "Terminal" ]
}

# --- Интерактивный запрос доступа -------------------------------------------

setup_request() {
  [ "$(id -u)" -ne 0 ] || skip "root игнорирует права доступа"
  stop_step_spinner() { :; }
  YELLOW=""; RESET=""; CYAN=""
  FLAG_YES=0
  APP_SCAN_FORCE_INTERACTIVE=1
  APP_SCAN_ACCESS_REQUESTED=0
  OPEN_LOG="$(mktemp)"
  LOCKED="$ROOT/Application Support/Locked"
  mkdir -p "$LOCKED/clash"
  chmod 000 "$LOCKED"
  # fd 3 занят самим bats — ввод пользователя читаем из fd 4.
  exec 4</dev/null
  APP_SCAN_INPUT_FD=4
}

@test "request: согласие -> открываются настройки «Полный доступ к диску», после выдачи доступа поиск повторяется" {
  setup_request
  ask_yes_no() { return 0; }
  # «Пользователь выдал доступ» в настройках.
  open() { echo "$1" >> "$OPEN_LOG"; chmod 755 "$LOCKED"; }
  scan_app_config_paths "$APPS_RE" "$ROOT"
  [ "${#APP_SCAN_DENIED[@]}" -eq 1 ]
  request_app_scan_access "$APPS_RE" "$ROOT" > "$OUT.console"
  grep -q 'Privacy_AllFiles' "$OPEN_LOG"
  [ "${#APP_SCAN_DENIED[@]}" -eq 0 ]
  [[ "$APP_CONFIG_PATHS" == *"/Locked/clash"* ]]
  grep -q 'Доступ получен' "$OUT.console"
  rm -f "$OPEN_LOG" "$OUT.console"
}

@test "request: доступ так и не выдан -> подсказка перезапустить терминал, отказ остаётся" {
  setup_request
  ask_yes_no() { return 0; }
  open() { echo "$1" >> "$OPEN_LOG"; }
  scan_app_config_paths "$APPS_RE" "$ROOT"
  TERM_PROGRAM=Apple_Terminal request_app_scan_access "$APPS_RE" "$ROOT" > "$OUT.console"
  [ "${#APP_SCAN_DENIED[@]}" -eq 1 ]
  grep -q 'после перезапуска Terminal' "$OUT.console"
  rm -f "$OPEN_LOG" "$OUT.console"
}

@test "request: отказ пользователя -> настройки не открываются" {
  setup_request
  ask_yes_no() { return 1; }
  open() { echo "$1" >> "$OPEN_LOG"; }
  scan_app_config_paths "$APPS_RE" "$ROOT"
  request_app_scan_access "$APPS_RE" "$ROOT" >/dev/null
  [ ! -s "$OPEN_LOG" ]
  [ "${#APP_SCAN_DENIED[@]}" -eq 1 ]
  rm -f "$OPEN_LOG"
}

@test "request: --yes (неинтерактивно) -> ничего не спрашивает и не ждёт" {
  setup_request
  FLAG_YES=1
  ask_yes_no() { echo ASKED; return 0; }
  open() { echo "$1" >> "$OPEN_LOG"; }
  scan_app_config_paths "$APPS_RE" "$ROOT"
  run request_app_scan_access "$APPS_RE" "$ROOT"
  [ -z "$output" ]
  [ ! -s "$OPEN_LOG" ]
  rm -f "$OPEN_LOG"
}
