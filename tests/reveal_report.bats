#!/usr/bin/env bats
# После завершения скрипт открывает Finder с выделенным файлом отчёта
# (`open -R`), чтобы пользователю было удобно его отправить.

load 'lib/extract'

setup() {
  source_fns reveal_report_in_finder
  CYAN=""; RESET=""
  FLAG_NO_OPEN=0
  REVEAL_FORCE_INTERACTIVE=1
  unset CI SUDO_USER
  REPORT="$(mktemp)"
  OPEN_LOG="$(mktemp)"
  open() { echo "open $*" >> "$OPEN_LOG"; }
  sudo() { echo "sudo $*" >> "$OPEN_LOG"; }
}

teardown() {
  rm -f "$REPORT" "$OPEN_LOG"
}

@test "reveal: интерактивный запуск -> open -R с путём отчёта и подсказка" {
  run reveal_report_in_finder "$REPORT"
  [ "$status" -eq 0 ]
  [ "$(cat "$OPEN_LOG")" = "open -R $REPORT" ]
  [[ "$output" == *"Finder"* ]]
}

@test "reveal: --no-open -> Finder не открывается" {
  FLAG_NO_OPEN=1
  run reveal_report_in_finder "$REPORT"
  [ ! -s "$OPEN_LOG" ]
  [ -z "$output" ]
}

@test "reveal: в CI -> Finder не открывается" {
  CI=true
  run reveal_report_in_finder "$REPORT"
  [ ! -s "$OPEN_LOG" ]
}

@test "reveal: без TTY -> Finder не открывается" {
  REVEAL_FORCE_INTERACTIVE=0
  run reveal_report_in_finder "$REPORT" </dev/null >/dev/null
  [ ! -s "$OPEN_LOG" ]
}

@test "reveal: отчёта нет -> ничего не делает" {
  run reveal_report_in_finder "$REPORT.missing"
  [ ! -s "$OPEN_LOG" ]
}

@test "reveal: под sudo -> Finder открывается от имени пользователя" {
  id() { echo 0; }
  SUDO_USER=alice
  run reveal_report_in_finder "$REPORT"
  [ "$(cat "$OPEN_LOG")" = "sudo -u alice open -R $REPORT" ]
}

@test "reveal: open вернул ошибку -> скрипт не падает и не пишет подсказку" {
  open() { return 1; }
  run reveal_report_in_finder "$REPORT"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
