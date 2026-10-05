#!/usr/bin/env bats
# Регрессия: шаг «зависал» на первом кадре спиннера. Если процесс спиннера
# остановлен (SIGSTOP/SIGTTOU), kill -TERM не доставляется, и `wait` в
# stop_step_spinner блокировался навсегда.

load 'lib/extract'

setup() {
  source_fns stop_step_spinner
}

teardown() {
  [ -n "${SPINNER_PID:-}" ] && kill -KILL "$SPINNER_PID" 2>/dev/null || true
}

start_fake_spinner() {
  ( trap 'exit 0' TERM INT; while :; do sleep 0.2; done ) &
  SPINNER_PID=$!
  sleep 0.3
}

@test "stop_step_spinner: обычный спиннер останавливается" {
  start_fake_spinner
  pid="$SPINNER_PID"
  stop_step_spinner
  [ -z "$SPINNER_PID" ]
  ! kill -0 "$pid" 2>/dev/null
}

@test "stop_step_spinner: остановленный (SIGSTOP) спиннер не вешает скрипт" {
  start_fake_spinner
  pid="$SPINNER_PID"
  kill -STOP "$pid"
  start="$(date +%s)"
  stop_step_spinner
  [ $(( $(date +%s) - start )) -le 3 ]
  ! kill -0 "$pid" 2>/dev/null
}
