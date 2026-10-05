#!/usr/bin/env bats
# Регрессия: шаг «зависал» на первом кадре спиннера. Если процесс спиннера
# остановлен (SIGSTOP/SIGTTOU), kill -TERM не доставляется, и `wait` в
# stop_step_spinner блокировался навсегда.

load 'lib/extract'

setup() {
  source_fns start_step_spinner stop_step_spinner run_with_timeout
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

# Регрессия: в bash 3.2 TERM, пришедший в подоболочку сразу после fork (она
# унаследовала глобальный `trap ... TERM`), давал в консоли
# "run_pending_traps: bad value in trap_list[15]: 0x0". Спиннер и сторож
# run_with_timeout теперь гасятся только KILL — сам TERM больше не шлётся.
@test "stop_step_spinner: частые старт/стоп спиннера под глобальным trap TERM — без мусора в выводе" {
  run bash -c '
    source <(sed -n "/^start_step_spinner() {/,/^}/p; /^stop_step_spinner() {/,/^}/p" "'"$SCRIPT_UNDER_TEST"'")
    trap ":" EXIT INT TERM
    # start_step_spinner рисует только в TTY — запускаем подоболочку напрямую.
    for i in $(seq 1 100); do
      ( while :; do sleep 0.2; done ) &
      SPINNER_PID=$!
      stop_step_spinner
    done
    echo done'
  [ "$status" -eq 0 ]
  [ "$output" = "done" ]
}

@test "stop_step_spinner и run_with_timeout не шлют TERM своим служебным подпроцессам" {
  ! sed -n '/^stop_step_spinner() {/,/^}/p' "$SCRIPT_UNDER_TEST" | grep -Eq 'kill (-TERM )?"\$SPINNER_PID"'
  sed -n '/^run_with_timeout() {/,/^}/p' "$SCRIPT_UNDER_TEST" | grep -q 'kill -KILL "\$watchdog_pid"'
}

@test "run_with_timeout: быстрая команда — без мусора в выводе, код возврата сохраняется" {
  trap ':' TERM
  run run_with_timeout 5 sh -c 'exit 3'
  [ "$status" -eq 3 ]
  [ -z "$output" ]
}
