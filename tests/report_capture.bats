#!/usr/bin/env bats
# Регрессия: tcpdump под sudo переживал run_with_timeout (sudo не пересылает
# SIGTERM процессу из той же группы, что и отправитель) и продолжал дописывать
# пакеты в $OUT — они всплывали в чужих секциях отчёта ("Конфиги приложений").

load 'lib/extract'

setup() {
  source_fns run_with_timeout capture_dns_traffic
  OUT="$(mktemp)"
  TS_TAG="test"
  FAKEBIN="$(mktemp -d)"
  cat > "$FAKEBIN/tcpdump" <<'SH'
#!/bin/sh
# Бесконечный "трафик", флаг -c игнорируется — как при слабом DNS-трафике.
while :; do echo "10:35:22.576360 IP 10.0.0.1.5353 > 224.0.0.251.5353: pkt"; sleep 0.1; done
SH
  chmod +x "$FAKEBIN/tcpdump"
  PATH="$FAKEBIN:$PATH"
  # Как sudo: обёртка умирает от TERM, а дочерний процесс — нет.
  run_sudo() { sh -c '"$@" & wait' sh "$@"; }
}

teardown() {
  pkill -f "$FAKEBIN/tcpdump" 2>/dev/null || true
  rm -rf "$FAKEBIN" "$OUT"
}

@test "capture_dns_traffic: после таймаута tcpdump остановлен и больше не пишет в отчёт" {
  capture_dns_traffic 1
  grep -q 'pkt' "$OUT"
  size_before="$(wc -c < "$OUT")"
  sleep 1
  size_after="$(wc -c < "$OUT")"
  [ "$size_before" -eq "$size_after" ]
  ! pgrep -f "$FAKEBIN/tcpdump" >/dev/null
}

@test "capture_dns_traffic: PID обёртки не попадает в отчёт" {
  capture_dns_traffic 1
  ! grep -Eq '^[0-9]+$' "$OUT"
}
