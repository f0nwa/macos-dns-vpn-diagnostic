#!/usr/bin/env bats
# Детект DPI-обходов (zapret и аналоги) и перенаправления трафика в PF-анкерах.
# Повод: отчёт, где ZapretMac (Flowseal) через анкер com.apple/zapret-macos
# заворачивал весь TCP 80/443 в utun50 и отправлял его через BPF прямо на шлюз
# en0 — мимо корпоративного VPN (utun8). DNS при этом был PASS, а connect к
# внутреннему адресу висел до таймаута, и скрипт этого не замечал.

load 'lib/extract'

FIXTURES="$BATS_TEST_DIRNAME/fixtures"

setup() {
  source_fns emit_fact has_fact join_by_semicolon parse_pf_redirect_rules dpi_bypass_signatures detect_dpi_bypass
  # add_cause/add_note в скрипте однострочные — extract_fn их не вытащит.
  add_cause() { CAUSES+=("$1"); }
  add_note() { NOTES+=("$1"); }
  FACTS_FILE="$(mktemp)"
  CAUSES=()
  NOTES=()
}

teardown() {
  rm -f "$FACTS_FILE"
}

fact_value() {
  awk -F'\t' -v l="$1" -v k="$2" '$2==l && $3==k {v=$4} END{print v}' "$FACTS_FILE"
}

@test "PF: ZapretMac route-to в com.apple/zapret-macos распознаётся (одна запись на анкер/цель)" {
  run parse_pf_redirect_rules < "$FIXTURES/pf_anchors_zapretmac.txt"
  [ "$status" -eq 0 ]
  [ "$output" = "com.apple/zapret-macos|route-to|utun50 10.77.0.2" ]
}

@test "PF: upstream zapret (tpws) — rdr на 127.0.0.1:988 и route-to lo0" {
  run parse_pf_redirect_rules < "$FIXTURES/pf_anchors_zapret_tpws.txt"
  [ "$status" -eq 0 ]
  [[ "$output" == *"zapret|rdr|127.0.0.1 port 988"* ]]
  [[ "$output" == *"zapret|route-to|lo0 127.0.0.1"* ]]
  [ "$(printf '%s\n' "$output" | wc -l | tr -d ' ')" -eq 2 ]
}

@test "PF: только штатные анкеры Apple (block, без перенаправлений) -> пусто" {
  run parse_pf_redirect_rules < "$FIXTURES/pf_anchors_apple_only.txt"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "ZapretMac запущен (launchd PID + utunws + анкер) -> активный DPI-обход, причина с командой остановки" {
  launchd=$'/Library/LaunchDaemons/io.github.flowseal.zapretmac.plist\n812\t0\tio.github.flowseal.zapretmac'
  procs=$'launchd\nutunws\nmDNSResponder'
  paths='/Library/Application Support/ZapretMac'
  redirects='com.apple/zapret-macos|route-to|utun50 10.77.0.2'
  detect_dpi_bypass "$launchd" "$procs" "$paths" "$redirects"
  [ "$(fact_value interceptor dpi_bypass_present)" = "yes" ]
  [ "$(fact_value interceptor dpi_bypass_active)" = "yes" ]
  tool="$(fact_value interceptor dpi_bypass_tool)"
  [[ "$tool" == *"id=zapretmac;"* ]]
  [[ "$tool" == *"active=yes"* ]]
  [[ "$tool" == *"pf_anchor"* ]]
  [ "${#CAUSES[@]}" -eq 1 ]
  [[ "${CAUSES[0]}" == *"ZapretMac"* ]]
  [[ "${CAUSES[0]}" == *"utun50"* ]]
  [[ "${CAUSES[0]}" == *"stop.sh"* ]]
  # Перенаправление объяснено конкретным инструментом -> отдельной «безымянной» причины нет.
  [ "$(fact_value policy pf_traffic_redirect)" = "yes" ]
  [ "$(fact_value policy pf_traffic_redirect_unattributed)" = "no" ]
}

@test "ZapretMac лишь установлен (plist есть, PID нет, процесса и анкера нет) -> заметка, не проблема" {
  launchd=$'/Library/LaunchDaemons/io.github.flowseal.zapretmac.plist\n-\t0\tio.github.flowseal.zapretmac'
  detect_dpi_bypass "$launchd" "launchd" "/Library/Application Support/ZapretMac" ""
  [ "$(fact_value interceptor dpi_bypass_present)" = "yes" ]
  [ "$(fact_value interceptor dpi_bypass_active)" = "no" ]
  [ "${#CAUSES[@]}" -eq 0 ]
  [ "${#NOTES[@]}" -eq 1 ]
  [[ "${NOTES[0]}" == *"ZapretMac"* ]]
}

@test "ярлык ZapretMac не определяется дополнительно как upstream zapret" {
  detect_dpi_bypass $'812\t0\tio.github.flowseal.zapretmac' "utunws" "" ""
  [ "$(awk -F'\t' '$3=="dpi_bypass_tool"' "$FACTS_FILE" | wc -l | tr -d ' ')" -eq 1 ]
}

@test "upstream zapret: процесс tpws + rdr в анкере zapret -> активный, id=zapret" {
  detect_dpi_bypass "" $'tpws\nlaunchd' "/opt/zapret" $'zapret|rdr|127.0.0.1 port 988'
  [ "$(fact_value interceptor dpi_bypass_active)" = "yes" ]
  [[ "$(fact_value interceptor dpi_bypass_tool)" == *"id=zapret;"* ]]
  [[ "${CAUSES[0]}" == *"/opt/zapret/init.d/macos/zapret stop"* ]]
}

@test "SpoofDPI и ByeDPI (ciadpi) распознаются по имени процесса" {
  detect_dpi_bypass "" $'spoofdpi\nciadpi' "" ""
  tools="$(awk -F'\t' '$3=="dpi_bypass_tool"{print $4}' "$FACTS_FILE")"
  [[ "$tools" == *"id=spoofdpi;"* ]]
  [[ "$tools" == *"id=byedpi;"* ]]
  [ "${#CAUSES[@]}" -eq 2 ]
}

@test "без ложных срабатываний на системный шум (store/tor-подстроки, Apple-демоны)" {
  launchd=$'-\t0\tcom.apple.storeuid\n710\t0\tcom.apple.amsondevicestoraged\n60616\t0\tapplication.ru.cryptopro.ngateclient.1.2'
  detect_dpi_bypass "$launchd" $'storekitagent\nmonitor\nngateclient' "" ""
  [ "$(fact_value interceptor dpi_bypass_present)" = "no" ]
  [ "$(fact_value interceptor dpi_bypass_active)" = "no" ]
  [ "$(fact_value policy pf_traffic_redirect)" = "no" ]
  [ "${#CAUSES[@]}" -eq 0 ]
  [ "${#NOTES[@]}" -eq 0 ]
}

@test "перенаправление в неизвестном анкере -> отдельная причина, даже без известного инструмента" {
  detect_dpi_bypass "" "launchd" "" 'custom/filter|route-to|utun9 10.9.0.2'
  [ "$(fact_value interceptor dpi_bypass_present)" = "no" ]
  [ "$(fact_value policy pf_traffic_redirect)" = "yes" ]
  [ "$(fact_value policy pf_traffic_redirect_unattributed)" = "yes" ]
  [ "${#CAUSES[@]}" -eq 1 ]
  [[ "${CAUSES[0]}" == *"custom/filter"* ]]
  [[ "${CAUSES[0]}" == *"utun9"* ]]
}
