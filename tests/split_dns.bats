#!/usr/bin/env bats
# Проверяет classify_dns_server_failures(): при split-DNS (домен виден только
# через VPN/utun) NXDOMAIN от локальных DNS не должен попадать в "Возможные
# проблемы" и деградировать DNS_ONLY_VERDICT, а реальные сбои — должны.

load 'lib/extract'

setup() {
  source_fns emit_fact has_fact classify_dns_server_failures
  # add_cause/add_note в скрипте однострочные — extract_fn их не вытащит.
  add_cause() { CAUSES+=("$1"); }
  add_note() { NOTES+=("$1"); }
  FACTS_FILE="$(mktemp)"
  CAUSES=()
  NOTES=()
  DNS_SERVER_FAILS=()
  TEST_DOMAIN="corp.example"
  SCOPED_OK_UTUN=0
  SCOPED_OK_NONUTUN=0
}

teardown() {
  rm -f "$FACTS_FILE"
}

write_facts() {
  printf '%s\n' "$@" > "$FACTS_FILE"
}

@test "split-DNS через VPN: NXDOMAIN от локального DNS -> заметка, не проблема" {
  write_facts \
    $'1\tresolver\tsystem_resolver_ok\tyes\ttest' \
    $'1\tresolver\tscoped_probe\tresolver=1;if_index=12;iface=en0;ns=192.168.1.1;a=fail/NXDOMAIN/0;ips=-;ok=0\ttest'
  DNS_SERVER_FAILS=("192.168.1.1|NXDOMAIN")
  SCOPED_OK_UTUN=1
  classify_dns_server_failures
  [ "${#CAUSES[@]}" -eq 0 ]
  [ "${#NOTES[@]}" -eq 1 ]
  [[ "${NOTES[0]}" == *"только через VPN"* ]]
  [[ "${NOTES[0]}" == *"192.168.1.1 (en0)"* ]]
  has_fact resolver dns_server_probe_fail_unexpected 0
  has_fact resolver dns_server_probe_fail_expected 1
}

@test "TIMEOUT от DNS-сервера остаётся проблемой даже при рабочем системном резолвере" {
  write_facts $'1\tresolver\tsystem_resolver_ok\tyes\ttest'
  DNS_SERVER_FAILS=("10.0.0.1|TIMEOUT" "192.168.1.1|NXDOMAIN")
  classify_dns_server_failures
  [ "${#CAUSES[@]}" -eq 1 ]
  [[ "${CAUSES[0]}" == *"10.0.0.1"*"TIMEOUT"* ]]
  [ "${#NOTES[@]}" -eq 1 ]
  has_fact resolver dns_server_probe_fail_unexpected 1
}

@test "системный резолвер не работает -> NXDOMAIN считается проблемой" {
  write_facts $'1\tresolver\tsystem_resolver_ok\tno\ttest'
  DNS_SERVER_FAILS=("192.168.1.1|NXDOMAIN")
  classify_dns_server_failures
  [ "${#CAUSES[@]}" -eq 1 ]
  [ "${#NOTES[@]}" -eq 0 ]
  has_fact resolver dns_server_probe_fail_expected 0
}

@test "нет отказов -> ни проблем, ни заметок (и без падения на пустом массиве под set -u)" {
  write_facts $'1\tresolver\tsystem_resolver_ok\tyes\ttest'
  set -u
  classify_dns_server_failures
  [ "${#CAUSES[@]}" -eq 0 ]
  [ "${#NOTES[@]}" -eq 0 ]
}
