#!/usr/bin/env bats
# Проверяет ip_is_private() и run_cross_resolver_consistency_check() на
# синтетических фактах — без сети, без реального dig/curl. Реальные внешние
# пробы (run_external_dns_probes/doh_probe) требуют сети и покрываются e2e-тестом
# в cli_flags.bats ("full non-interactive run"), где просто проверяется, что
# новые секции отчёта появляются и скрипт не падает независимо от того, доступны
# ли независимые резолверы в среде CI.

load 'lib/extract'

setup() {
  source_fns emit_fact has_fact ip_is_private run_cross_resolver_consistency_check
  FACTS_FILE="$(mktemp)"
  OUT="$(mktemp)"
}

teardown() {
  rm -f "$FACTS_FILE" "$OUT"
}

write_facts() {
  printf '%s\n' "$@" > "$FACTS_FILE"
}

@test "ip_is_private: RFC1918, loopback and CGNAT are private" {
  ip_is_private 10.0.0.1
  ip_is_private 192.168.1.1
  ip_is_private 172.16.5.5
  ip_is_private 172.31.255.255
  ip_is_private 127.0.0.1
  ip_is_private 100.64.0.1
}

@test "ip_is_private: public IPs are not private" {
  ! ip_is_private 93.184.216.34
  ! ip_is_private 1.1.1.1
  ! ip_is_private 8.8.8.8
}

@test "ip_is_private: 172.32.x.x is public (just outside 172.16/12)" {
  ! ip_is_private 172.32.0.1
}

@test "ip_is_private: empty/dash/garbage is treated as not-private (no false positives)" {
  ! ip_is_private ""
  ! ip_is_private "-"
  ! ip_is_private "not-an-ip"
}

@test "cross-resolver check: all resolvers agree -> no mismatch" {
  write_facts \
    $'1\tresolver\tdns_server_probe\tserver=192.168.1.1;rr=A;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\tresolver\tsystem_probe\trr=A;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\texternal\tdns_probe\tserver=1.1.1.1;transport=udp;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest'
  run_cross_resolver_consistency_check
  [ "$(awk -F'\t' '$3=="cross_mismatch_count"{v=$4} END{print v}' "$FACTS_FILE")" = "0" ]
  [ "$(awk -F'\t' '$3=="cross_consensus_ip"{v=$4} END{print v}' "$FACTS_FILE")" = "93.184.216.34" ]
}

@test "cross-resolver check: system resolver returns private IP while independent ones agree -> private-IP suspect" {
  write_facts \
    $'1\tresolver\tsystem_probe\trr=A;result=ok;reason=NOERROR;answers=1;ips=10.10.10.10\ttest' \
    $'1\texternal\tdns_probe\tserver=1.1.1.1;transport=udp;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\texternal\tdns_probe\tserver=8.8.8.8;transport=udp;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest'
  run_cross_resolver_consistency_check
  [ "$(awk -F'\t' '$3=="cross_mismatch_count"{v=$4} END{print v}' "$FACTS_FILE")" = "1" ]
  [ "$(awk -F'\t' '$3=="cross_private_ip_suspect_count"{v=$4} END{print v}' "$FACTS_FILE")" = "1" ]
}

@test "cross-resolver check: mismatch confined to a utun scoped resolver -> route flag set, interceptor flag not set" {
  write_facts \
    $'1\tresolver\tsystem_probe\trr=A;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\texternal\tdns_probe\tserver=1.1.1.1;transport=udp;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\tresolver\tscoped_probe\tresolver=1;if_index=5;iface=utun4;ns=100.64.0.1;a=ok/NOERROR/1;ips=203.0.113.9;ok=1\ttest'
  run_cross_resolver_consistency_check
  [ "$(awk -F'\t' '$2=="route"&&$3=="cross_mismatch_utun_only"{v=$4} END{print v}' "$FACTS_FILE")" = "yes" ]
  [ "$(awk -F'\t' '$2=="interceptor"&&$3=="cross_mismatch_nonutun_only"{v=$4} END{print v}' "$FACTS_FILE")" = "no" ]
}

@test "cross-resolver check: mismatch confined to a non-utun scoped resolver while VPN scoped resolver agrees -> interceptor flag set, route flag not set" {
  write_facts \
    $'1\tresolver\tsystem_probe\trr=A;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\texternal\tdns_probe\tserver=1.1.1.1;transport=udp;result=ok;reason=NOERROR;answers=1;ips=93.184.216.34\ttest' \
    $'1\tresolver\tscoped_probe\tresolver=1;if_index=5;iface=utun4;ns=100.64.0.1;a=ok/NOERROR/1;ips=93.184.216.34;ok=1\ttest' \
    $'1\tresolver\tscoped_probe\tresolver=2;if_index=7;iface=en0;ns=192.168.1.1;a=ok/NOERROR/1;ips=10.10.10.10;ok=1\ttest'
  run_cross_resolver_consistency_check
  [ "$(awk -F'\t' '$2=="interceptor"&&$3=="cross_mismatch_nonutun_only"{v=$4} END{print v}' "$FACTS_FILE")" = "yes" ]
  [ "$(awk -F'\t' '$2=="route"&&$3=="cross_mismatch_utun_only"{v=$4} END{print v}' "$FACTS_FILE")" = "no" ]
}

@test "cross-resolver check: no successful probes at all -> consensus is '-', no crash, zero mismatches" {
  write_facts
  run_cross_resolver_consistency_check
  [ "$(awk -F'\t' '$3=="cross_consensus_ip"{v=$4} END{print v}' "$FACTS_FILE")" = "-" ]
  [ "$(awk -F'\t' '$3=="cross_mismatch_count"{v=$4} END{print v}' "$FACTS_FILE")" = "0" ]
}
