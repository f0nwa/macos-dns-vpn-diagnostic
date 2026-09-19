#!/usr/bin/env bats
# Тестирует движок гипотез (build_hypotheses/confidence_label) macos-dns-test.sh
# на синтетических наборах фактов, не запуская сам скрипт и не трогая систему.
# Функции берутся из реального скрипта через extract_fn/source_fns (tests/lib/extract.bash),
# так что тест всегда проверяет актуальный код, а не свою копию.

load 'lib/extract'

setup() {
  source_fns join_by_semicolon has_fact add_hypothesis confidence_label build_hypotheses
  FACTS_FILE="$(mktemp)"
}

teardown() {
  rm -f "$FACTS_FILE"
}

write_facts() {
  printf '%s\n' "$@" > "$FACTS_FILE"
}

@test "no facts at all -> no hypotheses (healthy run)" {
  write_facts
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 0 ]
}

@test "resolver failure facts -> top hypothesis is resolver layer with HIGH confidence" {
  write_facts \
    $'1\tresolver\tnameserver_missing\tyes\ttest' \
    $'1\tresolver\tsystem_resolver_ok\tno\ttest' \
    $'1\tresolver\tdns_servers_all_fail\tyes\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "resolver" ]
  [ "$(confidence_label "$score")" = "HIGH" ]
}

@test "PF block facts -> top hypothesis is policy layer with HIGH confidence" {
  write_facts \
    $'1\tpolicy\tpf_enabled\tyes\ttest' \
    $'1\tpolicy\tpf_block_rules\tyes\ttest' \
    $'1\tpolicy\tpf_blocks_recent\tyes\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "policy" ]
  [ "$score" -eq 100 ]
  [ "$(confidence_label "$score")" = "HIGH" ]
}

@test "confidence_label boundaries: <40 LOW, 40-69 MED, >=70 HIGH" {
  [ "$(confidence_label 0)" = "LOW" ]
  [ "$(confidence_label 39)" = "LOW" ]
  [ "$(confidence_label 40)" = "MED" ]
  [ "$(confidence_label 69)" = "MED" ]
  [ "$(confidence_label 70)" = "HIGH" ]
  [ "$(confidence_label 100)" = "HIGH" ]
}

@test "independent external resolvers also fail (not a timeout) -> external hypothesis" {
  write_facts \
    $'1\texternal\tprobe_skipped\tno\ttest' \
    $'1\texternal\tany_ok\tno\ttest' \
    $'1\texternal\tall_timeout\tno\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "external" ]
  [ "$score" -eq 50 ]
}

@test "independent external probes all timed out -> no false 'domain blocked' hypothesis (likely just no internet)" {
  write_facts \
    $'1\texternal\tprobe_skipped\tno\ttest' \
    $'1\texternal\tany_ok\tno\ttest' \
    $'1\texternal\tall_timeout\tyes\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 0 ]
}

@test "external probe disabled by flag -> no external hypothesis even if any_ok would say no" {
  write_facts \
    $'1\texternal\tprobe_skipped\tyes\ttest' \
    $'1\texternal\tany_ok\tno\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 0 ]
}

@test "UDP:53 blocked to independent resolvers but DoH works -> external hypothesis (selective DNS-port filtering)" {
  write_facts \
    $'1\texternal\tprobe_skipped\tno\ttest' \
    $'1\texternal\tany_ok\tyes\ttest' \
    $'1\texternal\tall_timeout\tno\ttest' \
    $'1\texternal\tudp53_blocked_but_doh_ok\tyes\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "external" ]
  [ "$score" -eq 35 ]
}

@test "independent resolvers ok but system resolver fails -> interceptor hypothesis included (problem is local)" {
  # system_resolver_ok=no само по себе уже поднимает отдельную гипотезу resolver
  # (существующее правило) — здесь проверяем, что ДОПОЛНИТЕЛЬНО появляется
  # interceptor-гипотеза именно из-за контраста с рабочими внешними резолверами.
  write_facts \
    $'1\texternal\tprobe_skipped\tno\ttest' \
    $'1\texternal\tany_ok\tyes\ttest' \
    $'1\texternal\tall_timeout\tno\ttest' \
    $'1\tresolver\tsystem_resolver_ok\tno\ttest'
  HYPOTHESES=()
  build_hypotheses
  found=0
  for h in "${HYPOTHESES[@]}"; do
    IFS='|' read -r score layer _ <<< "$h"
    if [ "$layer" = "interceptor" ]; then
      [ "$score" -eq 20 ]
      found=1
    fi
  done
  [ "$found" -eq 1 ]
}

@test "cross-resolver private-IP mismatch -> strong interceptor hypothesis" {
  write_facts \
    $'1\tresolver\tcross_mismatch_count\t1\ttest' \
    $'1\tresolver\tcross_private_ip_suspect_count\t1\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "interceptor" ]
  [ "$score" -eq 45 ]
}

@test "cross-resolver mismatch without a private IP -> weaker interceptor hypothesis" {
  write_facts \
    $'1\tresolver\tcross_mismatch_count\t2\ttest' \
    $'1\tresolver\tcross_private_ip_suspect_count\t0\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "interceptor" ]
  [ "$score" -eq 20 ]
}

@test "cross-resolver mismatch confined to utun paths -> route hypothesis" {
  write_facts \
    $'1\troute\tcross_mismatch_utun_only\tyes\ttest'
  HYPOTHESES=()
  build_hypotheses
  [ "${#HYPOTHESES[@]}" -eq 1 ]
  IFS='|' read -r score layer _ <<< "${HYPOTHESES[0]}"
  [ "$layer" = "route" ]
  [ "$score" -eq 25 ]
}
