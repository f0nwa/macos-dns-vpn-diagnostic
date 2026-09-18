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
