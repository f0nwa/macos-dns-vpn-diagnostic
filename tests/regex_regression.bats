#!/usr/bin/env bats
# Регрессия на найденный баг: в macos-dns-test.sh было два места, где regex
# для подсчёта/извлечения nameserver'ов из `scutil --dns` был написан как
# /nameserver\\[[0-9]+\\]/ (двойной бэкслеш) вместо /nameserver\[[0-9]+\]/.
# Реальный вывод scutil выглядит как "nameserver[0] : 1.2.3.4" — без
# бэкслешей, поэтому баг-версия всегда возвращала 0 совпадений.
#
# Тест не хардкодит своё регулярное выражение: он вытаскивает его прямо из
# рабочего скрипта, чтобы при регрессии (кто-то случайно вернёт двойной
# бэкслеш обратно) тест упал сразу.

load 'lib/extract'

setup() {
  FIXTURES_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/fixtures" && pwd)"
}

get_ns_count_awk_prog() {
  grep -m1 'SCUTIL_NS_COUNT=' "$SCRIPT_UNDER_TEST" | sed -E "s/.*awk '([^']*)'.*/\1/"
}

@test "regex nameserver-count matches real scutil --dns syntax (2 nameservers)" {
  prog="$(get_ns_count_awk_prog)"
  run bash -c "awk \"\$1\" < \"\$2\"" _ "$prog" "$FIXTURES_DIR/scutil_dns_two_ns.txt"
  [ "$status" -eq 0 ]
  [ "$output" = "2" ]
}

@test "regex nameserver-count matches real scutil --dns syntax (1 nameserver)" {
  prog="$(get_ns_count_awk_prog)"
  run bash -c "awk \"\$1\" < \"\$2\"" _ "$prog" "$FIXTURES_DIR/scutil_dns_one_ns.txt"
  [ "$status" -eq 0 ]
  [ "$output" = "1" ]
}

@test "regex nameserver-count matches real scutil --dns syntax (scoped VPN resolvers, 4 nameservers total)" {
  prog="$(get_ns_count_awk_prog)"
  run bash -c "awk \"\$1\" < \"\$2\"" _ "$prog" "$FIXTURES_DIR/scutil_dns_scoped_vpn.txt"
  [ "$status" -eq 0 ]
  [ "$output" = "4" ]
}

@test "regex is not the double-backslash bug (guards against regression)" {
  prog="$(get_ns_count_awk_prog)"
  [[ "$prog" != *'\\\\['* ]]
}
