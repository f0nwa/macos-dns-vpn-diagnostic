#!/bin/bash
# Description: Полная диагностика DNS/VPN/Proxy на macOS с классификацией причин и e2e-проверкой.
# Author: f0nwa
# Last Modified: 2026-02-16

clear
set -u

CYAN=$'\033[36m'
MAGENTA=$'\033[35m'
DETAIL=$'\033[90m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'

# Читаем интерактивные ответы из TTY, даже если скрипт запускается из pipe.
if [ -r /dev/tty ]; then
  exec 3</dev/tty
else
  exec 3<&0
fi

say_step() {
  flush_step_details
  printf "\n%s%s%s\n" "$CYAN" "$1" "$RESET"
}
say_step_detail() {
  local msg="$1"
  STEP_DETAILS+=("$msg")
  start_step_spinner "$msg"
}

STEP_DETAILS=()
SPINNER_PID=""
start_step_spinner() {
  local message="$1"
  [ -t 1 ] || return 0
  stop_step_spinner
  local cols max_len display_message
  cols="$(tput cols 2>/dev/null || echo 80)"
  max_len=$((cols - 12))
  if [ "$max_len" -lt 20 ]; then
    max_len=20
  fi
  if [ "${#message}" -gt "$max_len" ]; then
    display_message="${message:0:$((max_len - 3))}..."
  else
    display_message="$message"
  fi
  (
    trap 'exit 0' TERM INT
    local i=0
    local frames='|/-\'
    while :; do
      i=$(( (i + 1) % 4 ))
      printf "\r\033[2K%s[%s] %s%s" "$DETAIL" "${frames:$i:1}" "$display_message" "$RESET"
      sleep 0.2
    done
  ) &
  SPINNER_PID=$!
}
stop_step_spinner() {
  if [ -n "${SPINNER_PID:-}" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
  fi
  SPINNER_PID=""
  if [ -t 1 ]; then
    # Очищаем всю текущую строку целиком независимо от длины.
    printf "\r\033[2K"
  fi
}
run_sudo() {
  # Если sudo уже авторизован, не трогаем спиннер.
  if [ "${EUID:-$(id -u)}" -eq 0 ] || sudo -n true 2>/dev/null; then
    sudo -n "$@"
    return $?
  fi

  # Если нужен пароль, останавливаем спиннер, чтобы не ломать строку Password:
  stop_step_spinner
  if [ -t 1 ]; then
    printf "\n"
  fi
  sudo "$@"
}
SUDO_KEEPALIVE_PID=""
stop_sudo_keepalive() {
  if [ -n "${SUDO_KEEPALIVE_PID:-}" ] && kill -0 "$SUDO_KEEPALIVE_PID" 2>/dev/null; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  fi
  SUDO_KEEPALIVE_PID=""
}
start_sudo_keepalive() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    return 0
  fi
  echo
  echo "Введите локальный пароль администратора для доступа в систему..."
  if sudo -v; then
    (
      while :; do
        sudo -n true 2>/dev/null || exit 0
        sleep 50
      done
    ) &
    SUDO_KEEPALIVE_PID=$!
  else
    echo -e "${YELLOW}Не удалось получить sudo-сессию заранее. Возможны дополнительные запросы пароля в ходе диагностики.${RESET}"
  fi
}
flush_step_details() {
  local item=""
  if [ "${#STEP_DETAILS[@]}" -eq 0 ]; then
    return
  fi
  stop_step_spinner
  for item in "${STEP_DETAILS[@]}"; do
    printf "  %s- %s%s\n" "$DETAIL" "$item" "$RESET"
  done
  STEP_DETAILS=()
}
trap 'stop_sudo_keepalive' EXIT INT TERM

printf "%s" "$CYAN"
cat <<'EOF'

                         ____  _____    ____  _   _______    ______          __ 
   ____ ___  ____ ______/ __ \/ ___/   / __ \/ | / / ___/   /_  __/__  _____/ /_
  / __ `__ \/ __ `/ ___/ / / /\__ \   / / / /  |/ /\__ \     / / / _ \/ ___/ __/
 / / / / / / /_/ / /__/ /_/ /___/ /  / /_/ / /|  /___/ /    / / /  __(__  ) /_  
/_/ /_/ /_/\__,_/\___/\____//____/  /_____/_/ |_//____/    /_/  \___/____/\__/  
                                                                                                                                                    
https://t.me/fonwa

EOF
printf "%s" "$RESET"

USER_TAG="${USER:-user}"
HOST_TAG="$(hostname -s 2>/dev/null || echo host)"
TS_TAG="$(date +%Y%m%d_%H%M%S)"
OUT="$(pwd)/${USER_TAG}_${HOST_TAG}_dns_diag_${TS_TAG}.txt"
echo ">> DNS+VPN/Прокси Диагностика Полная ($(date))" > "$OUT"
echo -e "\n>> RAW_APPENDIX" >> "$OUT"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo -e "${YELLOW}Скрипт запущен без sudo. После ввода домена будет запрошен пароль.${RESET}"
  echo -e "${YELLOW}Подсказка: можно запустить сразу с sudo для более ровного прохождения шагов.${RESET}"
  echo
  echo -e "\n>> PRIVILEGE_NOTICE" >> "$OUT"
  echo "run_mode=non_root; elevated_steps_require_sudo=yes" >> "$OUT"
fi

CAUSES=()
add_cause() { CAUSES+=("$1"); }

ask_yes_no() {
  # Возвращает 0 для yes и 1 для no; повторяет запрос до корректного ответа.
  local prompt="$1" reply=""
  while :; do
    read -r -u 3 -p "$prompt [y/N]: " reply
    case "${reply:-}" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO|"") return 1 ;;
      *) echo "Введите y или n." ;;
    esac
  done
}

RUN_START_EPOCH="$(date +%s)"
TIME_BUDGET_SEC=60
FACTS_FILE="/tmp/dns_diag_facts_${TS_TAG}_$$.tsv"
: > "$FACTS_FILE"

emit_fact() {
  local layer="$1" key="$2" value="$3" source="$4"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$layer" "$key" "$value" "$source" >> "$FACTS_FILE"
}

has_fact() {
  local layer="$1" key="$2" value="${3:-}"
  if [ -n "$value" ]; then
    awk -F'\t' -v l="$layer" -v k="$key" -v v="$value" '($2==l && $3==k && $4==v){found=1} END{exit !found}' "$FACTS_FILE"
  else
    awk -F'\t' -v l="$layer" -v k="$key" '($2==l && $3==k){found=1} END{exit !found}' "$FACTS_FILE"
  fi
}

join_by_semicolon() {
  local out="" item=""
  for item in "$@"; do
    if [ -n "$out" ]; then
      out="${out}; ${item}"
    else
      out="${item}"
    fi
  done
  printf '%s' "$out"
}

escape_ere() {
  printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\]/\\&/g'
}

PYTHON3_SKIP_REASON=""
DETECTED_PYTHON3_BIN=""
detect_primary_python3_bin() {
  # Базовый путь: "обычный" python3 из PATH.
  # Для /usr/bin/python3 обязательно проверяем наличие CLT, чтобы не вызвать установщик.
  local candidate=""
  PYTHON3_SKIP_REASON=""
  DETECTED_PYTHON3_BIN=""

  if ! command -v python3 >/dev/null 2>&1; then
    PYTHON3_SKIP_REASON="python3_missing"
    return 1
  fi

  candidate="$(command -v python3)"
  if [ "$candidate" = "/usr/bin/python3" ] && ! xcode-select -p >/dev/null 2>&1; then
    PYTHON3_SKIP_REASON="apple_stub_missing_clt"
    return 1
  fi

  DETECTED_PYTHON3_BIN="$candidate"
  return 0
}

detect_homebrew_python3_bin() {
  # Фолбэк: python3, установленный через Homebrew.
  local candidate=""
  PYTHON3_SKIP_REASON=""
  DETECTED_PYTHON3_BIN=""

  for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$candidate" ]; then
      DETECTED_PYTHON3_BIN="$candidate"
      return 0
    fi
  done

  PYTHON3_SKIP_REASON="homebrew_python3_missing"
  return 1
}

dig_probe() {
  # Вывод в stdout: result|reason|answers
  # result: ok|fail; reason: NOERROR|NODATA|NXDOMAIN|SERVFAIL|REFUSED|TIMEOUT|UNKNOWN
  local domain="$1" rr="$2" server="${3:-}" out status answer
  if [ -n "$server" ]; then
    out="$(dig +time=2 +tries=1 +noall +comments +answer "$domain" "$rr" @"$server" 2>&1)"
  else
    out="$(dig +time=2 +tries=1 +noall +comments +answer "$domain" "$rr" 2>&1)"
  fi

  status="$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z][A-Z]*\),.*/\1/p' | head -1)"
  answer="$(printf '%s\n' "$out" | sed -n 's/.*ANSWER: \([0-9][0-9]*\).*/\1/p' | head -1)"
  [ -z "$answer" ] && answer=0

  if printf '%s\n' "$out" | grep -Eiq 'timed out|no servers could be reached'; then
    echo "fail|TIMEOUT|$answer"
  elif [ "$status" = "NOERROR" ] && [ "$answer" -gt 0 ]; then
    echo "ok|NOERROR|$answer"
  elif [ "$status" = "NOERROR" ] && [ "$answer" -eq 0 ]; then
    echo "fail|NODATA|0"
  elif [ -n "$status" ]; then
    echo "fail|$status|$answer"
  else
    echo "fail|UNKNOWN|$answer"
  fi
}

nslookup_probe() {
  # Вывод в stdout: result|reason|answers
  local domain="$1" server="${2:-}" out
  if [ -n "$server" ]; then
    out="$(nslookup -timeout=2 "$domain" "$server" 2>&1 || true)"
  else
    out="$(nslookup -timeout=2 "$domain" 2>&1 || true)"
  fi
  if printf '%s\n' "$out" | grep -Eiq 'timed out|no servers could be reached'; then
    echo "fail|TIMEOUT|0"
  elif printf '%s\n' "$out" | grep -Eiq 'NXDOMAIN'; then
    echo "fail|NXDOMAIN|0"
  elif printf '%s\n' "$out" | grep -Eiq 'SERVFAIL'; then
    echo "fail|SERVFAIL|0"
  elif printf '%s\n' "$out" | grep -Eiq 'REFUSED'; then
    echo "fail|REFUSED|0"
  elif printf '%s\n' "$out" | grep -Eiq '^Address:[[:space:]]*[0-9a-fA-F:.]'; then
    echo "ok|NOERROR|1"
  else
    echo "fail|UNKNOWN|0"
  fi
}

SCOPED_TESTED=0
SCOPED_OK=0
SCOPED_FAIL=0
SCOPED_OK_UTUN=0
SCOPED_OK_NONUTUN=0
SCOPED_BEST_PATH="n/a"
DNS_ONLY_VERDICT="UNKNOWN"
E2E_VERDICT="not_run"
PRIMARY_CLASSIFICATION="unknown"
MOST_LIKELY_LAYER="dns"

run_scoped_resolver_probes() {
  local snapshot="$1" domain="$2"
  local resolver_id if_index iface flags reach ns
  local res_a st_a rs_a an_a
  local ns_ok

  echo -e "\n>> SCUTIL_SCOPED_NS_PROBE ($domain)" >> "$OUT"

  while IFS=$'\t' read -r resolver_id if_index iface flags reach ns; do
    [ -z "${ns:-}" ] && continue
    SCOPED_TESTED=$((SCOPED_TESTED + 1))
    ns_ok=0

    if command -v dig >/dev/null 2>&1; then
      res_a="$(dig_probe "$domain" A "$ns")"
    else
      res_a="$(nslookup_probe "$domain" "$ns")"
    fi

    st_a="$(printf '%s' "$res_a" | cut -d'|' -f1)"
    rs_a="$(printf '%s' "$res_a" | cut -d'|' -f2)"
    an_a="$(printf '%s' "$res_a" | cut -d'|' -f3)"

    if [ "$st_a" = "ok" ]; then
      ns_ok=1
      SCOPED_OK=$((SCOPED_OK + 1))
      if [ "$SCOPED_BEST_PATH" = "n/a" ] || { printf '%s' "$SCOPED_BEST_PATH" | grep -q '/na/' && [ "${iface:-na}" != "na" ]; }; then
        SCOPED_BEST_PATH="resolver#${resolver_id}/${iface:-if${if_index}}/$ns"
      fi
      if printf '%s' "${iface:-}" | grep -q '^utun'; then
        SCOPED_OK_UTUN=$((SCOPED_OK_UTUN + 1))
      else
        SCOPED_OK_NONUTUN=$((SCOPED_OK_NONUTUN + 1))
      fi
    else
      SCOPED_FAIL=$((SCOPED_FAIL + 1))
    fi

    echo "resolver#$resolver_id if_index=$if_index iface=${iface:-unknown} ns=$ns flags=${flags:-n/a} reach=${reach:-n/a} A=${st_a}/${rs_a}/${an_a}" >> "$OUT"
    emit_fact resolver scoped_probe "resolver=$resolver_id;if_index=$if_index;iface=${iface:-unknown};ns=$ns;a=$st_a/$rs_a/$an_a;ok=$ns_ok" "scutil scoped"
  done < <(
    printf '%s\n' "$snapshot" | awk '
      function flush_block(   i) {
        if (rid == "" || ns_count == 0) return
        for (i = 1; i <= ns_count; i++) {
          print rid "\t" (ifi==""?"na":ifi) "\t" (iface==""?"na":iface) "\t" (flags==""?"na":flags) "\t" (reach==""?"na":reach) "\t" ns_list[i]
        }
      }
      /^[[:space:]]*resolver #[0-9]+/ {
        flush_block()
        rid=$2; gsub("#","",rid)
        ifi=""; iface=""; flags=""; reach=""
        ns_count=0
        delete ns_list
        next
      }
      /if_index[[:space:]]*:/ {
        ifi=$3
        if ($0 ~ /\(/) {
          iface=$0
          sub(/^.*\(/, "", iface)
          sub(/\).*$/, "", iface)
        }
        next
      }
      /flags[[:space:]]*:/ {
        sub(/^[^:]*:[[:space:]]*/, "", $0)
        flags=$0
        next
      }
      /reach[[:space:]]*:/ {
        sub(/^[^:]*:[[:space:]]*/, "", $0)
        reach=$0
        next
      }
      /nameserver\[[0-9]+\][[:space:]]*:/ {
        ns=$3
        if (rid != "" && ns != "") ns_list[++ns_count]=ns
      }
      END {
        flush_block()
      }'
  )

  emit_fact resolver scoped_resolvers_tested "$SCOPED_TESTED" "scutil scoped"
  emit_fact resolver scoped_resolvers_ok "$SCOPED_OK" "scutil scoped"
  emit_fact resolver scoped_resolvers_fail "$SCOPED_FAIL" "scutil scoped"
  emit_fact resolver scoped_best_path "$SCOPED_BEST_PATH" "scutil scoped"
}

run_e2e_curl_probe() {
  local display_domain="$1" probe_domain="${2:-$1}" url_display url_probe meta curl_log ec remote_ip http_code t_dns t_conn t_tls
  local resolve_phase connect_phase tls_phase http_phase note
  url_display="https://$display_domain"
  url_probe="https://$probe_domain"
  curl_log="/tmp/dns_diag_curl_${TS_TAG}_$$.log"

  if ! command -v curl >/dev/null 2>&1; then
    E2E_VERDICT="not_run"
    emit_fact e2e curl_available no "curl"
    return
  fi
  emit_fact e2e curl_available yes "curl"

  meta="$(curl -sS -o /dev/null --connect-timeout 3 --max-time 8 -w '%{remote_ip}|%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{errormsg}' -v "$url_probe" 2>"$curl_log")"
  ec=$?
  remote_ip="$(printf '%s' "$meta" | cut -d'|' -f1)"
  http_code="$(printf '%s' "$meta" | cut -d'|' -f2)"
  t_dns="$(printf '%s' "$meta" | cut -d'|' -f3)"
  t_conn="$(printf '%s' "$meta" | cut -d'|' -f4)"
  t_tls="$(printf '%s' "$meta" | cut -d'|' -f5)"

  resolve_phase=fail
  connect_phase=fail
  tls_phase=fail
  http_phase=fail
  note=mixed

  if [ -n "$remote_ip" ] && [ "$remote_ip" != "0.0.0.0" ]; then
    resolve_phase=ok
  fi
  if awk "BEGIN{exit !($t_conn > 0)}"; then
    connect_phase=ok
  fi
  if awk "BEGIN{exit !($t_tls > 0)}"; then
    tls_phase=ok
  fi
  if printf '%s' "$http_code" | grep -Eq '^[23][0-9][0-9]$'; then
    http_phase=ok
  fi

  if [ "$ec" -ne 0 ]; then
    if grep -Eiq 'Could not resolve host|Name or service not known|nodename nor servname provided' "$curl_log"; then
      note=dns_issue
    elif grep -Eiq 'Failed to connect|Operation timed out|No route to host|Network is unreachable' "$curl_log"; then
      note=network_issue
    elif grep -Eiq 'SSL|TLS|certificate|handshake' "$curl_log"; then
      note=tls_issue
    else
      note=mixed
    fi
  else
    if [ "$http_phase" = "ok" ]; then
      note=http_ok
    elif [ "$tls_phase" = "fail" ]; then
      note=tls_issue
    else
      note=http_issue
    fi
  fi

  if [ "$http_phase" = "ok" ] && [ "$resolve_phase" = "ok" ] && [ "$connect_phase" = "ok" ] && [ "$tls_phase" = "ok" ]; then
    E2E_VERDICT="PASS"
  elif [ "$resolve_phase" = "fail" ]; then
    E2E_VERDICT="FAIL"
  else
    E2E_VERDICT="DEGRADED"
  fi

  emit_fact e2e resolve_phase "$resolve_phase" "curl"
  emit_fact e2e connect_phase "$connect_phase" "curl"
  emit_fact e2e tls_phase "$tls_phase" "curl"
  emit_fact e2e http_phase "$http_phase" "curl"
  emit_fact e2e http_code "${http_code:-000}" "curl"
  emit_fact e2e remote_ip "${remote_ip:-n/a}" "curl"
  emit_fact e2e note "$note" "curl"
  emit_fact e2e verdict "$E2E_VERDICT" "curl"

  echo -e "\n>> E2E_CURL_TRACE ($url_display)" >> "$OUT"
  if [ "$url_probe" != "$url_display" ]; then
    echo "curl_probe_url=$url_probe" >> "$OUT"
  fi
  sed -n '1,80p' "$curl_log" >> "$OUT" 2>/dev/null || true
}

render_dual_mode_sections() {
  local resolvers_tested a_ok total_fail dominant_failure system_ok
  local dns_ok e2e_ok e2e_resolve e2e_connect e2e_tls e2e_note
  local host_reachable tls_trust_ok human_status

  resolvers_tested="$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_count"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")"
  a_ok="$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_probe"&&$4 ~ /rr=A;/&&$4 ~ /result=ok/{c++} END{print c+0}' "$FACTS_FILE")"
  total_fail="$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_probe_fail"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")"
  system_ok="$(awk -F'\t' '$2=="resolver"&&$3=="system_resolver_ok"{v=$4} END{if(v=="") v="no"; print v}' "$FACTS_FILE")"
  dominant_failure="$(awk -F'\t' '
    $2=="resolver"&&$3=="dns_server_probe"&&$4 ~ /result=fail/ {
      n=split($4, p, "reason=")
      if (n > 1) {
        r=p[2]
        sub(/;.*/, "", r)
      } else {
        r="UNKNOWN"
      }
      cnt[r]++
    }
    END {
      max=0; best="none";
      for (k in cnt) if (cnt[k] > max) {max=cnt[k]; best=k}
      print best
    }' "$FACTS_FILE")"
  e2e_resolve="$(awk -F'\t' '$2=="e2e"&&$3=="resolve_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")"
  e2e_connect="$(awk -F'\t' '$2=="e2e"&&$3=="connect_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")"
  e2e_tls="$(awk -F'\t' '$2=="e2e"&&$3=="tls_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")"
  e2e_note="$(awk -F'\t' '$2=="e2e"&&$3=="note"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")"

  if [ "$system_ok" = "yes" ]; then
    if [ "$total_fail" -gt 0 ]; then
      DNS_ONLY_VERDICT="DEGRADED"
    else
      DNS_ONLY_VERDICT="PASS"
    fi
  else
    if has_fact resolver dns_servers_all_fail yes; then
      DNS_ONLY_VERDICT="FAIL"
    else
      DNS_ONLY_VERDICT="DEGRADED"
    fi
  fi

  if [ "$DNS_ONLY_VERDICT" = "PASS" ] || [ "$DNS_ONLY_VERDICT" = "DEGRADED" ]; then
    dns_ok=yes
  else
    dns_ok=no
  fi
  if [ "$E2E_VERDICT" = "PASS" ]; then
    e2e_ok=yes
  else
    e2e_ok=no
  fi
  if [ "$e2e_resolve" = "ok" ] && [ "$e2e_connect" = "ok" ]; then
    host_reachable=yes
  else
    host_reachable=no
  fi
  if [ "$e2e_tls" = "ok" ]; then
    tls_trust_ok=yes
  else
    tls_trust_ok=no
  fi

  if [ "$dns_ok" = "yes" ] && [ "$e2e_ok" = "yes" ]; then
    PRIMARY_CLASSIFICATION="healthy"
    MOST_LIKELY_LAYER="dns"
  elif [ "$dns_ok" = "yes" ] && [ "$host_reachable" = "yes" ] && [ "$tls_trust_ok" = "no" ] && [ "$e2e_note" = "tls_issue" ]; then
    PRIMARY_CLASSIFICATION="tls_certificate_or_trust_issue"
    MOST_LIKELY_LAYER="tls"
  elif [ "$dns_ok" = "yes" ] && [ "$e2e_ok" = "no" ]; then
    PRIMARY_CLASSIFICATION="network_or_tunnel_or_policy_issue"
    MOST_LIKELY_LAYER="tunnel"
  elif [ "$dns_ok" = "no" ] && [ "$e2e_ok" = "no" ]; then
    if [ "$e2e_resolve" = "ok" ] || [ "$e2e_connect" = "ok" ]; then
      PRIMARY_CLASSIFICATION="mixed_resolution_path_issue"
      MOST_LIKELY_LAYER="resolver"
    else
      PRIMARY_CLASSIFICATION="dns_primary_or_mixed_issue"
      MOST_LIKELY_LAYER="dns"
    fi
  else
    PRIMARY_CLASSIFICATION="partial_dns_issue_or_cache_effect"
    MOST_LIKELY_LAYER="dns"
  fi

  if [ "$dominant_failure" = "NXDOMAIN" ] && [ "$e2e_resolve" = "ok" ] && [ "$TEST_DOMAIN_QUERY" != "$TEST_DOMAIN" ]; then
    emit_fact resolver idn_dns_tool_mismatch yes "dual-mode inference"
    add_cause "DNS-инструменты дали NXDOMAIN, но e2e resolve успешен: возможен mismatch IDN/резолвера (query=$TEST_DOMAIN_QUERY)"
  fi

  if [ "$SCOPED_OK_UTUN" -gt 0 ] && [ "$SCOPED_OK_NONUTUN" -eq 0 ]; then
    emit_fact resolver vpn_dns_dependency yes "scutil scoped"
  elif [ "$SCOPED_OK_UTUN" -gt 0 ] && [ "$SCOPED_OK_NONUTUN" -gt 0 ]; then
    emit_fact resolver vpn_dns_dependency no "scutil scoped"
  else
    emit_fact resolver vpn_dns_dependency unknown "scutil scoped"
  fi

  echo -e "\n>> DNS_ONLY_RESULT" >> "$OUT"
  echo "domain=$TEST_DOMAIN" >> "$OUT"
  if [ "$TEST_DOMAIN_QUERY" != "$TEST_DOMAIN" ]; then
    echo "dns_query_domain=$TEST_DOMAIN_QUERY" >> "$OUT"
  fi
  echo "resolvers_tested=$resolvers_tested" >> "$OUT"
  echo "a_ok=$a_ok" >> "$OUT"
  if [ "$system_ok" = "yes" ]; then
    echo "system_resolver_match=yes" >> "$OUT"
  elif [ "$a_ok" -gt 0 ]; then
    echo "system_resolver_match=partial" >> "$OUT"
  else
    echo "system_resolver_match=no" >> "$OUT"
  fi
  echo "dominant_failure_reason=${dominant_failure:-none}" >> "$OUT"
  echo "scoped_resolvers_tested=$SCOPED_TESTED" >> "$OUT"
  echo "scoped_resolvers_ok=$SCOPED_OK" >> "$OUT"
  echo "scoped_resolvers_fail=$SCOPED_FAIL" >> "$OUT"
  echo "best_path=$SCOPED_BEST_PATH" >> "$OUT"
  echo "verdict=$DNS_ONLY_VERDICT" >> "$OUT"

  echo -e "\n>> E2E_RESULT" >> "$OUT"
  echo "url=https://$TEST_DOMAIN" >> "$OUT"
  echo "resolve_phase=$(awk -F'\t' '$2=="e2e"&&$3=="resolve_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "connect_phase=$(awk -F'\t' '$2=="e2e"&&$3=="connect_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "tls_phase=$(awk -F'\t' '$2=="e2e"&&$3=="tls_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "http_phase=$(awk -F'\t' '$2=="e2e"&&$3=="http_phase"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "http_code=$(awk -F'\t' '$2=="e2e"&&$3=="http_code"{v=$4} END{if(v=="") v="n/a"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "remote_ip=$(awk -F'\t' '$2=="e2e"&&$3=="remote_ip"{v=$4} END{if(v=="") v="n/a"; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "host_reachable=$host_reachable" >> "$OUT"
  echo "tls_trust_ok=$tls_trust_ok" >> "$OUT"
  echo "verdict=$E2E_VERDICT" >> "$OUT"
  echo "note=$(awk -F'\t' '$2=="e2e"&&$3=="note"{v=$4} END{if(v=="") v="not_run"; print v}' "$FACTS_FILE")" >> "$OUT"

  echo -e "\n>> PRIMARY_CLASSIFICATION" >> "$OUT"
  echo "DNS_ONLY_VERDICT=$DNS_ONLY_VERDICT" >> "$OUT"
  echo "E2E_VERDICT=$E2E_VERDICT" >> "$OUT"
  echo "PRIMARY_CLASSIFICATION=$PRIMARY_CLASSIFICATION" >> "$OUT"
  echo "MOST_LIKELY_LAYER=$MOST_LIKELY_LAYER" >> "$OUT"
  if [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$E2E_VERDICT" = "PASS" ]; then
    human_status="ТЕСТ УСПЕШНО ПРОЙДЕН: хост доступен, TLS и HTTP в норме"
  elif [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$host_reachable" = "yes" ] && [ "$tls_trust_ok" = "no" ]; then
    human_status="ТЕСТ ЧАСТИЧНО ПРОЙДЕН: хост доступен, но TLS сертификат не прошел проверку доверия"
  else
    human_status="ТЕСТ НЕ ПРОЙДЕН: есть проблемы с доступностью, резолвингом или TLS"
  fi
  echo "HUMAN_STATUS=$human_status" >> "$OUT"
}

HYPOTHESES=()
add_hypothesis() {
  # Поля: score|layer|symptom|evidence|impact|next_check
  HYPOTHESES+=("$1|$2|$3|$4|$5|$6")
}

confidence_label() {
  local score="$1"
  if [ "$score" -ge 70 ]; then
    echo "HIGH"
  elif [ "$score" -ge 40 ]; then
    echo "MED"
  else
    echo "LOW"
  fi
}

build_hypotheses() {
  local score_resolver=0 score_route=0 score_interceptor=0 score_policy=0
  local ev_resolver=() ev_route=() ev_interceptor=() ev_policy=()

  if has_fact resolver nameserver_missing yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("nameserver в scutil не найден")
  fi
  if has_fact resolver system_resolver_ok no; then
    score_resolver=$((score_resolver + 30))
    ev_resolver+=("системный резолвер не отвечает")
  fi
  if has_fact resolver dns_servers_all_fail yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("все DNS сервера не отвечают")
  fi
  if has_fact resolver test_domain_resolver_scope yes; then
    score_resolver=$((score_resolver + 25))
    ev_resolver+=("для домена действует /etc/resolver scope")
  fi
  if has_fact resolver test_domain_hosts_override yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("домен присутствует в /etc/hosts")
  fi
  if has_fact resolver system_resolver_ok yes; then
    score_resolver=$((score_resolver - 25))
    ev_resolver+=("контрдоказательство: системный резолвер успешен")
  fi

  if has_fact route default_via_utun yes; then
    score_route=$((score_route + 20))
    ev_route+=("default route через utun")
  fi
  if has_fact route utun_rfc19818_present yes; then
    score_route=$((score_route + 10))
    ev_route+=("обнаружены utun с адресом из 198.18/15")
  fi
  if has_fact route active_utun yes; then
    score_route=$((score_route + 20))
    ev_route+=("есть активные utun интерфейсы")
  fi
  if has_fact resolver system_resolver_ok no && has_fact resolver dns_servers_any_ok yes; then
    score_route=$((score_route + 40))
    ev_route+=("DNS серверы отвечают напрямую, но системный резолвер падает")
  fi

  if has_fact interceptor local_dns_listener_present yes; then
    score_interceptor=$((score_interceptor + 40))
    ev_interceptor+=("локальный процесс слушает DNS порт 53")
  fi
  if has_fact interceptor system_proxy_enabled yes; then
    score_interceptor=$((score_interceptor + 20))
    ev_interceptor+=("системный прокси включен")
  fi
  if has_fact interceptor active_network_extension yes; then
    score_interceptor=$((score_interceptor + 20))
    ev_interceptor+=("активны network extension VPN/фильтрации")
  fi
  if has_fact interceptor local_dns_listener_present yes && has_fact resolver system_resolver_ok no; then
    score_interceptor=$((score_interceptor + 40))
    ev_interceptor+=("совпадение локального перехватчика и отказа резолвера")
  fi

  if has_fact policy pf_enabled yes; then
    score_policy=$((score_policy + 20))
    ev_policy+=("PF включен")
  fi
  if has_fact policy pf_block_rules yes; then
    score_policy=$((score_policy + 40))
    ev_policy+=("есть PF block/drop правила")
  fi
  if has_fact policy pf_blocks_recent yes; then
    score_policy=$((score_policy + 40))
    ev_policy+=("есть PF block события за последний час")
  fi

  if [ "$score_resolver" -gt 0 ]; then
    add_hypothesis "$score_resolver" "resolver" \
      "Проблема на уровне DNS конфигурации/резолвера" \
      "$(join_by_semicolon "${ev_resolver[@]}")" \
      "Имя может не резолвиться даже без явных сетевых блоков" \
      "scutil --dns; cat /etc/resolver/*; grep -vE '^(#|$)' /etc/hosts"
  fi
  if [ "$score_route" -gt 0 ]; then
    add_hypothesis "$score_route" "route" \
      "Проблема маршрутизации DNS через VPN/utun" \
      "$(join_by_semicolon "${ev_route[@]}")" \
      "DNS запросы могут уходить через неожиданный интерфейс" \
      "route -n get default; netstat -rn | grep '^default'"
  fi
  if [ "$score_interceptor" -gt 0 ]; then
    add_hypothesis "$score_interceptor" "interceptor" \
      "Локальный перехват/модификация DNS трафика" \
      "$(join_by_semicolon "${ev_interceptor[@]}")" \
      "Локальный агент может подменять DNS/прокси поведение" \
      "sudo lsof -nP -iTCP:53 -iUDP:53; systemextensionsctl list"
  fi
  if [ "$score_policy" -gt 0 ]; then
    add_hypothesis "$score_policy" "policy" \
      "Политики фильтрации (PF/Firewall) влияют на DNS" \
      "$(join_by_semicolon "${ev_policy[@]}")" \
      "DNS запросы могут блокироваться правилами ОС" \
      "sudo pfctl -sr; sudo log show --predicate 'subsystem == \"com.apple.pf\"' --last 1h"
  fi
}

render_evidence_sections() {
  local elapsed now sorted line score layer symptom evidence impact next confidence rank=0
  now="$(date +%s)"
  elapsed=$((now - RUN_START_EPOCH))
  if [ "$elapsed" -gt "$TIME_BUDGET_SEC" ]; then
    emit_fact runtime budget_exceeded yes "time_guard"
  fi

  build_hypotheses

  echo -e "\n>> EXEC_SUMMARY" >> "$OUT"
  echo "runtime_sec=$elapsed budget_sec=$TIME_BUDGET_SEC facts_file=$FACTS_FILE" >> "$OUT"
  if [ "${#HYPOTHESES[@]}" -eq 0 ]; then
    echo "No high-signal hypotheses from collected evidence." >> "$OUT"
  else
    sorted="$(printf '%s\n' "${HYPOTHESES[@]}" | sort -t'|' -k1,1nr | head -3)"
    while IFS='|' read -r score layer symptom evidence impact next; do
      [ -z "$score" ] && continue
      rank=$((rank + 1))
      confidence="$(confidence_label "$score")"
      echo "$rank. [$confidence/$score] $symptom (layer=$layer)" >> "$OUT"
      echo "   evidence: $evidence" >> "$OUT"
      echo "   next: $next" >> "$OUT"
    done <<< "$sorted"
  fi

  echo -e "\n>> EVIDENCE_MATRIX" >> "$OUT"
  echo "Symptom | Evidence | Layer | Confidence | Impact | Next check" >> "$OUT"
  if [ "${#HYPOTHESES[@]}" -eq 0 ]; then
    echo "none | no hypothesis | none | LOW/0 | n/a | collect more data" >> "$OUT"
  else
    sorted="$(printf '%s\n' "${HYPOTHESES[@]}" | sort -t'|' -k1,1nr)"
    while IFS='|' read -r score layer symptom evidence impact next; do
      [ -z "$score" ] && continue
      confidence="$(confidence_label "$score")"
      echo "$symptom | $evidence | $layer | $confidence/$score | $impact | $next" >> "$OUT"
    done <<< "$sorted"
  fi
}

TEST_DOMAIN=""
while :; do
  read -r -u 3 -p "Введите домен для проверки DNS: " INPUT_DOMAIN
  INPUT_DOMAIN_TRIMMED="$(printf '%s' "${INPUT_DOMAIN:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [ -z "$INPUT_DOMAIN_TRIMMED" ]; then
    echo "Домен не введен. Повторите ввод."
    continue
  fi
  if ! printf '%s' "$INPUT_DOMAIN_TRIMMED" | grep -Eq '^[^.].*\..*[^.]$'; then
    echo "Некорректный домен: требуется формат вида name.zone (одна точка без меток недопустима)."
    continue
  fi
  if [ -n "$INPUT_DOMAIN_TRIMMED" ]; then
    TEST_DOMAIN="$INPUT_DOMAIN_TRIMMED"
    break
  fi
done

TEST_DOMAIN_QUERY="$TEST_DOMAIN"
IDN_PUNY=""
if printf '%s' "$TEST_DOMAIN" | LC_ALL=C grep -q '[^ -~]'; then
  PYTHON3_BIN=""
  if detect_primary_python3_bin; then
    PYTHON3_BIN="$DETECTED_PYTHON3_BIN"
    IDN_PUNY="$("$PYTHON3_BIN" -c 'import sys; print(sys.argv[1].encode("idna").decode("ascii"))' "$TEST_DOMAIN" 2>/dev/null || true)"
    if [ -n "${IDN_PUNY:-}" ]; then
      TEST_DOMAIN_QUERY="$IDN_PUNY"
      echo
      echo -e "${CYAN}IDN нормализация для DNS-запросов: $TEST_DOMAIN -> $TEST_DOMAIN_QUERY${RESET}"
      emit_fact resolver idn_normalized yes "python3 idna (${PYTHON3_BIN})"
      emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "idna"
    else
      emit_fact resolver idn_normalized no "python3 idna (${PYTHON3_BIN})"
    fi
  else
    echo
    if [ "$PYTHON3_SKIP_REASON" = "apple_stub_missing_clt" ]; then
      echo -e "${CYAN}Обнаружен IDN-домен, но /usr/bin/python3 недоступен без Command Line Tools.${RESET}"
      echo -e "${CYAN}Переходим на установку Homebrew + python3.${RESET}"
      emit_fact resolver idn_normalized no "python3 apple stub skipped"
    else
      echo -e "${CYAN}Обнаружен IDN-домен, но python3 не найден.${RESET}"
      emit_fact resolver idn_normalized no "python3 missing"
    fi
    AUTO_INSTALL_PYTHON_WITH_BREW=no

    if ! command -v brew >/dev/null 2>&1; then
      if ask_yes_no "Не найден Homebrew. Установить Homebrew и python3 автоматически сейчас?"; then
        AUTO_INSTALL_PYTHON_WITH_BREW=yes
        if command -v curl >/dev/null 2>&1; then
          echo "Устанавливаем Homebrew..."
          if NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
            emit_fact resolver brew_install_attempt success "homebrew install script"
            if [ -x /opt/homebrew/bin/brew ]; then
              eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [ -x /usr/local/bin/brew ]; then
              eval "$(/usr/local/bin/brew shellenv)"
            fi
          else
            emit_fact resolver brew_install_attempt failed "homebrew install script"
          fi
        else
          emit_fact resolver brew_install_attempt unavailable "curl missing"
        fi
      else
        emit_fact resolver brew_install_attempt skipped "user declined"
      fi
    fi

    if command -v brew >/dev/null 2>&1; then
      if [ "$AUTO_INSTALL_PYTHON_WITH_BREW" = "yes" ] || ask_yes_no "Установить python3 через Homebrew сейчас?"; then
        echo "Пробуем установить python3 через Homebrew..."
        if brew install python >/dev/null 2>&1; then
          emit_fact resolver python3_install_attempt success "brew install python"
        else
          emit_fact resolver python3_install_attempt failed "brew install python"
        fi
      else
        emit_fact resolver python3_install_attempt skipped "user declined"
      fi
    else
      emit_fact resolver python3_install_attempt unavailable "brew missing"
    fi

    PYTHON3_BIN=""
    if detect_homebrew_python3_bin; then
      PYTHON3_BIN="$DETECTED_PYTHON3_BIN"
      IDN_PUNY="$("$PYTHON3_BIN" -c 'import sys; print(sys.argv[1].encode("idna").decode("ascii"))' "$TEST_DOMAIN" 2>/dev/null || true)"
      if [ -n "${IDN_PUNY:-}" ]; then
        TEST_DOMAIN_QUERY="$IDN_PUNY"
        echo
        echo -e "${CYAN}IDN нормализация после установки: $TEST_DOMAIN -> $TEST_DOMAIN_QUERY${RESET}"
        emit_fact resolver idn_normalized yes "python3 idna post-install (${PYTHON3_BIN})"
        emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "idna post-install"
      else
        emit_fact resolver idn_normalized no "python3 idna post-install (${PYTHON3_BIN})"
      fi
    fi

    if [ "$TEST_DOMAIN_QUERY" = "$TEST_DOMAIN" ]; then
      echo
      echo "Авто-конвертация IDN недоступна."
      echo "Рекомендуется ввести punycode-домен (например xn--...)."
      read -r -u 3 -p "Введите punycode для DNS-запросов (Enter = оставить исходный): " MANUAL_PUNY
      MANUAL_PUNY_TRIMMED="$(printf '%s' "${MANUAL_PUNY:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      if [ -n "$MANUAL_PUNY_TRIMMED" ]; then
        TEST_DOMAIN_QUERY="$MANUAL_PUNY_TRIMMED"
        emit_fact resolver idn_normalized yes "manual punycode"
        emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "manual punycode"
        echo -e "${CYAN}Используем вручную заданный query-домен: $TEST_DOMAIN_QUERY${RESET}"
      fi
    fi
  fi
fi

start_sudo_keepalive

say_step "1/12 Сбор DNS настроек (scutil)"
say_step_detail "Снимаем единый snapshot: scutil --dns"
say_step_detail "Снимаем системные прокси: scutil --proxy"
say_step_detail "Фиксируем базовые факты resolver (nameserver_count)"
# 1. scutil DNS
echo ">> scutil --dns (DNS настройки)" >> "$OUT"
SCUTIL_DNS_RAW="$(scutil --dns 2>&1 || true)"
printf '%s\n' "$SCUTIL_DNS_RAW" >> "$OUT"
echo -e "\n>> scutil --proxy (прокси)" >> "$OUT"
scutil --proxy >> "$OUT" 2>&1
SCUTIL_NS_COUNT="$(printf '%s\n' "$SCUTIL_DNS_RAW" | awk '/nameserver\\[[0-9]+\\]/{c++} END{print c+0}')"
emit_fact resolver nameserver_count "$SCUTIL_NS_COUNT" "scutil --dns"

say_step "2/12 PF: статус/анкоры/правила"
say_step_detail "Читаем pfctl: info / anchors / rules"
say_step_detail "Фиксируем факт: PF включен или нет"
# 2. PF полный
echo -e "\n>> PF: статус, анкоры, правила" >> "$OUT"
run_sudo pfctl -s info >> "$OUT" 2>&1
run_sudo pfctl -a all -s info >> "$OUT" 2>&1
run_sudo pfctl -s rules >> "$OUT" 2>&1
if run_sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
  emit_fact policy pf_enabled yes "pfctl -s info"
else
  emit_fact policy pf_enabled no "pfctl -s info"
fi

say_step "3/12 Сетевые расширения VPN/Прокси"
say_step_detail "Проверяем neagent (если доступен)"
say_step_detail "Снимаем systemextensionsctl list"
# 3. Сетевые расширения (NetworkExtension)
echo -e "\n>> Сетевые расширения VPN/Прокси" >> "$OUT"
if command -v neagent >/dev/null 2>&1; then
  neagent list >> "$OUT" 2>&1
else
  echo "neagent не найден, пропуск" >> "$OUT"
fi
echo -e "\n>> systemextensionsctl список" >> "$OUT"
systemextensionsctl list >> "$OUT" 2>&1

say_step "4/12 Процессы VPN/Прокси/PF"
say_step_detail "Ищем процессы VPN/Proxy/Filter через pgrep"
# 4. ВСЕ процессы VPN/Прокси/PF (расширенный список)
VPN_PROCS="happ|ngate|cryptopro|xray|v2ray|v2rayn|qv2ray|nekoray|sing-box|clash|clashx|clashx-pro|clash-verge|shadowrocket|shadowsocksx|shadowsocksx-ng|shadowsocks|quantumult|surge|loon|stash|kitsunebi|v2box|napsternet|mosdns|dnscrypt-proxy|cloudflared|adguard|nextdns|smartdns|stubby|unbound|coredns|1\\.1\\.1\\.1|outline|wireguard|tailscale|headscale|mullvad|protonvpn|expressvpn|nordvpn|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vyprvpn|cyberghost|hide\\.me|zenmate|tunnelbear|astrill|hotspotshield|hma|openvpn|viscosity|tunnelblick|shimo|vpntracker|forticlient|paloaltonetworks|globalprotect|pulse|anyconnect|cisco|checkpoint|snx|sophos|sonicwall|zerotier|netbird|privoxy|polipo|3proxy|dante|tinyproxy|squid|mitmproxy|proxifier|proxychains|proxyswitcher|proxynotion|littlesnitch|lulu|tripmode|murus|goodbyedpi|zapret|antizapret|stunnel|obfs4proxy|meek-client|snowflake|tor|psiphon|safing|portmaster|proxynotion|ovpnproxy|unblockpro"
echo -e "\n>> ПРОЦЕССЫ VPN/Прокси/PF" >> "$OUT"
pgrep -ai "$VPN_PROCS|neagent|utun|pfctl|socketfilterfw" >> "$OUT" 2>&1 || true

say_step "5/12 Службы запуска"
say_step_detail "Проверяем launchctl и plist сервисы VPN/Proxy"
# 5. Launch plist всех клиентов
LAUNCH_LIST="happ|ngate|cryptopro|xray|v2ray|qv2ray|clash|clashx|shadow|quantumult|surge|loon|stash|sing|nekoray|kitsunebi|v2box|napster|mosdns|dnscrypt|cloudflared|adguard|nextdns|smartdns|stubby|unbound|coredns|outline|wireguard|tailscale|headscale|mullvad|proton|expressvpn|nord|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vypr|cyberghost|tunnelbear|astrill|hotspotshield|hma|openvpn|viscosity|tunnelblick|shimo|vpntracker|forticlient|paloalto|globalprotect|pulse|anyconnect|cisco|checkpoint|snx|sophos|sonicwall|zerotier|netbird|privoxy|polipo|3proxy|dante|tinyproxy|squid|mitmproxy|proxifier|proxychains|proxyswitcher|socketfilterfw|littlesnitch|lulu|tripmode|murus|icefloor|goodbyedpi|zapret|antizapret|stunnel|obfs4|meek|snowflake|tor|psiphon|safing|portmaster|unblockpro"
echo -e "\n>> Службы запуска (launchd) VPN/Прокси" >> "$OUT"
launchctl list 2>/dev/null | grep -iE "$LAUNCH_LIST" >> "$OUT"
find /Library/Launch* ~/Library/Launch* -name "*.plist" -print0 2>/dev/null | xargs -0 grep -l -iE "$LAUNCH_LIST" 2>/dev/null | head -20 >> "$OUT"

say_step "6/12 DNS трафик и PF блоки"
say_step_detail "Короткий capture DNS/mDNS/LLMNR: tcpdump"
say_step_detail "Ищем PF block события за 1 час"
# 6. DNS трафик + блоки
echo -e "\n>> DNS трафик (30 пакетов)" >> "$OUT"
run_sudo tcpdump -i any -n '(udp or tcp) and (port 53 or port 5353 or port 5355)' -c 30 2>/dev/null >> "$OUT" || echo "tcpdump: нет DNS/mDNS/LLMNR трафика" >> "$OUT"
echo -e "\n>> PF блоки (1ч)" >> "$OUT"
PF_BLOCKS="$(run_sudo log show --style compact --predicate 'subsystem == "com.apple.pf"' --last 1h --info 2>/dev/null | grep -i block | head -15 || true)"
if [ -n "$PF_BLOCKS" ]; then
  printf '%s\n' "$PF_BLOCKS" >> "$OUT"
  emit_fact policy pf_blocks_recent yes "log show com.apple.pf"
else
  echo "PF block-события за 1ч не обнаружены" >> "$OUT"
  emit_fact policy pf_blocks_recent no "log show com.apple.pf"
fi

say_step "7/12 Конфиги приложений"
say_step_detail "Сканируем типовые пути конфигов VPN/Proxy приложений"
# 7. Конфиги приложений (папки)
APPS_PATHS="happ|ngate|cryptopro|xray|v2ray|qv2ray|clash|clashx|shadowrocket|shadowsocks|quantumult|surge|loon|stash|adguard|nextdns|wireguard|tailscale|headscale|mullvad|proton|expressvpn|nordvpn|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vypr|cyberghost|tunnelbear|astrill|openvpn|viscosity|tunnelblick|shimo|vpntracker|globalprotect|forticlient|anyconnect|cisco|zerotier|netbird|littlesnitch|lulu|tripmode|murus|goodbyedpi|zapret|antizapret|unblockpro"
echo -e "\n>> Конфиги приложений" >> "$OUT"
find ~/Library/Preferences ~/Library/Application\ Support ~/Library/Caches /Applications -maxdepth 3 2>/dev/null | grep -Ei "$APPS_PATHS" | head -20 >> "$OUT"

say_step "8/12 Локальные слушатели портов"
say_step_detail "Проверяем, кто держит /dev/pf"
say_step_detail "Проверяем TCP LISTEN и UDP сокеты DNS/Proxy портов"
# 8. lsof PF + порты прокси
echo -e "\n>> /dev/pf пользователи" >> "$OUT"
run_sudo lsof /dev/pf 2>/dev/null | head -10 >> "$OUT"
echo -e "\n>> Прокси/DNS TCP порты (LISTEN)" >> "$OUT"
run_sudo lsof -nP -sTCP:LISTEN -iTCP:53 -iTCP:5353 -iTCP:1080 -iTCP:8080 -iTCP:40000-50000 2>/dev/null >> "$OUT"
echo -e "\n>> DNS UDP сокеты" >> "$OUT"
run_sudo lsof -nP -iUDP:53 -iUDP:5353 -iUDP:5355 2>/dev/null >> "$OUT"

say_step "9/12 Сетевые сервисы и прокси"
say_step_detail "Обходим network services"
say_step_detail "Снимаем DNS/proxy/PAC/bypass для каждого сервиса"
# 9. Сетевые сервисы + прокси настройки по каждому сервису
echo -e "\n>> Сетевые сервисы" >> "$OUT"
networksetup -listallnetworkservices 2>/dev/null | sed '1d' >> "$OUT"
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  echo -e "\n--- Сервис: $svc ---" >> "$OUT"
  networksetup -getdnsservers "$svc" >> "$OUT" 2>&1
  networksetup -getwebproxy "$svc" >> "$OUT" 2>&1
  networksetup -getsecurewebproxy "$svc" >> "$OUT" 2>&1
  networksetup -getautoproxyurl "$svc" >> "$OUT" 2>&1
  networksetup -getproxybypassdomains "$svc" >> "$OUT" 2>&1
done < <(networksetup -listallnetworkservices 2>/dev/null | sed '1d')

say_step "10/12 Логи DNS резолвера и сетевых расширений"
say_step_detail "Фильтрованные логи mDNSResponder (query/fail/timeout)"
say_step_detail "Фильтрованные логи NetworkExtension (dns/proxy/tunnel/fail)"
# 10. Логи DNS-резолвера и NetworkExtension
echo -e "\n>> mDNSResponder логи (3м)" >> "$OUT"
log show --style compact --predicate 'process == "mDNSResponder" AND (eventMessage CONTAINS[c] "query" OR eventMessage CONTAINS[c] "fail" OR eventMessage CONTAINS[c] "timeout" OR eventMessage CONTAINS[c] "nxdomain" OR eventMessage CONTAINS[c] "servfail")' --last 3m | head -500 >> "$OUT" 2>&1
echo -e "\n>> Логи сетевых расширений (3м)" >> "$OUT"
log show --style compact --predicate 'subsystem == "com.apple.networkextension" AND (eventMessage CONTAINS[c] "dns" OR eventMessage CONTAINS[c] "proxy" OR eventMessage CONTAINS[c] "tunnel" OR eventMessage CONTAINS[c] "drop" OR eventMessage CONTAINS[c] "deny" OR eventMessage CONTAINS[c] "fail")' --last 3m | head -500 >> "$OUT" 2>&1

say_step "11/12 Проверка доступности DNS"
say_step_detail "Собираем DNS servers из scutil/networksetup/resolv.conf"
say_step_detail "Снимаем default route и utun inventory (RFC198.18 маркер)"
say_step_detail "Снимаем таблицу маршрутизации: netstat -rn"
say_step_detail "Проверяем домен через DNS servers и системный resolver (A)"
# 11. Проверка доступности DNS
echo -e "\n>> DNS доступность ($TEST_DOMAIN)" >> "$OUT"
if [ "$TEST_DOMAIN_QUERY" != "$TEST_DOMAIN" ]; then
  echo "DNS query label (IDN->ASCII): $TEST_DOMAIN_QUERY" >> "$OUT"
fi
DNS_SERVERS="$(printf '%s\n' "$SCUTIL_DNS_RAW" | awk '/nameserver\\[[0-9]+\\]/{print $3}' | sort -u)"
if [ -z "$DNS_SERVERS" ]; then
  DNS_SERVERS="$(networksetup -listallnetworkservices 2>/dev/null | sed '1d' | while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    networksetup -getdnsservers "$svc" 2>/dev/null | awk '/^[0-9]/{print $1}'
  done | sort -u)"
fi
if [ -z "$DNS_SERVERS" ] && [ -r /etc/resolv.conf ]; then
  DNS_SERVERS="$(awk '/^nameserver /{print $2}' /etc/resolv.conf | sort -u)"
fi
echo "DNS сервера обнаружены: ${DNS_SERVERS:-нет}" >> "$OUT"
if [ -n "$DNS_SERVERS" ]; then
  emit_fact resolver dns_servers_detected yes "scutil/networksetup/resolv.conf"
  emit_fact resolver dns_server_count "$(printf '%s\n' "$DNS_SERVERS" | awk 'NF{c++} END{print c+0}')" "scutil/networksetup/resolv.conf"
else
  emit_fact resolver dns_servers_detected no "scutil/networksetup/resolv.conf"
fi

DEFAULT_UTUNS_ANY="$(netstat -rn 2>/dev/null | awk '$1=="default" {print $NF}' | grep '^utun' | sort -u || true)"
DEFAULT_UTUNS_V4="$(netstat -rn -f inet 2>/dev/null | awk '$1=="default" {print $NF}' | grep '^utun' | sort -u || true)"
DEFAULT_ROUTE_IF="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
emit_fact route default_interface "${DEFAULT_ROUTE_IF:-unknown}" "route -n get default"
if [ -n "$DEFAULT_UTUNS_V4" ] || { [ -n "${DEFAULT_ROUTE_IF:-}" ] && printf '%s' "$DEFAULT_ROUTE_IF" | grep -q '^utun'; }; then
  emit_fact route default_via_utun yes "netstat/route"
else
  emit_fact route default_via_utun no "netstat/route"
fi
echo -e "\n>> Маршрутизация (netstat -rn)" >> "$OUT"
netstat -rn >> "$OUT" 2>&1
echo -e "\n>> DEFAULT_ROUTE_SUMMARY" >> "$OUT"
echo "default_route_interface=${DEFAULT_ROUTE_IF:-unknown}" >> "$OUT"
if [ -n "$DEFAULT_UTUNS_V4" ]; then
  echo "default_utun_ipv4=$(printf '%s' "$DEFAULT_UTUNS_V4" | tr '\n' ' ' | sed 's/[[:space:]]*$//')" >> "$OUT"
else
  echo "default_utun_ipv4=none" >> "$OUT"
fi
if [ -n "$DEFAULT_UTUNS_ANY" ]; then
  echo "default_utun_any=$(printf '%s' "$DEFAULT_UTUNS_ANY" | tr '\n' ' ' | sed 's/[[:space:]]*$//')" >> "$OUT"
else
  echo "default_utun_any=none" >> "$OUT"
fi
if [ -n "$DEFAULT_UTUNS_ANY" ] && [ -z "$DEFAULT_UTUNS_V4" ]; then
  echo "note=utun в default замечены только в общем/часто IPv6 представлении netstat; это может быть штатно для macOS" >> "$OUT"
fi

echo -e "\n>> UTUN интерфейсы (inventory)" >> "$OUT"
UTUN_INVENTORY="$(
  ifconfig 2>/dev/null | awk '
    function flush_iface() {
      if (iface == "") return
      out_ip=(ip=="" ? "none" : ip)
      rfc=((out_ip ~ /^198\.18\./ || out_ip ~ /^198\.19\./) ? "yes" : "no")
      print iface "\t" state "\t" out_ip "\t" rfc
    }
    /^[[:alnum:]_.-]+:/ {
      flush_iface()
      iface=$1
      sub(/:.*/, "", iface)
      if (iface ~ /^utun[0-9]+$/) {
        state=(($0 ~ /UP/ && $0 ~ /RUNNING/) ? "UP+RUNNING" : "OTHER")
        ip=""
      } else {
        iface=""
        state=""
        ip=""
      }
      next
    }
    iface != "" && /^[[:space:]]*inet / {
      line=$0
      sub(/^[[:space:]]*inet /, "", line)
      sub(/[[:space:]].*$/, "", line)
      ip=line
    }
    END {
      flush_iface()
    }'
)"
if [ -n "$UTUN_INVENTORY" ]; then
  emit_fact route utun_present yes "ifconfig"
  while IFS=$'\t' read -r ui st ip rfc; do
    [ -z "${ui:-}" ] && continue
    echo "$ui state=$st inet=$ip rfc19818=$rfc" >> "$OUT"
    emit_fact route utun_iface "iface=$ui;state=$st;ip=$ip;rfc19818=$rfc" "ifconfig"
    if [ "$rfc" = "yes" ]; then
      emit_fact route utun_rfc19818_present yes "ifconfig"
      if [ -n "${DEFAULT_ROUTE_IF:-}" ] && [ "$ui" = "$DEFAULT_ROUTE_IF" ]; then
        add_cause "Default route через $ui с tunnel-адресом $ip (198.18/15)"
      fi
    fi
  done <<< "$UTUN_INVENTORY"
else
  emit_fact route utun_present no "ifconfig"
fi

# 11a. Wi-Fi ручной DNS/прокси
if command -v rg >/dev/null 2>&1; then
  WIFI_SVC="$(networksetup -listallnetworkservices 2>/dev/null | sed '1d' | rg -m 1 -i 'wi-?fi')"
else
  WIFI_SVC="$(networksetup -listallnetworkservices 2>/dev/null | sed '1d' | grep -im 1 'wi-\\?fi')"
fi
if [ -n "${WIFI_SVC:-}" ]; then
  echo -e "\n>> Wi-Fi ручной DNS/прокси" >> "$OUT"
  WIFI_DNS="$(networksetup -getdnsservers "$WIFI_SVC" 2>/dev/null)"
  if printf '%s' "$WIFI_DNS" | grep -q "There aren't any DNS Servers set"; then
    echo "Wi-Fi DNS: не задан вручную (DHCP/Авто)" >> "$OUT"
  else
    echo "Wi-Fi DNS: вручную задан -> $WIFI_DNS" >> "$OUT"
  fi
  WIFI_PROXY="$(networksetup -getwebproxy "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  WIFI_SPROXY="$(networksetup -getsecurewebproxy "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  WIFI_PAC="$(networksetup -getautoproxyurl "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  echo "Wi-Fi HTTP прокси: ${WIFI_PROXY:-неизвестно}" >> "$OUT"
  echo "Wi-Fi HTTPS прокси: ${WIFI_SPROXY:-неизвестно}" >> "$OUT"
  echo "Wi-Fi PAC: ${WIFI_PAC:-неизвестно}" >> "$OUT"
  if [ "${WIFI_PROXY:-No}" = "Yes" ] || [ "${WIFI_SPROXY:-No}" = "Yes" ] || [ "${WIFI_PAC:-No}" = "Yes" ]; then
    emit_fact interceptor wifi_proxy_enabled yes "networksetup $WIFI_SVC"
  else
    emit_fact interceptor wifi_proxy_enabled no "networksetup $WIFI_SVC"
  fi
fi
if command -v dig >/dev/null 2>&1; then
  emit_fact resolver probe_tool_available yes "dig"
  DNS_TOTAL=0
  DNS_FAIL=0
  DNS_OK=0
  for s in $DNS_SERVERS; do
    DNS_TOTAL=$((DNS_TOTAL + 1))
    PROBE_RESULT="$(dig_probe "$TEST_DOMAIN_QUERY" A "$s")"
    PROBE_STATE="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f1)"
    PROBE_REASON="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f2)"
    PROBE_ANS="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f3)"
    if [ "$PROBE_STATE" = "ok" ]; then
      echo "УСПЕХ $s [A] status=$PROBE_REASON answers=$PROBE_ANS" >> "$OUT"
      DNS_OK=$((DNS_OK + 1))
    else
      echo "СБОЙ $s [A] reason=$PROBE_REASON answers=$PROBE_ANS" >> "$OUT"
      add_cause "DNS сервер $s не резолвит $TEST_DOMAIN (A): $PROBE_REASON"
      DNS_FAIL=$((DNS_FAIL + 1))
    fi
    emit_fact resolver dns_server_probe "server=$s;rr=A;result=$PROBE_STATE;reason=$PROBE_REASON;answers=$PROBE_ANS" "dig"
  done
  emit_fact resolver dns_server_probe_total "$DNS_TOTAL" "dig"
  emit_fact resolver dns_server_probe_ok "$DNS_OK" "dig"
  emit_fact resolver dns_server_probe_fail "$DNS_FAIL" "dig"
  if [ "$DNS_OK" -gt 0 ]; then
    emit_fact resolver dns_servers_any_ok yes "dig"
  else
    emit_fact resolver dns_servers_any_ok no "dig"
  fi
  if [ "$DNS_TOTAL" -gt 0 ] && [ "$DNS_FAIL" -eq "$DNS_TOTAL" ]; then
    emit_fact resolver dns_servers_all_fail yes "dig"
  else
    emit_fact resolver dns_servers_all_fail no "dig"
  fi
  SYS_OK=0
  PROBE_RESULT="$(dig_probe "$TEST_DOMAIN_QUERY" A)"
  PROBE_STATE="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f1)"
  PROBE_REASON="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f2)"
  PROBE_ANS="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f3)"
  if [ "$PROBE_STATE" = "ok" ]; then
    echo "УСПЕХ системный резолвер [A] status=$PROBE_REASON answers=$PROBE_ANS" >> "$OUT"
    SYS_OK=$((SYS_OK + 1))
  else
    echo "СБОЙ системный резолвер [A] reason=$PROBE_REASON answers=$PROBE_ANS" >> "$OUT"
  fi
  emit_fact resolver system_probe "rr=A;result=$PROBE_STATE;reason=$PROBE_REASON;answers=$PROBE_ANS" "dig system"
  if [ "$SYS_OK" -gt 0 ]; then
    emit_fact resolver system_resolver_ok yes "dig system"
  else
    add_cause "Системный резолвер не резолвит $TEST_DOMAIN (A)"
    emit_fact resolver system_resolver_ok no "dig system"
  fi
elif command -v nslookup >/dev/null 2>&1; then
  emit_fact resolver probe_tool_available yes "nslookup"
  DNS_TOTAL=0
  DNS_FAIL=0
  DNS_OK=0
  for s in $DNS_SERVERS; do
    DNS_TOTAL=$((DNS_TOTAL + 1))
    NS_OUT="$(nslookup -timeout=2 "$TEST_DOMAIN_QUERY" "$s" 2>&1 || true)"
    if printf '%s\n' "$NS_OUT" | grep -Eiq 'NXDOMAIN|SERVFAIL|REFUSED|timed out|no servers could be reached'; then
      echo "СБОЙ $s [A] reason=$(printf '%s\n' "$NS_OUT" | head -1)" >> "$OUT"
      add_cause "DNS сервер не резолвит $TEST_DOMAIN: $s"
      DNS_FAIL=$((DNS_FAIL + 1))
      emit_fact resolver dns_server_probe "server=$s;rr=MIXED;result=fail;reason=NSLOOKUP_ERROR;answers=0" "nslookup"
    else
      echo "УСПЕХ $s [A]" >> "$OUT"
      DNS_OK=$((DNS_OK + 1))
      emit_fact resolver dns_server_probe "server=$s;rr=MIXED;result=ok;reason=NOERROR;answers=1" "nslookup"
    fi
  done
  emit_fact resolver dns_server_probe_total "$DNS_TOTAL" "nslookup"
  emit_fact resolver dns_server_probe_ok "$DNS_OK" "nslookup"
  emit_fact resolver dns_server_probe_fail "$DNS_FAIL" "nslookup"
  if [ "$DNS_OK" -gt 0 ]; then
    emit_fact resolver dns_servers_any_ok yes "nslookup"
  else
    emit_fact resolver dns_servers_any_ok no "nslookup"
  fi
  if [ "$DNS_TOTAL" -gt 0 ] && [ "$DNS_FAIL" -eq "$DNS_TOTAL" ]; then
    emit_fact resolver dns_servers_all_fail yes "nslookup"
  else
    emit_fact resolver dns_servers_all_fail no "nslookup"
  fi
  NS_SYS_OUT="$(nslookup -timeout=2 "$TEST_DOMAIN_QUERY" 2>&1 || true)"
  if printf '%s\n' "$NS_SYS_OUT" | grep -Eiq 'NXDOMAIN|SERVFAIL|REFUSED|timed out|no servers could be reached'; then
    echo "СБОЙ системный резолвер [A]" >> "$OUT"
    add_cause "Системный резолвер не резолвит $TEST_DOMAIN (nslookup)"
    emit_fact resolver system_resolver_ok no "nslookup system"
  else
    echo "УСПЕХ системный резолвер [A]" >> "$OUT"
    emit_fact resolver system_resolver_ok yes "nslookup system"
  fi
else
  echo "dig/nslookup не найден, пропуск проверки DNS" >> "$OUT"
  emit_fact resolver probe_tool_available no "dig/nslookup"
fi

say_step "12/12 Эвристика, scoped probe и итоговая классификация"
say_step_detail "Применяем эвристики causes (proxy/pf/hosts/resolver/utun)"
say_step_detail "SCUTIL_SCOPED_NS_PROBE: проверка домена по scoped nameserver"
say_step_detail "E2E curl probe: resolve/connect/tls/http"
say_step_detail "Формируем DNS_ONLY_RESULT, E2E_RESULT, PRIMARY_CLASSIFICATION и EVIDENCE_MATRIX"
# 12. Эвристика: возможные причины проблем с DNS
if ! printf '%s\n' "$SCUTIL_DNS_RAW" | grep -q "nameserver\\["; then
  add_cause "DNS серверы не обнаружены в scutil --dns"
  emit_fact resolver nameserver_missing yes "scutil --dns"
else
  emit_fact resolver nameserver_missing no "scutil --dns"
fi

if scutil --proxy | grep -Eq "HTTPEnable : 1|HTTPSEnable : 1|SOCKSEnable : 1|ProxyAutoConfigEnable : 1"; then
  add_cause "Системный прокси включен (scutil --proxy)"
  emit_fact interceptor system_proxy_enabled yes "scutil --proxy"
else
  emit_fact interceptor system_proxy_enabled no "scutil --proxy"
fi

if run_sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
  if run_sudo pfctl -s rules 2>/dev/null | grep -Eiq '(^|[[:space:]])(block|drop)[[:space:]]'; then
    add_cause "PF включен и есть block/drop правила: возможна фильтрация DNS"
    emit_fact policy pf_block_rules yes "pfctl -s rules"
  else
    emit_fact policy pf_block_rules no "pfctl -s rules"
  fi
fi

DNS_LISTEN="$({
  run_sudo lsof -nP -sTCP:LISTEN -iTCP:53 2>/dev/null | awk 'NR>1 {print $1}'
  run_sudo lsof -nP -iUDP:53 2>/dev/null | awk 'NR>1 {print $1}'
} | sort -u | grep -v mDNSResponder || true)"
if [ -n "$DNS_LISTEN" ]; then
  add_cause "Локальные процессы слушают 53 порт: $DNS_LISTEN"
  emit_fact interceptor local_dns_listener_present yes "lsof :53"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    emit_fact interceptor local_dns_listener_process "$p" "lsof :53"
  done <<< "$DNS_LISTEN"
else
  emit_fact interceptor local_dns_listener_present no "lsof :53"
fi

if [ -d /etc/resolver ] && ls /etc/resolver >/dev/null 2>&1; then
  add_cause "Есть кастомные resolver-файлы в /etc/resolver"
  echo -e "\n>> /etc/resolver (файлы)" >> "$OUT"
  ls -la /etc/resolver >> "$OUT" 2>&1
  emit_fact resolver custom_resolver_files yes "/etc/resolver"

  TEST_RESOLVER_SCOPE=no
  while IFS= read -r resolver_file; do
    resolver_name="$(basename "$resolver_file")"
    case "$TEST_DOMAIN" in
      "$resolver_name"|*."$resolver_name")
        TEST_RESOLVER_SCOPE=yes
        break
        ;;
    esac
  done < <(find /etc/resolver -maxdepth 1 -type f 2>/dev/null)
  emit_fact resolver test_domain_resolver_scope "$TEST_RESOLVER_SCOPE" "/etc/resolver scope"
  if [ "$TEST_RESOLVER_SCOPE" = "yes" ]; then
    add_cause "Для $TEST_DOMAIN действует кастомный /etc/resolver scope"
  fi
else
  emit_fact resolver custom_resolver_files no "/etc/resolver"
  emit_fact resolver test_domain_resolver_scope no "/etc/resolver scope"
fi

if grep -vE '^\s*#|^\s*$' /etc/hosts | grep -vE 'localhost|broadcasthost|ip6-' >/dev/null; then
  add_cause "Есть кастомные записи в /etc/hosts"
  emit_fact resolver custom_hosts_entries yes "/etc/hosts"

  TEST_DOMAIN_ERE="$(escape_ere "$TEST_DOMAIN")"
  if grep -vE '^\s*#|^\s*$' /etc/hosts | grep -Eiq "(^|[[:space:]])$TEST_DOMAIN_ERE([[:space:]]|$)"; then
    emit_fact resolver test_domain_hosts_override yes "/etc/hosts"
    add_cause "Домен $TEST_DOMAIN найден в /etc/hosts"
  else
    emit_fact resolver test_domain_hosts_override no "/etc/hosts"
  fi
else
  emit_fact resolver custom_hosts_entries no "/etc/hosts"
  emit_fact resolver test_domain_hosts_override no "/etc/hosts"
fi

if systemextensionsctl list 2>/dev/null | grep -Eiq 'activated[[:space:]]+enabled.*(tailscale|wireguard|cloudflare|nextdns|adguard|proton|mullvad|nord|surfshark|expressvpn|cisco|forti|globalprotect|littlesnitch|lulu|tripmode|clash|happ|ngate|v2ray|xray)'; then
  add_cause "Активны сетевые расширения VPN/фильтрации: возможна фильтрация DNS"
  emit_fact interceptor active_network_extension yes "systemextensionsctl list"
else
  emit_fact interceptor active_network_extension no "systemextensionsctl list"
fi

ACTIVE_UTUNS="$(ifconfig 2>/dev/null | awk 'BEGIN{RS="";} $1 ~ /^utun[0-9]+:$/ {if ($0 ~ /UP/ && $0 ~ /RUNNING/ && $0 ~ /inet /) {sub(":","",$1); print $1}}' | sort -u)"
if [ -n "$ACTIVE_UTUNS" ]; then
  add_cause "Активные utun-интерфейсы (UP+RUNNING+inet): $ACTIVE_UTUNS"
  emit_fact route active_utun yes "ifconfig utun*"
else
  emit_fact route active_utun no "ifconfig utun*"
fi
if [ -n "$DEFAULT_UTUNS_V4" ]; then
  DEFAULT_UTUNS_INLINE="$(printf '%s' "$DEFAULT_UTUNS_V4" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  add_cause "Маршрут по умолчанию через utun (IPv4 netstat -f inet): $DEFAULT_UTUNS_INLINE"
fi
if [ -n "${DEFAULT_ROUTE_IF:-}" ] && printf '%s' "$DEFAULT_ROUTE_IF" | grep -q '^utun'; then
  add_cause "Маршрут по умолчанию через utun (route get): $DEFAULT_ROUTE_IF"
fi

run_scoped_resolver_probes "$SCUTIL_DNS_RAW" "$TEST_DOMAIN_QUERY"
run_e2e_curl_probe "$TEST_DOMAIN" "$TEST_DOMAIN_QUERY"
render_dual_mode_sections
render_evidence_sections

echo -e "\n>> Возможные причины проблем с DNS" >> "$OUT"
if [ "${#CAUSES[@]}" -eq 0 ]; then
  echo "Не найдено явных причин по эвристикам" >> "$OUT"
else
  for c in "${CAUSES[@]}"; do
    echo "- $c" >> "$OUT"
  done
fi

flush_step_details

GREEN=$'\033[32m'
RED=$'\033[31m'
if [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$E2E_VERDICT" = "PASS" ]; then
  echo
  echo -e "${GREEN}ТЕСТ УСПЕШНО ПРОЙДЕН: хост доступен, TLS и HTTP в норме${RESET}"
elif [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$PRIMARY_CLASSIFICATION" = "tls_certificate_or_trust_issue" ]; then
  echo
  echo -e "${YELLOW}ТЕСТ ЧАСТИЧНО ПРОЙДЕН: хост доступен, но TLS сертификат не прошел проверку доверия${RESET}"
else
  echo
  echo -e "${RED}ТЕСТ НЕ ПРОЙДЕН: есть проблемы с доступностью, резолвингом или TLS${RESET}"
fi
if [ "${#CAUSES[@]}" -eq 0 ]; then
  echo "Не найдено явных проблем с DNS по эвристике."
else
  echo
  echo "Возможные проблемы:"
  for c in "${CAUSES[@]}"; do
    echo "- $c"
  done
fi
printf "\n${CYAN}Отчет сохранен в: ${MAGENTA}%s${RESET}\n\n" "$OUT"
