#!/bin/bash
# Description: Полная диагностика DNS/VPN/Proxy на macOS с классификацией причин и e2e-проверкой.
# Author: f0nwa
# Last Modified: 2026-10-08

set -u

SCRIPT_VERSION="2026-10-08"

# Язык интерфейса и отчёта: DNS_DIAG_LANG=ru|en, иначе по языку macOS (русский или английский).
# tx "english" "русский" печатает строку на выбранном языке.
LANG_UI=en
detect_lang() {
  local first="" home=""
  case "${DNS_DIAG_LANG:-}" in
    ru*|RU*) LANG_UI=ru; return 0 ;;
    en*|EN*) LANG_UI=en; return 0 ;;
  esac
  # Под sudo `defaults -g` прочитал бы настройки root: берём настройки реального пользователя.
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    home="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [ -n "$home" ]; then
      first="$(defaults read "$home/Library/Preferences/.GlobalPreferences" AppleLanguages 2>/dev/null | sed -n '2p')"
    fi
  fi
  [ -n "$first" ] || first="$(defaults read -g AppleLanguages 2>/dev/null | sed -n '2p')"
  [ -n "$first" ] || first="${LC_ALL:-${LANG:-}}"
  first="$(printf '%s' "$first" | tr -d ' "' | tr '[:upper:]' '[:lower:]')"
  case "$first" in
    ru*) LANG_UI=ru ;;
    *) LANG_UI=en ;;
  esac
}
tx() {
  if [ "$LANG_UI" = "ru" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi
}
detect_lang

FLAG_DOMAIN=""
FLAG_YES=0
FLAG_OUTPUT=""
FLAG_VERIFY_INTEGRITY=0
FLAG_NO_EXTERNAL_DNS=0
FLAG_NO_OPEN=0
for _arg in "$@"; do
  case "$_arg" in
    --domain=*) FLAG_DOMAIN="${_arg#--domain=}" ;;
    --yes) FLAG_YES=1 ;;
    --output=*) FLAG_OUTPUT="${_arg#--output=}" ;;
    --verify-integrity) FLAG_VERIFY_INTEGRITY=1 ;;
    --no-external-dns) FLAG_NO_EXTERNAL_DNS=1 ;;
    --no-open) FLAG_NO_OPEN=1 ;;
    -h|--help)
      if [ "$LANG_UI" = "ru" ]; then
        cat <<'USAGE'
Usage: macos-dns-test.sh [--domain=<host>] [--yes] [--output=<path>] [--verify-integrity] [--no-external-dns] [--no-open]

  --domain=<host>       Пропустить интерактивный ввод, тестировать этот домен.
  --yes                 Автоматически подтверждать все y/n запросы (в т.ч. установку Homebrew/python3).
  --output=<path>       Писать отчёт в указанный файл вместо ./<user>_<host>_dns_diag_<ts>.txt.
  --verify-integrity    Перед запуском сверить свой sha256 с checksums.txt из репозитория
                        (требует локальный клон: scripts/integrity-lib.sh должен лежать
                        рядом со скриптом; для one-liner "curl | bash" эта проверка
                        недоступна, см. README).
  --no-external-dns     Не делать дополнительные запросы к независимым внешним DNS/DoH
                        (1.1.1.1, 8.8.8.8, Cloudflare/Google DoH).
  --no-open             Не открывать Finder с выделенным отчётом после завершения.

Без флагов скрипт работает как раньше, в интерактивном режиме.
USAGE
      else
        cat <<'USAGE'
Usage: macos-dns-test.sh [--domain=<host>] [--yes] [--output=<path>] [--verify-integrity] [--no-external-dns] [--no-open]

  --domain=<host>       Skip the interactive prompt and test this domain.
  --yes                 Automatically confirm all y/n questions (including installing Homebrew/python3).
  --output=<path>       Write the report to this file instead of ./<user>_<host>_dns_diag_<ts>.txt.
  --verify-integrity    Before running, compare the script's sha256 with checksums.txt from the repository
                        (needs a local clone: scripts/integrity-lib.sh must sit next to the script;
                        not available for the "curl | bash" one-liner, see the README).
  --no-external-dns     Do not make extra queries to independent external DNS/DoH
                        (1.1.1.1, 8.8.8.8, Cloudflare/Google DoH).
  --no-open             Do not open Finder with the report highlighted when finished.

Without flags the script runs interactively.
USAGE
      fi
      exit 0
      ;;
    *)
      echo "$(tx "Unknown argument: $_arg (see --help)" "Неизвестный аргумент: $_arg (см. --help)")" >&2
      exit 2
      ;;
  esac
done

if [ "$FLAG_VERIFY_INTEGRITY" = "1" ]; then
  _self_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  if [ -n "$_self_dir" ] && [ -r "$_self_dir/scripts/integrity-lib.sh" ]; then
    # shellcheck source=scripts/integrity-lib.sh
    source "$_self_dir/scripts/integrity-lib.sh"
    if ! dns_diag_verify_self "$_self_dir/macos-dns-test.sh"; then
      echo "$(tx "Integrity check failed. Aborting (--verify-integrity)." "Проверка целостности не пройдена. Прерываю выполнение (--verify-integrity).")" >&2
      exit 1
    fi
    echo "$(tx "Integrity check passed (checksums.txt)." "Проверка целостности пройдена (checksums.txt).")"
  else
    echo "$(tx "scripts/integrity-lib.sh not found next to the script: --verify-integrity is unavailable in this run mode (for example, with curl | bash)." "Не найден scripts/integrity-lib.sh рядом со скриптом — --verify-integrity недоступен в этом режиме запуска (например, при curl | bash).")" >&2
    exit 1
  fi
fi

if [ -t 1 ]; then
  clear
fi

# Цвета только в терминале и без NO_COLOR (https://no-color.org).
ESC=$'\033'
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="${ESC}[1m"
  CYAN="${ESC}[36m"
  GREEN="${ESC}[32m"
  YELLOW="${ESC}[33m"
  RED="${ESC}[31m"
  MAGENTA="${ESC}[35m"
  DETAIL="${ESC}[90m"
  RESET="${ESC}[0m"
else
  BOLD="" CYAN="" GREEN="" YELLOW="" RED="" MAGENTA="" DETAIL="" RESET=""
fi

# Единый вид вывода: заголовок блока, серая деталь, и строки с маркером результата.
title() {
  printf '\n%s%s%s%s\n' "$BOLD" "$CYAN" "$1" "$RESET"
}
info() {
  printf '  %s%s%s\n' "$DETAIL" "$1" "$RESET"
}
warn() {
  printf '  %s! %s%s\n' "$YELLOW" "$1" "$RESET"
}
fail() {
  printf '  %s✗ %s%s\n' "$RED" "$1" "$RESET"
}
ok() {
  printf '  %s✓%s %s%s%s\n' "$GREEN" "$RESET" "$DETAIL" "$1" "$RESET"
}

# Читаем интерактивные ответы из TTY, даже если скрипт запускается из pipe.
if [ -r /dev/tty ]; then
  exec 3</dev/tty
else
  exec 3<&0
fi

say_step() {
  flush_step_details
  title "$1"
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
  max_len=$((cols - 8))
  if [ "$max_len" -lt 20 ]; then
    max_len=20
  fi
  if [ "${#message}" -gt "$max_len" ]; then
    display_message="${message:0:$((max_len - 3))}..."
  else
    display_message="$message"
  fi
  # Без собственного trap: спиннер завершается только KILL (см. stop_step_spinner).
  (
    local f
    while :; do
      for f in ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏; do
        printf "\r\033[2K  %s%s%s %s%s%s" "$CYAN" "$f" "$RESET" "$DETAIL" "$display_message" "$RESET"
        sleep 0.1
      done
    done
  ) &
  SPINNER_PID=$!
}
stop_step_spinner() {
  if [ -n "${SPINNER_PID:-}" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
    # Только KILL, не TERM:
    # - подоболочка наследует глобальный `trap ... TERM`; если TERM приходит в
    #   первые мгновения после fork (подряд идущие say_step_detail), bash 3.2
    #   печатает "run_pending_traps: bad value in trap_list[15]: 0x0";
    # - остановленный (SIGSTOP/SIGTTOU) процесс TERM не получит, и `wait`
    #   повиснет навсегда, а KILL доставляется и остановленному процессу.
    kill -KILL "$SPINNER_PID" 2>/dev/null || true
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
run_with_timeout() {
  # Портативный аналог `timeout N cmd...`: в BSD/macOS нет системной утилиты
  # timeout (это GNU coreutils), а полагаться на её наличие у конечного
  # пользователя нельзя (скрипт запускается как `curl | bash` на голой
  # macOS). Убивает команду по SIGTERM, если она не уложилась в N секунд.
  local secs="$1"; shift
  "$@" &
  local cmd_pid=$!
  ( sleep "$secs"; kill -TERM "$cmd_pid" 2>/dev/null ) &
  local watchdog_pid=$!
  wait "$cmd_pid" 2>/dev/null
  local rc=$?
  # KILL, а не TERM: сторож наследует глобальный trap TERM, и ранний TERM
  # в bash 3.2 даёт "run_pending_traps: bad value in trap_list[15]".
  kill -KILL "$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null
  return "$rc"
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
  title "$(tx "Administrator rights required" "Требуются права администратора")"
  info "$(tx "You will now be asked for the local password of your macOS account (the one you use to log in)." "Сейчас потребуется ввести локальный пароль от вашей учётной записи macOS (тот, которым вы входите в систему).")"
  info "$(tx "Characters are not shown while you type, this is normal. Press Enter when done." "Символы при вводе не отображаются, это нормально. После ввода нажмите Enter.")"
  printf '\n'
  if sudo -v -p "$(tx "Mac account password: " "Пароль учётной записи Mac: ")"; then
    (
      while :; do
        sudo -n true 2>/dev/null || exit 0
        sleep 50
      done
    ) &
    SUDO_KEEPALIVE_PID=$!
  else
    warn "$(tx "Could not obtain a sudo session in advance. You may be asked for the password again during the diagnostics." "Не удалось получить sudo-сессию заранее. Возможны дополнительные запросы пароля в ходе диагностики.")"
  fi
}
flush_step_details() {
  local item=""
  if [ "${#STEP_DETAILS[@]}" -eq 0 ]; then
    return
  fi
  stop_step_spinner
  for item in "${STEP_DETAILS[@]}"; do
    ok "$item"
  done
  STEP_DETAILS=()
}
trap 'stop_sudo_keepalive' EXIT INT TERM

USER_TAG="${USER:-user}"
HOST_TAG="$(hostname -s 2>/dev/null || echo host)"
TS_TAG="$(date +%Y%m%d_%H%M%S)"
if [ -n "$FLAG_OUTPUT" ]; then
  OUT="$FLAG_OUTPUT"
else
  OUT="$(pwd)/${USER_TAG}_${HOST_TAG}_dns_diag_${TS_TAG}.txt"
fi
echo "$(tx ">> DNS+VPN/Proxy full diagnostics ($(date))" ">> DNS+VPN/Прокси Диагностика Полная ($(date))")" > "$OUT"
echo -e "\n>> RAW_APPENDIX" >> "$OUT"

title "$(tx "DNS / VPN / Proxy diagnostics for macOS" "Диагностика DNS / VPN / Прокси на macOS")"
info "$(tx "User: ${USER_TAG}" "Пользователь: ${USER_TAG}")"
info "$(tx "Host: ${HOST_TAG}   Script version: ${SCRIPT_VERSION}" "Хост: ${HOST_TAG}   Версия скрипта: ${SCRIPT_VERSION}")"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo -e "\n>> PRIVILEGE_NOTICE" >> "$OUT"
  echo "run_mode=non_root; elevated_steps_require_sudo=yes" >> "$OUT"
fi

CAUSES=()
add_cause() { CAUSES+=("$1"); }
# Информационные заметки: факты, которые стоит показать, но которые не являются
# проблемой (например, ожидаемый NXDOMAIN от локального DNS при split-DNS через VPN).
NOTES=()
add_note() { NOTES+=("$1"); }
# Ограничения проверки: шаги, которые не удалось выполнить полностью (например,
# macOS не дала доступ к папкам). Наличие хотя бы одной записи = отчёт неполный.
COVERAGE_GAPS=()
add_coverage_gap() { COVERAGE_GAPS+=("$1"); }
# Отказы отдельных DNS-серверов ("server|reason"). Решение, проблема это или
# ожидаемое поведение split-DNS, принимает classify_dns_server_failures().
DNS_SERVER_FAILS=()

ask_yes_no() {
  # ask_yes_no "вопрос" [y|n — ответ по умолчанию, n если не указан] ["описание"]
  # Возвращает 0 для «да» и 1 для «нет»; повторяет запрос до корректного ответа.
  local question="$1" default="${2:-n}" desc="${3:-}" hint reply="" line
  printf '\n%s?%s %s%s%s\n' "$CYAN" "$RESET" "$BOLD" "$question" "$RESET"
  if [ -n "$desc" ]; then
    while IFS= read -r line; do
      printf '  %s%s%s\n' "$DETAIL" "$line" "$RESET"
    done <<< "$desc"
  fi
  if [ "$FLAG_YES" = "1" ]; then
    printf '  %s›%s %s%s%s\n' "$YELLOW" "$RESET" "$DETAIL" "$(tx "yes (auto, --yes)" "да (авто, --yes)")" "$RESET"
    return 0
  fi
  if [ "$LANG_UI" = "ru" ]; then
    if [ "$default" = "y" ]; then hint="[Д/н]"; else hint="[д/Н]"; fi
  else
    if [ "$default" = "y" ]; then hint="[Y/n]"; else hint="[y/N]"; fi
  fi
  while :; do
    printf '  %s›%s %s%s%s ' "$YELLOW" "$RESET" "$YELLOW" "$hint" "$RESET"
    read -r -u 3 reply || return 1
    case "${reply:-}" in
      "") [ "$default" = "y" ]; return ;;
      y|Y|yes|YES|д|Д|да|Да|ДА) return 0 ;;
      n|N|no|NO|н|Н|нет|Нет|НЕТ) return 1 ;;
      *) warn "$(tx "Please answer y or n." "Введите д или н.")" ;;
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
  # Вывод в stdout: result|reason|answers|ips
  # result: ok|fail; reason: NOERROR|NODATA|NXDOMAIN|SERVFAIL|REFUSED|TIMEOUT|UNKNOWN
  # ips: адреса из секции ANSWER через запятую (или "-", если их нет)
  # transport: udp (по умолчанию) | tcp — для отличия "DNS сломан" от "порт 53 фильтруется"
  local domain="$1" rr="$2" server="${3:-}" transport="${4:-udp}" out status answer ips
  local dig_extra=""
  [ "$transport" = "tcp" ] && dig_extra="+tcp"
  if [ -n "$server" ]; then
    # shellcheck disable=SC2086
    out="$(dig +time=2 +tries=1 +noall +comments +answer $dig_extra "$domain" "$rr" @"$server" 2>&1)"
  else
    # shellcheck disable=SC2086
    out="$(dig +time=2 +tries=1 +noall +comments +answer $dig_extra "$domain" "$rr" 2>&1)"
  fi

  status="$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z][A-Z]*\),.*/\1/p' | head -1)"
  answer="$(printf '%s\n' "$out" | sed -n 's/.*ANSWER: \([0-9][0-9]*\).*/\1/p' | head -1)"
  [ -z "$answer" ] && answer=0
  ips="$(printf '%s\n' "$out" | awk -v want="$rr" '$0 !~ /^;/ && NF >= 5 && $4 == want {print $5}' | paste -sd, -)"
  [ -z "$ips" ] && ips="-"

  if printf '%s\n' "$out" | grep -Eiq 'timed out|no servers could be reached'; then
    echo "fail|TIMEOUT|$answer|-"
  elif [ "$status" = "NOERROR" ] && [ "$answer" -gt 0 ]; then
    echo "ok|NOERROR|$answer|$ips"
  elif [ "$status" = "NOERROR" ] && [ "$answer" -eq 0 ]; then
    echo "fail|NODATA|0|-"
  elif [ -n "$status" ]; then
    echo "fail|$status|$answer|-"
  else
    echo "fail|UNKNOWN|$answer|-"
  fi
}

nslookup_probe() {
  # Вывод в stdout: result|reason|answers|ips
  local domain="$1" server="${2:-}" out ips
  if [ -n "$server" ]; then
    out="$(nslookup -timeout=2 "$domain" "$server" 2>&1 || true)"
  else
    out="$(nslookup -timeout=2 "$domain" 2>&1 || true)"
  fi
  # Строка сервера в выводе nslookup имеет вид "Address: 1.2.3.4#53" — исключаем
  # её через "$" (конец строки сразу после адреса), чтобы не принять адрес
  # самого резолвера за адрес домена.
  ips="$(printf '%s\n' "$out" | grep -E '^Address:[[:space:]]*[0-9a-fA-F:.]+$' | awk '{print $2}' | paste -sd, -)"
  [ -z "$ips" ] && ips="-"
  if printf '%s\n' "$out" | grep -Eiq 'timed out|no servers could be reached'; then
    echo "fail|TIMEOUT|0|-"
  elif printf '%s\n' "$out" | grep -Eiq 'NXDOMAIN'; then
    echo "fail|NXDOMAIN|0|-"
  elif printf '%s\n' "$out" | grep -Eiq 'SERVFAIL'; then
    echo "fail|SERVFAIL|0|-"
  elif printf '%s\n' "$out" | grep -Eiq 'REFUSED'; then
    echo "fail|REFUSED|0|-"
  elif [ "$ips" != "-" ]; then
    echo "ok|NOERROR|1|$ips"
  else
    echo "fail|UNKNOWN|0|-"
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

# Независимые от локальной сети резолверы для контрольных проверок (не входят
# в DNS_SERVERS, обнаруженные из scutil/networksetup/resolv.conf).
EXTERNAL_DNS_SERVERS="1.1.1.1 8.8.8.8"
EXTERNAL_PROBE_SKIPPED=0
EXTERNAL_ANY_OK=0
EXTERNAL_DOH_OK=0
EXTERNAL_UDP53_ANY_OK=0

ip_is_private() {
  # 0 (true), если это приватный/зарезервированный/loopback/CGNAT IPv4-адрес.
  # Для не-IPv4 (например IPv6) или мусора возвращает 1 (не считаем приватным
  # по этой эвристике) — этого достаточно, т.к. сейчас проверяются только A-записи.
  local ip="$1" a b c d
  case "$ip" in
    ""|"-") return 1 ;;
  esac
  IFS='.' read -r a b c d <<< "$ip"
  case "$a$b$c$d" in
    *[!0-9]*|"") return 1 ;;
  esac
  [ "$a" -eq 10 ] && return 0
  [ "$a" -eq 127 ] && return 0
  [ "$a" -eq 0 ] && return 0
  [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 0
  [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 0
  [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 0
  [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 0
  return 1
}

doh_probe() {
  # Вывод в stdout: provider|result|reason|ips
  # DNS-over-HTTPS к независимому провайдеру (порт 443) в обход UDP/TCP-53 —
  # показывает, блокируется ли именно DNS-порт, а не сеть целиком.
  local domain="$1" rr="$2" provider="$3" url out status ips
  case "$provider" in
    cloudflare) url="https://cloudflare-dns.com/dns-query?name=${domain}&type=${rr}" ;;
    google) url="https://dns.google/resolve?name=${domain}&type=${rr}" ;;
    *) echo "$provider|fail|UNKNOWN_PROVIDER|-"; return ;;
  esac
  out="$(curl -s -m 3 --connect-timeout 3 -H 'accept: application/dns-json' "$url" 2>/dev/null)"
  if [ -z "$out" ]; then
    echo "$provider|fail|NO_RESPONSE|-"
    return
  fi
  status="$(printf '%s' "$out" | sed -n 's/.*"Status":\([0-9]*\).*/\1/p' | head -1)"
  ips="$(printf '%s' "$out" | grep -Eo '"data":"[0-9.]+"' | sed -E 's/"data":"([0-9.]+)"/\1/' | paste -sd, -)"
  [ -z "$ips" ] && ips="-"
  if [ "$status" = "0" ] && [ "$ips" != "-" ]; then
    echo "$provider|ok|NOERROR|$ips"
  elif [ "$status" = "0" ]; then
    echo "$provider|fail|NODATA|-"
  elif [ "$status" = "3" ]; then
    echo "$provider|fail|NXDOMAIN|-"
  else
    echo "$provider|fail|UNKNOWN|-"
  fi
}

run_scoped_resolver_probes() {
  local snapshot="$1" domain="$2"
  local resolver_id if_index iface flags reach ns
  local res_a st_a rs_a an_a ip_a
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
    ip_a="$(printf '%s' "$res_a" | cut -d'|' -f4)"

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

    echo "resolver#$resolver_id if_index=$if_index iface=${iface:-unknown} ns=$ns flags=${flags:-n/a} reach=${reach:-n/a} A=${st_a}/${rs_a}/${an_a} ips=$ip_a" >> "$OUT"
    emit_fact resolver scoped_probe "resolver=$resolver_id;if_index=$if_index;iface=${iface:-unknown};ns=$ns;a=$st_a/$rs_a/$an_a;ips=$ip_a;ok=$ns_ok" "scutil scoped"
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

classify_dns_server_failures() {
  # Разделяет отказы отдельных DNS-серверов на ожидаемые и реальные проблемы.
  # Ожидаемый случай — split-DNS: системный резолвер домен находит (через VPN/utun
  # или /etc/resolver scope), а остальные серверы (роутер, провайдер) честно
  # отвечают NXDOMAIN/NODATA, потому что домен им неизвестен. Это не сбой, а
  # норма, и в "$(tx "Possible problems" "Возможные проблемы")" такое попадать не должно.
  # Таймауты, SERVFAIL, REFUSED и любые отказы при неработающем системном
  # резолвере по-прежнему считаются проблемами.
  local item srv reason iface expected_list="" expected=0 unexpected=0

  # ${arr[@]+...}: пустой массив под set -u в bash 3.2 (штатный /bin/bash macOS) иначе падает.
  for item in ${DNS_SERVER_FAILS[@]+"${DNS_SERVER_FAILS[@]}"}; do
    srv="${item%%|*}"
    reason="${item#*|}"
    if has_fact resolver system_resolver_ok yes && { [ "$reason" = "NXDOMAIN" ] || [ "$reason" = "NODATA" ]; }; then
      expected=$((expected + 1))
      iface="$(awk -F'\t' -v s="$srv" '
        $2=="resolver" && $3=="scoped_probe" && $4 ~ ("(^|;)ns=" s ";") {
          if (match($4, /iface=[^;]*/)) { v = substr($4, RSTART + 6, RLENGTH - 6); if (v != "na" && v != "unknown") { print v; exit } }
        }' "$FACTS_FILE")"
      expected_list="${expected_list:+$expected_list, }$srv${iface:+ ($iface)}"
    else
      unexpected=$((unexpected + 1))
      add_cause "$(tx "DNS server $srv does not resolve $TEST_DOMAIN (A): $reason" "DNS сервер $srv не резолвит $TEST_DOMAIN (A): $reason")"
    fi
  done

  if [ "$expected" -gt 0 ]; then
    if [ "$SCOPED_OK_UTUN" -gt 0 ] && [ "$SCOPED_OK_NONUTUN" -eq 0 ]; then
      add_note "$(tx "$TEST_DOMAIN resolves only through the VPN (utun); other DNS servers do not know it: expected for split DNS: $expected_list" "$TEST_DOMAIN резолвится только через VPN (utun); остальные DNS его не знают — ожидаемо для split-DNS: $expected_list")"
    else
      add_note "$(tx "DNS servers do not know $TEST_DOMAIN (NXDOMAIN/NODATA), but the system resolver resolves it: expected for split DNS: $expected_list" "DNS серверы не знают $TEST_DOMAIN (NXDOMAIN/NODATA), но системный резолвер его резолвит — ожидаемо для split-DNS: $expected_list")"
    fi
  fi

  emit_fact resolver dns_server_probe_fail_expected "$expected" "split-dns classification"
  emit_fact resolver dns_server_probe_fail_unexpected "$unexpected" "split-dns classification"
}

run_external_dns_probes() {
  # Пробы через заведомо независимые от локальной сети резолверы (1.1.1.1/8.8.8.8):
  # UDP-53, TCP-53 и DoH (443). Позволяет отличить "сломано локально" от "домен
  # реально недоступен/фильтруется снаружи" и поймать избирательную блокировку
  # именно DNS-порта (частый паттерн провайдерской фильтрации).
  local domain="$1" srv res state reason ans ips provider
  local total_count=0 timeout_count=0

  echo -e "\n>> EXTERNAL_DNS_PROBE" >> "$OUT"

  if [ "$FLAG_NO_EXTERNAL_DNS" = "1" ]; then
    EXTERNAL_PROBE_SKIPPED=1
    echo "skipped=yes reason=disabled_by_flag" >> "$OUT"
    emit_fact external probe_skipped yes "disabled_by_flag(--no-external-dns)"
    return
  fi
  emit_fact external probe_skipped no "enabled"

  for srv in $EXTERNAL_DNS_SERVERS; do
    if command -v dig >/dev/null 2>&1; then
      res="$(dig_probe "$domain" A "$srv" udp)"
    else
      res="$(nslookup_probe "$domain" "$srv")"
    fi
    state="$(printf '%s' "$res" | cut -d'|' -f1)"
    reason="$(printf '%s' "$res" | cut -d'|' -f2)"
    ans="$(printf '%s' "$res" | cut -d'|' -f3)"
    ips="$(printf '%s' "$res" | cut -d'|' -f4)"
    total_count=$((total_count + 1))
    [ "$reason" = "TIMEOUT" ] && timeout_count=$((timeout_count + 1))
    if [ "$state" = "ok" ]; then
      EXTERNAL_ANY_OK=1
      EXTERNAL_UDP53_ANY_OK=1
    fi
    echo "udp53 server=$srv result=$state reason=$reason answers=$ans ips=$ips" >> "$OUT"
    emit_fact external dns_probe "server=$srv;transport=udp;result=$state;reason=$reason;answers=$ans;ips=$ips" "dig external"

    if command -v dig >/dev/null 2>&1; then
      res="$(dig_probe "$domain" A "$srv" tcp)"
      state="$(printf '%s' "$res" | cut -d'|' -f1)"
      reason="$(printf '%s' "$res" | cut -d'|' -f2)"
      ips="$(printf '%s' "$res" | cut -d'|' -f4)"
      echo "tcp53 server=$srv result=$state reason=$reason ips=$ips" >> "$OUT"
      emit_fact external dns_probe_tcp "server=$srv;transport=tcp;result=$state;reason=$reason;ips=$ips" "dig +tcp external"
    fi
  done

  if command -v curl >/dev/null 2>&1; then
    for provider in cloudflare google; do
      res="$(doh_probe "$domain" A "$provider")"
      state="$(printf '%s' "$res" | cut -d'|' -f2)"
      reason="$(printf '%s' "$res" | cut -d'|' -f3)"
      ips="$(printf '%s' "$res" | cut -d'|' -f4)"
      total_count=$((total_count + 1))
      [ "$reason" = "NO_RESPONSE" ] && timeout_count=$((timeout_count + 1))
      if [ "$state" = "ok" ]; then
        EXTERNAL_ANY_OK=1
        EXTERNAL_DOH_OK=1
      fi
      echo "doh provider=$provider result=$state reason=$reason ips=$ips" >> "$OUT"
      emit_fact external doh_probe "provider=$provider;result=$state;reason=$reason;ips=$ips" "curl DoH"
      [ "$state" = "ok" ] && break
    done
  fi

  emit_fact external any_ok "$([ "$EXTERNAL_ANY_OK" -eq 1 ] && echo yes || echo no)" "external probes"
  if [ "$total_count" -gt 0 ] && [ "$timeout_count" -eq "$total_count" ]; then
    emit_fact external all_timeout yes "external probes"
  else
    emit_fact external all_timeout no "external probes"
  fi
  if [ "$EXTERNAL_UDP53_ANY_OK" -eq 0 ] && [ "$EXTERNAL_DOH_OK" -eq 1 ]; then
    emit_fact external udp53_blocked_but_doh_ok yes "external probes"
  else
    emit_fact external udp53_blocked_but_doh_ok no "external probes"
  fi
  echo "any_ok=$([ "$EXTERNAL_ANY_OK" -eq 1 ] && echo yes || echo no)" >> "$OUT"
}

run_cross_resolver_consistency_check() {
  # Сравнивает реальные IP-ответы всех уже опрошенных резолверов (обнаруженные
  # системой DNS-серверы, системный резолвер по умолчанию, scoped-резолверы по
  # интерфейсам, независимые внешние) между собой. Расхождение — особенно с
  # приватным/зарезервированным IP у одного из резолверов — куда показательнее,
  # чем отдельные ok/fail по каждому резолверу.
  local consensus mismatch_count=0 private_suspect_count=0
  local utun_mismatch=0 nonutun_mismatch=0
  local label ips_val is_utun ip is_priv

  echo -e "\n>> CROSS_RESOLVER_CONSISTENCY" >> "$OUT"

  consensus="$(awk -F'\t' '
    $2=="resolver" && $3=="dns_server_probe" && $4 ~ /result=ok/ { collect() }
    $2=="resolver" && $3=="system_probe" && $4 ~ /result=ok/ { collect() }
    $2=="resolver" && $3=="scoped_probe" && $4 ~ /a=ok\// { collect() }
    $2=="external" && ($3=="dns_probe" || $3=="doh_probe") && $4 ~ /result=ok/ { collect() }
    function collect() {
      if (match($4, /ips=[^;]*/)) {
        v = substr($4, RSTART + 4, RLENGTH - 4)
        if (v != "-" && v != "") cnt[v]++
      }
    }
    END {
      max = 0; best = "-"
      for (k in cnt) if (cnt[k] > max) { max = cnt[k]; best = k }
      print best
    }' "$FACTS_FILE")"
  [ -z "$consensus" ] && consensus="-"

  emit_fact resolver cross_consensus_ip "$consensus" "cross-resolver check"
  echo "consensus_ip=$consensus" >> "$OUT"

  while IFS=$'\t' read -r label ips_val is_utun; do
    [ -z "$label" ] && continue
    if [ "$ips_val" = "-" ] || [ -z "$ips_val" ]; then
      continue
    fi
    if [ "$consensus" = "-" ] || [ "$ips_val" = "$consensus" ]; then
      echo "$label ips=$ips_val consistent=yes" >> "$OUT"
      continue
    fi
    mismatch_count=$((mismatch_count + 1))
    is_priv=no
    IFS=',' read -ra _cross_ip_arr <<< "$ips_val"
    for ip in "${_cross_ip_arr[@]}"; do
      [ -z "$ip" ] && continue
      if ip_is_private "$ip"; then
        is_priv=yes
        break
      fi
    done
    [ "$is_priv" = "yes" ] && private_suspect_count=$((private_suspect_count + 1))
    case "$is_utun" in
      yes) utun_mismatch=$((utun_mismatch + 1)) ;;
      no) nonutun_mismatch=$((nonutun_mismatch + 1)) ;;
    esac
    echo "$label ips=$ips_val consistent=no private_ip_suspect=$is_priv" >> "$OUT"
    emit_fact resolver cross_mismatch "label=$label;ips=$ips_val;private_ip_suspect=$is_priv;utun=$is_utun" "cross-resolver check"
  done < <(awk -F'\t' '
      $2=="resolver" && $3=="dns_server_probe" && $4 ~ /result=ok/ {
        s = "?"; i = "-"
        if (match($4, /server=[^;]*/)) s = substr($4, RSTART + 7, RLENGTH - 7)
        if (match($4, /ips=[^;]*/)) i = substr($4, RSTART + 4, RLENGTH - 4)
        print "dns_server:" s "\t" i "\tn/a"
      }
      $2=="resolver" && $3=="system_probe" && $4 ~ /result=ok/ {
        i = "-"
        if (match($4, /ips=[^;]*/)) i = substr($4, RSTART + 4, RLENGTH - 4)
        print "system_default\t" i "\tn/a"
      }
      $2=="resolver" && $3=="scoped_probe" && $4 ~ /a=ok\// {
        rid = "?"; ifc = "?"; i = "-"
        if (match($4, /resolver=[0-9]+/)) rid = substr($4, RSTART + 9, RLENGTH - 9)
        if (match($4, /iface=[^;]*/)) ifc = substr($4, RSTART + 6, RLENGTH - 6)
        if (match($4, /ips=[^;]*/)) i = substr($4, RSTART + 4, RLENGTH - 4)
        u = (ifc ~ /^utun/) ? "yes" : "no"
        print "scoped#" rid "/" ifc "\t" i "\t" u
      }
      $2=="external" && $3=="dns_probe" && $4 ~ /result=ok/ {
        s = "?"; i = "-"
        if (match($4, /server=[^;]*/)) s = substr($4, RSTART + 7, RLENGTH - 7)
        if (match($4, /ips=[^;]*/)) i = substr($4, RSTART + 4, RLENGTH - 4)
        print "external:" s "\t" i "\tn/a"
      }
      $2=="external" && $3=="doh_probe" && $4 ~ /result=ok/ {
        p = "?"; i = "-"
        if (match($4, /provider=[^;]*/)) p = substr($4, RSTART + 9, RLENGTH - 9)
        if (match($4, /ips=[^;]*/)) i = substr($4, RSTART + 4, RLENGTH - 4)
        print "doh:" p "\t" i "\tn/a"
      }
    ' "$FACTS_FILE")

  emit_fact resolver cross_mismatch_count "$mismatch_count" "cross-resolver check"
  emit_fact resolver cross_private_ip_suspect_count "$private_suspect_count" "cross-resolver check"
  if [ "$utun_mismatch" -gt 0 ] && [ "$nonutun_mismatch" -eq 0 ]; then
    emit_fact route cross_mismatch_utun_only yes "cross-resolver check"
  else
    emit_fact route cross_mismatch_utun_only no "cross-resolver check"
  fi
  if [ "$nonutun_mismatch" -gt 0 ] && [ "$utun_mismatch" -eq 0 ]; then
    emit_fact interceptor cross_mismatch_nonutun_only yes "cross-resolver check"
  else
    emit_fact interceptor cross_mismatch_nonutun_only no "cross-resolver check"
  fi

  echo "mismatch_count=$mismatch_count" >> "$OUT"
  echo "private_ip_suspect_count=$private_suspect_count" >> "$OUT"
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
  emit_fact e2e dns_time_sec "${t_dns:-0}" "curl"
  emit_fact e2e note "$note" "curl"
  emit_fact e2e verdict "$E2E_VERDICT" "curl"

  echo -e "\n>> E2E_CURL_TRACE ($url_display)" >> "$OUT"
  if [ "$url_probe" != "$url_display" ]; then
    echo "curl_probe_url=$url_probe" >> "$OUT"
  fi
  echo "curl_timing: dns=${t_dns:-0}s connect=${t_conn:-0}s tls=${t_tls:-0}s" >> "$OUT"
  sed -n '1,80p' "$curl_log" >> "$OUT" 2>/dev/null || true
}

render_dual_mode_sections() {
  local resolvers_tested a_ok total_fail dominant_failure system_ok
  local dns_ok e2e_ok e2e_resolve e2e_connect e2e_tls e2e_note
  local host_reachable tls_trust_ok human_status

  resolvers_tested="$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_count"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")"
  a_ok="$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_probe"&&$4 ~ /rr=A;/&&$4 ~ /result=ok/{c++} END{print c+0}' "$FACTS_FILE")"
  # Ожидаемые отказы split-DNS (см. classify_dns_server_failures) не деградируют вердикт.
  total_fail="$(awk -F'\t' '
    $2=="resolver"&&$3=="dns_server_probe_fail"{all=$4}
    $2=="resolver"&&$3=="dns_server_probe_fail_unexpected"{u=$4; has_u=1}
    END{v = has_u ? u : all; if(v=="") v=0; print v}' "$FACTS_FILE")"
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
    add_cause "$(tx "DNS tools returned NXDOMAIN but the e2e resolve succeeded: possible IDN/resolver mismatch (query=$TEST_DOMAIN_QUERY)" "DNS-инструменты дали NXDOMAIN, но e2e resolve успешен: возможен mismatch IDN/резолвера (query=$TEST_DOMAIN_QUERY)")"
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
  echo "split_dns_expected_fail=$(awk -F'\t' '$2=="resolver"&&$3=="dns_server_probe_fail_expected"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")" >> "$OUT"
  echo "scoped_resolvers_tested=$SCOPED_TESTED" >> "$OUT"
  echo "scoped_resolvers_ok=$SCOPED_OK" >> "$OUT"
  echo "scoped_resolvers_fail=$SCOPED_FAIL" >> "$OUT"
  if [ "$EXTERNAL_PROBE_SKIPPED" -eq 1 ]; then
    echo "external_probe_skipped=yes" >> "$OUT"
  else
    echo "external_probe_skipped=no" >> "$OUT"
    echo "external_resolvers_ok=$([ "$EXTERNAL_ANY_OK" -eq 1 ] && echo yes || echo no)" >> "$OUT"
  fi
  echo "cross_resolver_mismatch_count=$(awk -F'\t' '$2=="resolver"&&$3=="cross_mismatch_count"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")" >> "$OUT"
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
    human_status="$(tx "TEST PASSED: the host is reachable, TLS and HTTP are fine" "ТЕСТ УСПЕШНО ПРОЙДЕН: хост доступен, TLS и HTTP в норме")"
  elif [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$host_reachable" = "yes" ] && [ "$tls_trust_ok" = "no" ]; then
    human_status="$(tx "TEST PARTIALLY PASSED: the host is reachable, but the TLS certificate failed the trust check" "ТЕСТ ЧАСТИЧНО ПРОЙДЕН: хост доступен, но TLS сертификат не прошел проверку доверия")"
  else
    human_status="$(tx "TEST FAILED: there are problems with reachability, resolving or TLS" "ТЕСТ НЕ ПРОЙДЕН: есть проблемы с доступностью, резолвингом или TLS")"
  fi
  echo "HUMAN_STATUS=$human_status" >> "$OUT"
}

collect_pf_anchor_rules() {
  # Полный дамп PF по всем анкерам (включая вложенные вида com.apple/<имя>).
  # Обычный `pfctl -s rules` показывает только `anchor "com.apple/*"` и прячет
  # содержимое — именно туда, например, ZapretMac кладёт свой route-to.
  # Формат: строка "anchor=<имя>" (пусто = главный набор), затем nat/rdr и filter-правила.
  local anchors a
  echo "anchor="
  run_sudo pfctl -s nat 2>/dev/null
  run_sudo pfctl -s rules 2>/dev/null
  # Явно добавляем анкеры известных DPI-обходов: на случай, если список анкеров
  # пуст/урезан (старые macOS, нестандартный pf.conf).
  anchors="$({ run_sudo pfctl -s Anchors -v 2>/dev/null | sed 's/^[[:space:]]*//'; printf '%s\n' com.apple/zapret-macos zapret; } | awk 'NF && !seen[$0]++')"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    echo "anchor=$a"
    run_sudo pfctl -a "$a" -s nat 2>/dev/null
    run_sudo pfctl -a "$a" -s rules 2>/dev/null
  done <<< "$anchors"
}

parse_pf_redirect_rules() {
  # stdin: вывод collect_pf_anchor_rules.
  # stdout: уникальные записи "anchor|kind|target", где kind — route-to|reply-to|dup-to|rdr|divert-to|divert-packet.
  # Такие правила меняют путь пакета в обход таблицы маршрутизации (а значит, и VPN).
  # nat и rdr из Internet Sharing (com.apple.internet-sharing) — штатные, их пропускаем.
  awk '
    function emit(a, k, t,   key) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
      key = a "|" k "|" t
      if (!(key in seen)) { seen[key] = 1; print key }
    }
    /^anchor=/ { anchor = substr($0, 8); if (anchor == "") anchor = "main"; next }
    anchor ~ /internet-sharing/ { next }
    /^[[:space:]]*rdr[[:space:]]/ && /->/ {
      t = $0
      sub(/.*->[[:space:]]*/, "", t)
      sub(/[[:space:]]+(round-robin|random|source-hash|bitmask|static-port).*$/, "", t)
      emit(anchor, "rdr", t)
      next
    }
    match($0, /(route-to|reply-to|dup-to)[[:space:]]+\([^)]*\)/) {
      s = substr($0, RSTART, RLENGTH)
      k = s; sub(/[[:space:]].*/, "", k)
      t = s; sub(/^[^(]*\(/, "", t); sub(/\)$/, "", t)
      emit(anchor, k, t)
      next
    }
    match($0, /divert-(to|packet)[[:space:]]+[^[:space:]]+([[:space:]]+port[[:space:]]+[^[:space:]]+)?/) {
      s = substr($0, RSTART, RLENGTH)
      k = s; sub(/[[:space:]].*/, "", k)
      t = s; sub(/^[^[:space:]]+[[:space:]]+/, "", t)
      emit(anchor, k, t)
      next
    }
  '
}

dpi_bypass_signatures() {
  # Сигнатуры DPI-обходов для macOS. Поля через TAB (пустое поле = "-"):
  # id, название, launchd ERE, имя процесса ERE (целиком), путь ERE, анкер PF ERE, как остановить.
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    zapretmac 'ZapretMac (Flowseal)' 'io\.github\.flowseal\.zapretmac' 'utunws' 'ZapretMac' '(^|/)zapret-macos$' \
      'sudo "/Library/Application Support/ZapretMac/stop.sh"' \
    zapret 'zapret (bol-van: tpws/dvtws + PF)' '(^|[/.[:space:]])zapret(\.plist)?([[:space:]]|$)' 'tpws|dvtws|nfqws' '^/opt/zapret' '^zapret(/|$)' \
      'sudo /opt/zapret/init.d/macos/zapret stop' \
    spoofdpi "$(tx "SpoofDPI (local HTTP proxy)" "SpoofDPI (локальный HTTP-прокси)")" 'spoofdpi' 'spoofdpi' 'spoofdpi' '-' \
      "$(tx "brew services stop spoofdpi (and turn off the system proxy on 127.0.0.1)" "brew services stop spoofdpi (и выключить системный прокси на 127.0.0.1)")" \
    byedpi "$(tx "ByeDPI (ciadpi, local SOCKS proxy)" "ByeDPI (ciadpi, локальный SOCKS-прокси)")" 'byedpi|ciadpi' 'ciadpi|byedpi' 'byedpi|ciadpi' '-' \
      "$(tx "stop ciadpi/ByeDPI and remove the SOCKS proxy from the network settings" "остановить ciadpi/ByeDPI и убрать SOCKS-прокси из настроек сети")"
}

# Папки внутри ~/Library, в которые шаг 7 не заходит: системные данные Apple
# (com.apple.*) и каталоги под защитой TCC. Конфигов VPN/прокси там нет, а обход
# их содержимого вызывает системные запросы macOS (Apple Music/медиатека,
# Контакты, Календари и т.п.). Сами имена этих папок по-прежнему попадают в вывод.
APP_SCAN_PRUNE_NAMES=('com.apple.*' AddressBook Calendars CallHistoryDB CallHistoryTransactions CloudDocs FaceTime Knowledge Mail Messages MobileSync Safari)

# Ищет пути конфигов VPN/прокси приложений (до 20 совпадений с regex $1) в корнях
# $2... Результат — в глобальных переменных (не через stdout, чтобы не терять их
# в subshell):
#   APP_CONFIG_PATHS  — найденные пути (по одному на строку);
#   APP_SCAN_DENIED   — массив путей, куда macOS не пустила (TCC/права доступа).
APP_CONFIG_PATHS=""
APP_SCAN_DENIED=()
scan_app_config_paths() {
  local pattern="$1"; shift
  local out_file err_file name prune_expr=()
  out_file="$(mktemp "${TMPDIR:-/tmp}/dns_diag_appscan_out.XXXXXX")"
  err_file="$(mktemp "${TMPDIR:-/tmp}/dns_diag_appscan_err.XXXXXX")"
  for name in "${APP_SCAN_PRUNE_NAMES[@]}"; do
    [ "${#prune_expr[@]}" -gt 0 ] && prune_expr+=(-o)
    prune_expr+=(-name "$name")
  done
  find "$@" -maxdepth 3 \( "${prune_expr[@]}" \) -prune -print -o -print >"$out_file" 2>"$err_file" || true
  APP_CONFIG_PATHS="$(grep -Ei "$pattern" "$out_file" | head -20 || true)"
  APP_SCAN_DENIED=()
  # BSD find: "find: /path: ...", GNU find: "find: '/path': ..." или ‘/path’.
  while IFS= read -r name; do
    [ -n "$name" ] && APP_SCAN_DENIED+=("$name")
  done < <(sed -E -n 's/^find: (.*): (Operation not permitted|Permission denied)$/\1/p' "$err_file" \
    | sed -E -e "s/^('|‘)//" -e "s/('|’)\$//" | sort -u)
  rm -f "$out_file" "$err_file"
}

# Имя приложения-терминала для подсказок (TERM_PROGRAM у Terminal.app = Apple_Terminal).
terminal_app_name() {
  case "${TERM_PROGRAM:-}" in
    ""|Apple_Terminal) printf 'Terminal' ;;
    iTerm.app) printf 'iTerm' ;;
    *) printf '%s' "$TERM_PROGRAM" ;;
  esac
}

# Подсказка, как открыть доступ. Скрипт не может отличить «пользователь отказал в
# запросе» от «папка защищена системой и запрос не показывается вовсе» — поэтому
# объясняем оба случая. В обоих macOS сама повторно не спросит.
tcc_recovery_hint() {
  local app bundle="${__CFBundleIdentifier:-}"
  app="$(terminal_app_name)"
  printf '%s' "$(tx "If you denied the prompt earlier, macOS will not ask again. If there was no prompt, the folder is protected by the system. In both cases: System Settings → Privacy & Security → Full Disk Access → enable ${app} and run the script again (to reset past decisions: tccutil reset All${bundle:+ $bundle})" "Если ранее вы отказали в запросе — macOS повторно не спросит. Если запроса не было — папка защищена системой. В обоих случаях: Системные настройки → Конфиденциальность и безопасность → «Полный доступ к диску» → включить ${app} и перезапустить скрипт (сброс прошлых решений: tccutil reset All${bundle:+ $bundle})")"
}

# Фиксирует результат обхода шага 7 в отчёте/фактах и, если macOS не пустила
# в часть папок, помечает отчёт как неполный.
report_app_scan_access() {
  local shown denied_count="${#APP_SCAN_DENIED[@]}"
  echo -e "\n>> APP_CONFIG_SCAN_ACCESS" >> "$OUT"
  if [ "$denied_count" -eq 0 ]; then
    echo "access=ok" >> "$OUT"
    emit_fact coverage app_config_scan complete "find ~/Library,/Applications"
    return 0
  fi
  echo "access=denied denied_count=$denied_count" >> "$OUT"
  printf 'denied: %s\n' "${APP_SCAN_DENIED[@]:0:10}" >> "$OUT"
  [ "$denied_count" -gt 10 ] && echo "$(tx "denied: ... and $((denied_count - 10)) more" "denied: ... и ещё $((denied_count - 10))")" >> "$OUT"
  echo "hint: $(tcc_recovery_hint)" >> "$OUT"
  emit_fact coverage app_config_scan incomplete "find ~/Library,/Applications"
  shown="$(join_by_semicolon "${APP_SCAN_DENIED[@]:0:3}")"
  [ "$denied_count" -gt 3 ] && shown="$(tx "$shown; ... ($denied_count in total)" "$shown; ... (всего $denied_count)")"
  add_coverage_gap "$(tx "Step 7/12 (app configs): macOS denied access to folders: $shown. VPN/proxy configs were not searched in them. $(tcc_recovery_hint)" "Шаг 7/12 (конфиги приложений): macOS не дала доступ к папкам — $shown. Поиск конфигов VPN/прокси в них не выполнен. $(tcc_recovery_hint)")"
}

# Вывод в консоль после шага 7: какие папки недоступны и что с этим делать.
print_app_scan_denied() {
  [ "${#APP_SCAN_DENIED[@]}" -gt 0 ] || return 0
  stop_step_spinner
  # Если только что предлагали выдать доступ — пути уже показаны, не повторяем.
  [ "${APP_SCAN_ACCESS_REQUESTED:-0}" = "1" ] || print_app_scan_denied_paths
  warn "$(tx "The config search is incomplete; this is noted in the report." "Поиск конфигов неполный, это отмечено в отчёте.")"
  [ "${APP_SCAN_ACCESS_REQUESTED:-0}" = "1" ] || info "$(tcc_recovery_hint)"
}

print_app_scan_denied_paths() {
  # Тильда через переменную: в bash 3.2 (macOS) "\~" в замене оставляет обратный слэш.
  local d tilde='~'
  warn "$(tx "macOS denied access to folders (${#APP_SCAN_DENIED[@]}):" "macOS не дала доступ к папкам (${#APP_SCAN_DENIED[@]} шт.):")"
  for d in "${APP_SCAN_DENIED[@]:0:5}"; do
    info "  ${d/#"$HOME"/$tilde}"
  done
  [ "${#APP_SCAN_DENIED[@]}" -gt 5 ] && info "$(tx "  ... and $(( ${#APP_SCAN_DENIED[@]} - 5 )) more (see the report)" "  ... и ещё $(( ${#APP_SCAN_DENIED[@]} - 5 )) (см. отчёт)")"
  return 0
}

# Интерактивно запрашивает доступ к папкам, куда macOS не пустила шаг 7.
# Для таких папок (защищённые системой данные, «Полный доступ к диску») macOS
# не показывает системный диалог и не даёт выдать доступ программно — поэтому
# скрипт сам открывает нужный раздел Системных настроек, ждёт пользователя и
# повторяет поиск. Аргументы — как у scan_app_config_paths.
# Пропускается в неинтерактивном режиме (нет TTY или --yes), чтобы не зависать.
APP_SCAN_ACCESS_REQUESTED=0
# 1 только если «Полный доступ к диску» выдан во время этого запуска: в конце
# напоминаем отключить его обратно.
FDA_GRANTED_NOW=0
request_app_scan_access() {
  local app reply=""
  [ "${#APP_SCAN_DENIED[@]}" -gt 0 ] || return 0
  [ "${FLAG_YES:-0}" = "1" ] && return 0
  [ -t 1 ] || [ "${APP_SCAN_FORCE_INTERACTIVE:-0}" = "1" ] || return 0
  app="$(terminal_app_name)"
  stop_step_spinner
  print_app_scan_denied_paths
  info "$(tx "macOS shows no prompt for these folders: access is granted manually via 'Full Disk Access' for $app." "Для этих папок macOS не показывает запрос — доступ выдаётся вручную: «Полный доступ к диску» для $app.")"
  ask_yes_no "$(tx "Open System Settings and grant access now?" "Открыть Системные настройки и выдать доступ сейчас?")" y || return 0
  APP_SCAN_ACCESS_REQUESTED=1
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" >/dev/null 2>&1 || true
  info "$(tx "1. In the window that opened, enable $app (if it is not listed: '+' > Applications > Utilities > $app)." "1. В открывшемся окне включите $app (если его нет в списке: «+» → Программы → Утилиты → $app).")"
  info "$(tx "2. If macOS offers to quit $app, choose 'Later', otherwise the diagnostics will be interrupted." "2. Если macOS предложит завершить $app — выберите «Позже», иначе диагностика прервётся.")"
  info "$(tx "3. Come back here and press Enter." "3. Вернитесь сюда и нажмите Enter.")"
  # fd 3 — TTY пользователя (см. exec 3</dev/tty в начале); в тестах подменяется.
  printf '  %s›%s %s' "$YELLOW" "$RESET" "$(tx "Press Enter when access is granted (or to continue without it)... " "Нажмите Enter, когда доступ выдан (или чтобы продолжить без него)... ")"
  read -r -u "${APP_SCAN_INPUT_FD:-3}" reply || true
  scan_app_config_paths "$@"
  if [ "${#APP_SCAN_DENIED[@]}" -eq 0 ]; then
    ok "$(tx "Access granted, the config search completed in full." "Доступ получен, поиск конфигов выполнен полностью.")"
    FDA_GRANTED_NOW=1
  else
    warn "$(tx "Access is not active yet. The permission applies after $app is restarted: restart it and run the script again." "Доступ пока не действует. Права применятся после перезапуска $app — перезапустите его и запустите скрипт снова.")"
  fi
}

# После завершения открывает Finder с выделенным файлом отчёта, чтобы его было
# удобно отправить (перетащить в мессенджер/почту). Только в интерактивном
# запуске: без TTY, в CI и с --no-open ничего не делает. При запуске через sudo
# Finder открываем от имени пользователя, иначе `open` под root не попадёт в его сессию.
reveal_report_in_finder() {
  local report="$1"
  [ "${FLAG_NO_OPEN:-0}" = "1" ] && return 0
  [ -n "${CI:-}" ] && return 0
  [ -t 1 ] || [ "${REVEAL_FORCE_INTERACTIVE:-0}" = "1" ] || return 0
  [ -f "$report" ] || return 0
  command -v open >/dev/null 2>&1 || return 0
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" open -R "$report" >/dev/null 2>&1 || return 0
  else
    open -R "$report" >/dev/null 2>&1 || return 0
  fi
  info "$(tx "The report is highlighted in Finder: you can drag it into a messenger or an email." "Отчёт выделен в Finder — его можно перетащить в мессенджер или письмо.")"
}

detect_dpi_bypass() {
  # Ищет DPI-обходы (zapret и аналоги) по совокупности признаков и PF-перенаправления.
  #   $1 — launchd: строки `launchctl list` ("PID<TAB>status<TAB>label") и пути plist
  #   $2 — имена процессов, по одному на строку
  #   $3 — найденные на диске пути установки, по одному на строку
  #   $4 — записи parse_pf_redirect_rules ("anchor|kind|target")
  # Активным считается инструмент с живым процессом, PID в launchd или своим PF-анкером;
  # установленный, но неактивный — только заметка.
  local launchd_text="$1" procs="$2" paths="$3" redirects="$4"
  local id title re_launchd re_proc re_path re_anchor stop
  local ev active redir_rec redir_text any_present=no any_active=no attributed_anchors="" rec r_anchor r_kind r_target
  local unattributed=()

  while IFS=$'\t' read -r id title re_launchd re_proc re_path re_anchor stop; do
    [ -z "$id" ] && continue
    ev=""
    active=no
    redir_rec=""
    if [ "$re_launchd" != "-" ] && printf '%s\n' "$launchd_text" | grep -Eiq "$re_launchd"; then
      ev="${ev:+$ev,}launchd"
      if printf '%s\n' "$launchd_text" | awk -F'\t' '$1 ~ /^[0-9]+$/' | grep -Eiq "$re_launchd"; then
        active=yes
      fi
    fi
    if [ "$re_proc" != "-" ] && printf '%s\n' "$procs" | grep -Eixq "($re_proc)"; then
      ev="${ev:+$ev,}process"
      active=yes
    fi
    if [ "$re_path" != "-" ] && printf '%s\n' "$paths" | grep -Eiq "$re_path"; then
      ev="${ev:+$ev,}path"
    fi
    if [ "$re_anchor" != "-" ] && [ -n "$redirects" ]; then
      redir_rec="$(printf '%s\n' "$redirects" | awk -F'|' -v re="$re_anchor" '$1 ~ re {print; exit}')"
      if [ -n "$redir_rec" ]; then
        ev="${ev:+$ev,}pf_anchor"
        active=yes
        attributed_anchors="${attributed_anchors}${redir_rec%%|*}"$'\n'
      fi
    fi
    [ -z "$ev" ] && continue

    any_present=yes
    redir_text=""
    if [ -n "$redir_rec" ]; then
      IFS='|' read -r r_anchor r_kind r_target <<< "$redir_rec"
      redir_text="$(tx ", PF: $r_kind $r_target in anchor $r_anchor" ", PF: $r_kind $r_target в анкере $r_anchor")"
    fi
    emit_fact interceptor dpi_bypass_tool "id=$id;title=$title;active=$active;evidence=$ev;redirect=${redir_rec:--};stop=$stop" "dpi signatures"
    if [ "$active" = "yes" ]; then
      any_active=yes
      add_cause "$(tx "DPI bypass $title is active (signs: $ev$redir_text): it intercepts outgoing traffic and may send it around the VPN tunnel. Stop it: $stop" "Активен DPI-обход $title (признаки: $ev$redir_text): перехватывает исходящий трафик и может отправлять его мимо VPN-туннеля. Остановить: $stop")"
    else
      add_note "$(tx "DPI bypass $title is installed (signs: $ev) but not active now. If problems appear after it starts, stop it: $stop" "Установлен DPI-обход $title (признаки: $ev), сейчас не активен. Если проблемы появляются после его запуска — остановить: $stop")"
    fi
  done < <(dpi_bypass_signatures)

  emit_fact interceptor dpi_bypass_present "$any_present" "dpi signatures"
  emit_fact interceptor dpi_bypass_active "$any_active" "dpi signatures"

  while IFS= read -r rec; do
    [ -z "$rec" ] && continue
    emit_fact policy pf_traffic_redirect_rule "$rec" "pfctl -a <anchor>"
    if ! printf '%s' "$attributed_anchors" | grep -Fxq "${rec%%|*}"; then
      IFS='|' read -r r_anchor r_kind r_target <<< "$rec"
      unattributed+=("$(tx "$r_kind $r_target in anchor $r_anchor" "$r_kind $r_target в анкере $r_anchor")")
    fi
  done <<< "$redirects"
  if [ -n "$redirects" ]; then
    emit_fact policy pf_traffic_redirect yes "pfctl -a <anchor>"
  else
    emit_fact policy pf_traffic_redirect no "pfctl -a <anchor>"
  fi
  if [ "${#unattributed[@]}" -gt 0 ]; then
    emit_fact policy pf_traffic_redirect_unattributed yes "pfctl -a <anchor>"
    add_cause "$(tx "PF redirects outgoing traffic ($(join_by_semicolon "${unattributed[@]}")): packets may bypass the VPN / routing table" "PF перенаправляет исходящий трафик ($(join_by_semicolon "${unattributed[@]}")): пакеты могут уходить мимо VPN/таблицы маршрутизации")"
  else
    emit_fact policy pf_traffic_redirect_unattributed no "pfctl -a <anchor>"
  fi
}

system_resolver_ips() {
  # IP из последней system_probe (через запятую), пусто если ответа нет.
  awk -F'\t' '$2=="resolver"&&$3=="system_probe"{v=$4} END{
    n = split(v, p, "ips=")
    if (n > 1) { ips = p[2]; sub(/;.*/, "", ips); if (ips != "-") print ips }
  }' "$FACTS_FILE"
}

system_resolver_ips_all_private() {
  # 0, если системный резолвер вернул хотя бы один IP и все они приватные.
  local ips ip
  ips="$(system_resolver_ips)"
  [ -z "$ips" ] && return 1
  for ip in ${ips//,/ }; do
    ip_is_private "$ip" || return 1
  done
  return 0
}

classify_external_probe_for_internal_domain() {
  # Внутренний домен (за VPN) снаружи не существует: NXDOMAIN от 1.1.1.1/8.8.8.8
  # для него ожидаем и не должен превращаться в гипотезу "домен фильтруется снаружи".
  if has_fact external probe_skipped no && has_fact external any_ok no && has_fact external all_timeout no \
    && has_fact resolver system_resolver_ok yes && system_resolver_ips_all_private; then
    emit_fact external internal_domain_expected yes "system resolver private-only + external fail"
    add_note "$(tx "Independent external resolvers do not know $TEST_DOMAIN while the system resolver returns only private addresses ($(system_resolver_ips)): this is an internal domain, so a failure from outside is expected" "Независимые внешние резолверы не знают $TEST_DOMAIN, а системный резолвер отдаёт только приватные адреса ($(system_resolver_ips)) — это внутренний домен, отказ снаружи ожидаем")"
  else
    emit_fact external internal_domain_expected no "system resolver private-only + external fail"
  fi
}

capture_dns_traffic() {
  # Короткий capture DNS/mDNS/LLMNR в отчёт. tcpdump пишет сначала во временный
  # файл: sudo не пересылает SIGTERM от run_with_timeout процессу из той же
  # группы, и без этого tcpdump продолжал дописывать пакеты прямо в $OUT —
  # в чужие секции отчёта. Поэтому запоминаем PID tcpdump и добиваем его явно.
  local secs="${1:-5}" tmp pid body
  tmp="/tmp/dns_diag_tcpdump_${TS_TAG}_$$.txt"
  : > "$tmp"
  # shellcheck disable=SC2016
  run_with_timeout "$secs" run_sudo sh -c 'echo "$$"; exec "$@"' sh \
    tcpdump -l -i any -n '(udp or tcp) and (port 53 or port 5353 or port 5355)' -c 30 > "$tmp" 2>/dev/null || true
  pid="$(head -1 "$tmp")"
  case "$pid" in
    ''|*[!0-9]*) ;;
    *) run_sudo kill "$pid" 2>/dev/null || true ;;
  esac
  body="$(tail -n +2 "$tmp")"
  rm -f "$tmp"
  if [ -n "$body" ]; then
    printf '%s\n' "$body" >> "$OUT"
  else
    echo "$(tx "tcpdump: no DNS/mDNS/LLMNR traffic (or time limit of ${secs}s)" "tcpdump: нет DNS/mDNS/LLMNR трафика (или лимит времени ${secs}с)")" >> "$OUT"
  fi
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
  local score_resolver=0 score_route=0 score_interceptor=0 score_policy=0 score_external=0 score_dpi=0
  local ev_resolver=() ev_route=() ev_interceptor=() ev_policy=() ev_external=() ev_dpi=()
  local dpi_titles dpi_redirects dpi_stop
  local cross_mismatch_count cross_private_suspect_count
  cross_mismatch_count="$(awk -F'\t' '$2=="resolver"&&$3=="cross_mismatch_count"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")"
  cross_private_suspect_count="$(awk -F'\t' '$2=="resolver"&&$3=="cross_private_ip_suspect_count"{v=$4} END{if(v=="") v=0; print v}' "$FACTS_FILE")"

  if has_fact resolver nameserver_missing yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("$(tx "no nameserver found in scutil" "nameserver в scutil не найден")")
  fi
  if has_fact resolver system_resolver_ok no; then
    score_resolver=$((score_resolver + 30))
    ev_resolver+=("$(tx "system resolver does not respond" "системный резолвер не отвечает")")
  fi
  if has_fact resolver dns_servers_all_fail yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("$(tx "all DNS servers do not respond" "все DNS сервера не отвечают")")
  fi
  if has_fact resolver test_domain_resolver_scope yes; then
    score_resolver=$((score_resolver + 25))
    ev_resolver+=("$(tx "a /etc/resolver scope applies to the domain" "для домена действует /etc/resolver scope")")
  fi
  if has_fact resolver test_domain_hosts_override yes; then
    score_resolver=$((score_resolver + 40))
    ev_resolver+=("$(tx "domain is present in /etc/hosts" "домен присутствует в /etc/hosts")")
  fi
  if has_fact resolver system_resolver_ok yes; then
    score_resolver=$((score_resolver - 25))
    ev_resolver+=("$(tx "counter-evidence: system resolver succeeded" "контрдоказательство: системный резолвер успешен")")
  fi

  if has_fact route default_via_utun yes; then
    score_route=$((score_route + 20))
    ev_route+=("$(tx "default route via utun" "default route через utun")")
  fi
  if has_fact route utun_rfc19818_present yes; then
    score_route=$((score_route + 10))
    ev_route+=("$(tx "utun with an address from 198.18/15 found" "обнаружены utun с адресом из 198.18/15")")
  fi
  if has_fact route active_utun yes; then
    score_route=$((score_route + 20))
    ev_route+=("$(tx "active utun interfaces present" "есть активные utun интерфейсы")")
  fi
  if has_fact resolver system_resolver_ok no && has_fact resolver dns_servers_any_ok yes; then
    score_route=$((score_route + 40))
    ev_route+=("$(tx "DNS servers respond directly but the system resolver fails" "DNS серверы отвечают напрямую, но системный резолвер падает")")
  fi

  if has_fact interceptor local_dns_listener_present yes; then
    score_interceptor=$((score_interceptor + 40))
    ev_interceptor+=("$(tx "a local process listens on DNS port 53" "локальный процесс слушает DNS порт 53")")
  fi
  if has_fact interceptor system_proxy_enabled yes; then
    score_interceptor=$((score_interceptor + 20))
    ev_interceptor+=("$(tx "system proxy is enabled" "системный прокси включен")")
  fi
  if has_fact interceptor active_network_extension yes; then
    score_interceptor=$((score_interceptor + 20))
    ev_interceptor+=("$(tx "VPN/filtering network extensions are active" "активны network extension VPN/фильтрации")")
  fi
  if has_fact interceptor local_dns_listener_present yes && has_fact resolver system_resolver_ok no; then
    score_interceptor=$((score_interceptor + 40))
    ev_interceptor+=("$(tx "local interceptor coincides with resolver failure" "совпадение локального перехватчика и отказа резолвера")")
  fi

  if has_fact policy pf_enabled yes; then
    score_policy=$((score_policy + 20))
    ev_policy+=("$(tx "PF is enabled" "PF включен")")
  fi
  if has_fact policy pf_block_rules yes; then
    score_policy=$((score_policy + 40))
    ev_policy+=("$(tx "PF block/drop rules present" "есть PF block/drop правила")")
  fi
  if has_fact policy pf_blocks_recent yes; then
    score_policy=$((score_policy + 40))
    ev_policy+=("$(tx "PF block events in the last hour" "есть PF block события за последний час")")
  fi

  if [ "$cross_private_suspect_count" -gt 0 ]; then
    score_interceptor=$((score_interceptor + 45))
    ev_interceptor+=("$(tx "resolver(s) return a private/reserved IP instead of the public consensus ($cross_private_suspect_count)" "резолвер(ы) возвращают приватный/зарезервированный IP вместо публичного консенсуса ($cross_private_suspect_count шт.)")")
  elif [ "$cross_mismatch_count" -gt 0 ]; then
    score_interceptor=$((score_interceptor + 20))
    ev_interceptor+=("$(tx "some resolvers answer with an IP different from the majority ($cross_mismatch_count)" "часть резолверов отвечает IP, отличным от большинства ($cross_mismatch_count шт.)")")
  fi
  if has_fact route cross_mismatch_utun_only yes; then
    score_route=$((score_route + 25))
    ev_route+=("$(tx "answer mismatch is limited to VPN/utun paths" "рассинхронизация ответов ограничена VPN/utun путями")")
  fi
  if has_fact interceptor cross_mismatch_nonutun_only yes; then
    score_interceptor=$((score_interceptor + 25))
    ev_interceptor+=("$(tx "answer mismatch outside the VPN: likely the local network/ISP, not the VPN" "рассинхронизация ответов вне VPN — вероятно локальная сеть/провайдер, не VPN")")
  fi
  if has_fact external probe_skipped no; then
    if has_fact external any_ok no && has_fact external all_timeout no \
      && ! has_fact external internal_domain_expected yes; then
      score_external=$((score_external + 50))
      ev_external+=("$(tx "independent external resolvers (not from the system configuration) do not resolve the domain either" "независимые внешние резолверы (не из конфигурации системы) тоже не резолвят домен")")
    fi
    if has_fact external udp53_blocked_but_doh_ok yes; then
      score_external=$((score_external + 35))
      ev_external+=("$(tx "DNS over UDP:53 to external resolvers fails but DoH (443) works: looks like selective blocking of the DNS port" "DNS по UDP:53 к внешним резолверам не проходит, но DoH (443) работает — похоже на избирательную блокировку DNS-порта")")
    fi
    if has_fact external any_ok yes && has_fact resolver system_resolver_ok no; then
      score_interceptor=$((score_interceptor + 20))
      ev_interceptor+=("$(tx "independent resolvers respond normally but the system resolver does not: the problem is local" "независимые резолверы отвечают нормально, а системный резолвер — нет: проблема локальная")")
    fi
  fi

  # DPI-обход (zapret и аналоги): трафик перехватывается и уходит мимо маршрутизации/VPN.
  if has_fact interceptor dpi_bypass_active yes; then
    dpi_titles="$(awk -F'\t' '$2=="interceptor"&&$3=="dpi_bypass_tool"&&$4 ~ /;active=yes;/ {
      t=$4; sub(/.*;title=/, "", t); sub(/;.*/, "", t); printf "%s%s", (n++ ? ", " : ""), t }' "$FACTS_FILE")"
    score_dpi=$((score_dpi + 50))
    ev_dpi+=("$(tx "DPI bypass is active: ${dpi_titles:-unknown}" "активен DPI-обход: ${dpi_titles:-неизвестный}")")
  fi
  if has_fact policy pf_traffic_redirect yes; then
    dpi_redirects="$(awk -F'\t' -v in_anchor="$(tx "in anchor" "в анкере")" '$2=="policy"&&$3=="pf_traffic_redirect_rule" {
      split($4, p, "|"); printf "%s%s %s %s %s", (n++ ? ", " : ""), p[2], p[3], in_anchor, p[1] }' "$FACTS_FILE")"
    score_dpi=$((score_dpi + 25))
    ev_dpi+=("$(tx "PF redirects outgoing traffic: $dpi_redirects" "PF перенаправляет исходящий трафик: $dpi_redirects")")
  fi
  if [ "$score_dpi" -gt 0 ] && has_fact e2e resolve_phase ok && has_fact e2e connect_phase fail; then
    score_dpi=$((score_dpi + 20))
    ev_dpi+=("$(tx "DNS resolves the domain but the TCP connection cannot be established" "DNS резолвит домен, но TCP-соединение не устанавливается")")
    if system_resolver_ips_all_private; then
      score_dpi=$((score_dpi + 10))
      ev_dpi+=("$(tx "the target address is private ($(system_resolver_ips)): the resource is behind the VPN, while the intercepted traffic goes through the physical interface gateway" "целевой адрес приватный ($(system_resolver_ips)) — ресурс за VPN, а перехваченный трафик уходит через шлюз физического интерфейса")")
    fi
  fi
  [ "$score_dpi" -gt 100 ] && score_dpi=100

  if [ "$score_resolver" -gt 0 ]; then
    add_hypothesis "$score_resolver" "resolver" \
      "$(tx "Problem at the DNS configuration/resolver level" "Проблема на уровне DNS конфигурации/резолвера")" \
      "$(join_by_semicolon "${ev_resolver[@]}")" \
      "$(tx "The name may fail to resolve even without explicit network blocks" "Имя может не резолвиться даже без явных сетевых блоков")" \
      "scutil --dns; cat /etc/resolver/*; grep -vE '^(#|$)' /etc/hosts"
  fi
  if [ "$score_route" -gt 0 ]; then
    add_hypothesis "$score_route" "route" \
      "$(tx "DNS routing problem through VPN/utun" "Проблема маршрутизации DNS через VPN/utun")" \
      "$(join_by_semicolon "${ev_route[@]}")" \
      "$(tx "DNS queries may go through an unexpected interface" "DNS запросы могут уходить через неожиданный интерфейс")" \
      "route -n get default; netstat -rn | grep '^default'"
  fi
  if [ "$score_interceptor" -gt 0 ]; then
    add_hypothesis "$score_interceptor" "interceptor" \
      "$(tx "Local interception/modification of DNS traffic" "Локальный перехват/модификация DNS трафика")" \
      "$(join_by_semicolon "${ev_interceptor[@]}")" \
      "$(tx "A local agent may alter DNS/proxy behavior" "Локальный агент может подменять DNS/прокси поведение")" \
      "sudo lsof -nP -iTCP:53 -iUDP:53; systemextensionsctl list"
  fi
  if [ "$score_policy" -gt 0 ]; then
    add_hypothesis "$score_policy" "policy" \
      "$(tx "Filtering policies (PF/firewall) affect DNS" "Политики фильтрации (PF/Firewall) влияют на DNS")" \
      "$(join_by_semicolon "${ev_policy[@]}")" \
      "$(tx "DNS queries may be blocked by OS rules" "DNS запросы могут блокироваться правилами ОС")" \
      "sudo pfctl -sr; sudo log show --predicate 'subsystem == \"com.apple.pf\"' --last 1h"
  fi
  if [ "$score_dpi" -gt 0 ]; then
    dpi_stop="$(awk -F'\t' '$2=="interceptor"&&$3=="dpi_bypass_tool"&&$4 ~ /;active=yes;/ {
      t=$4; sub(/.*;stop=/, "", t); printf "%s%s", (n++ ? "; " : ""), t }' "$FACTS_FILE")"
    add_hypothesis "$score_dpi" "dpi_bypass" \
      "$(tx "A DPI bypass (zapret and similar) intercepts traffic and sends it around the VPN / routing table" "DPI-обход (zapret и аналоги) перехватывает трафик и отправляет его мимо VPN/таблицы маршрутизации")" \
      "$(join_by_semicolon "${ev_dpi[@]}")" \
      "$(tx "TCP 80/443 to resources behind the VPN (and some external ones) hangs until timeout although DNS is fine" "TCP 80/443 к ресурсам за VPN (и часть внешних) зависает до таймаута, хотя DNS в порядке")" \
      "$(tx "${dpi_stop:-sudo pfctl -a '<anchor>' -sr and stop the software that loaded the anchor}; then repeat the test" "${dpi_stop:-sudo pfctl -a '<анкер>' -sr и остановить ПО, загрузившее анкер}; затем повторить тест")"
  fi
  if [ "$score_external" -gt 0 ]; then
    add_hypothesis "$score_external" "external" \
      "$(tx "The problem is outside this machine: the domain is filtered/unreachable from outside, not only because of the local VPN/DNS configuration" "Проблема вне этой машины: домен фильтруется/недоступен снаружи, а не только из-за локальной VPN/DNS конфигурации")" \
      "$(join_by_semicolon "${ev_external[@]}")" \
      "$(tx "Local settings may be irrelevant: the problem is on the network/ISP/domain side" "Локальные настройки могут быть ни при чём — проблема на стороне сети/провайдера/самого домена")" \
      "$(tx "check the domain from another device/network; manually: curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=<domain>&type=A'" "проверить домен с другого устройства/сети; вручную curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=<domain>&type=A'")"
  fi
}

render_evidence_sections() {
  local elapsed now sorted score layer symptom evidence impact next confidence rank=0
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
if [ -n "$FLAG_DOMAIN" ]; then
  INPUT_DOMAIN_TRIMMED="$(printf '%s' "$FLAG_DOMAIN" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [ -z "$INPUT_DOMAIN_TRIMMED" ] || ! printf '%s' "$INPUT_DOMAIN_TRIMMED" | grep -Eq '^[^.].*\..*[^.]$'; then
    echo "$(tx "Invalid --domain: the name.zone format is required" "Некорректный --domain: требуется формат вида name.zone")" >&2
    exit 2
  fi
  TEST_DOMAIN="$INPUT_DOMAIN_TRIMMED"
else
  printf '\n%s?%s %s%s%s\n' "$CYAN" "$RESET" "$BOLD" "$(tx "Domain to check" "Домен для проверки DNS")" "$RESET"
  info "$(tx "Latin or Cyrillic letters, in the name.zone format (for example example.com)." "Латиницей или кириллицей, в формате name.zone (например example.com).")"
  while :; do
    printf '  %s›%s ' "$YELLOW" "$RESET"
    if ! read -r -u 3 INPUT_DOMAIN; then
      fail "$(tx "No terminal for entering the domain. Pass it with --domain=<host>." "Нет терминала для ввода домена. Укажите его флагом --domain=<host>.")" >&2
      exit 2
    fi
    INPUT_DOMAIN_TRIMMED="$(printf '%s' "${INPUT_DOMAIN:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [ -z "$INPUT_DOMAIN_TRIMMED" ]; then
      warn "$(tx "No domain entered. Try again." "Домен не введён. Повторите ввод.")"
      continue
    fi
    if ! printf '%s' "$INPUT_DOMAIN_TRIMMED" | grep -Eq '^[^.].*\..*[^.]$'; then
      warn "$(tx "Invalid domain: the name.zone format is required (a single dot without labels is not allowed)." "Некорректный домен: требуется формат вида name.zone (одна точка без меток недопустима).")"
      continue
    fi
    if [ -n "$INPUT_DOMAIN_TRIMMED" ]; then
      TEST_DOMAIN="$INPUT_DOMAIN_TRIMMED"
      break
    fi
  done
fi

# Получаем sudo-сессию до возможной неинтерактивной установки Homebrew.
start_sudo_keepalive

TEST_DOMAIN_QUERY="$TEST_DOMAIN"
IDN_PUNY=""
if printf '%s' "$TEST_DOMAIN" | LC_ALL=C grep -q '[^ -~]'; then
  PYTHON3_BIN=""
  if detect_primary_python3_bin; then
    PYTHON3_BIN="$DETECTED_PYTHON3_BIN"
    IDN_PUNY="$("$PYTHON3_BIN" -c 'import sys; print(sys.argv[1].encode("idna").decode("ascii"))' "$TEST_DOMAIN" 2>/dev/null || true)"
    if [ -n "${IDN_PUNY:-}" ]; then
      TEST_DOMAIN_QUERY="$IDN_PUNY"
      title "$(tx "Non-ASCII (IDN) domain" "Кириллический домен")"
      ok "$(tx "Punycode for DNS queries: $TEST_DOMAIN → $TEST_DOMAIN_QUERY" "Punycode для DNS-запросов: $TEST_DOMAIN → $TEST_DOMAIN_QUERY")"
      emit_fact resolver idn_normalized yes "python3 idna (${PYTHON3_BIN})"
      emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "idna"
    else
      emit_fact resolver idn_normalized no "python3 idna (${PYTHON3_BIN})"
    fi
  else
    title "$(tx "Non-ASCII (IDN) domain" "Кириллический домен")"
    if [ "$PYTHON3_SKIP_REASON" = "apple_stub_missing_clt" ]; then
      warn "$(tx "python3 is needed, but /usr/bin/python3 is unavailable without Command Line Tools." "Нужен python3, но /usr/bin/python3 недоступен без Command Line Tools.")"
      info "$(tx "Switching to installing Homebrew + python3." "Переходим на установку Homebrew + python3.")"
      emit_fact resolver idn_normalized no "python3 apple stub skipped"
    else
      warn "$(tx "python3 is needed for a non-ASCII domain, but it was not found." "Нужен python3 для кириллического домена, но он не найден.")"
      emit_fact resolver idn_normalized no "python3 missing"
    fi
    AUTO_INSTALL_PYTHON_WITH_BREW=no

    if ! command -v brew >/dev/null 2>&1; then
      if ask_yes_no "$(tx "Install Homebrew and python3?" "Установить Homebrew и python3?")" n \
"$(tx "A non-ASCII domain needs python3 (it converts the domain to punycode), and Homebrew is not installed on this Mac.
The installation is automatic and may take a few minutes." "Для кириллического домена нужен python3 (он переводит домен в punycode), а Homebrew на этом Mac не найден.
Установка идёт автоматически и может занять несколько минут.")"; then
        AUTO_INSTALL_PYTHON_WITH_BREW=yes
        if command -v curl >/dev/null 2>&1; then
          info "$(tx "Installing Homebrew..." "Устанавливаем Homebrew...")"
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
      if [ "$AUTO_INSTALL_PYTHON_WITH_BREW" = "yes" ] || ask_yes_no "$(tx "Install python3 via Homebrew?" "Установить python3 через Homebrew?")" n \
"$(tx "Needed to convert a non-ASCII domain to punycode." "Нужен для перевода кириллического домена в punycode.")"; then
        start_step_spinner "$(tx "Installing python3 via Homebrew" "Устанавливаем python3 через Homebrew")"
        if brew install python >/dev/null 2>&1; then
          stop_step_spinner
          ok "$(tx "python3 installed" "python3 установлен")"
          emit_fact resolver python3_install_attempt success "brew install python"
        else
          stop_step_spinner
          fail "$(tx "Could not install python3 via Homebrew" "Не удалось установить python3 через Homebrew")"
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
        ok "$(tx "Punycode for DNS queries: $TEST_DOMAIN → $TEST_DOMAIN_QUERY" "Punycode для DNS-запросов: $TEST_DOMAIN → $TEST_DOMAIN_QUERY")"
        emit_fact resolver idn_normalized yes "python3 idna post-install (${PYTHON3_BIN})"
        emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "idna post-install"
      else
        emit_fact resolver idn_normalized no "python3 idna post-install (${PYTHON3_BIN})"
      fi
    fi

    if [ "$TEST_DOMAIN_QUERY" = "$TEST_DOMAIN" ]; then
      warn "$(tx "Could not convert the domain to punycode automatically." "Автоматически перевести домен в punycode не удалось.")"
      printf '\n%s?%s %s%s%s\n' "$CYAN" "$RESET" "$BOLD" "$(tx "Punycode domain for DNS queries" "Punycode-домен для DNS-запросов")" "$RESET"
      info "$(tx "For example xn--... Press Enter to keep the original domain." "Например xn--... Enter — оставить исходный домен.")"
      printf '  %s›%s ' "$YELLOW" "$RESET"
      read -r -u 3 MANUAL_PUNY || true
      MANUAL_PUNY_TRIMMED="$(printf '%s' "${MANUAL_PUNY:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      if [ -n "$MANUAL_PUNY_TRIMMED" ]; then
        TEST_DOMAIN_QUERY="$MANUAL_PUNY_TRIMMED"
        emit_fact resolver idn_normalized yes "manual punycode"
        emit_fact resolver dns_query_domain "$TEST_DOMAIN_QUERY" "manual punycode"
        ok "$(tx "Using the manually specified query domain: $TEST_DOMAIN_QUERY" "Используем заданный вручную домен для запросов: $TEST_DOMAIN_QUERY")"
      fi
    fi
  fi
fi

say_step "$(tx "1/12 Collecting DNS settings (scutil)" "1/12 Сбор DNS настроек (scutil)")"
say_step_detail "$(tx "Taking a single snapshot: scutil --dns" "Снимаем единый snapshot: scutil --dns")"
say_step_detail "$(tx "Reading system proxies: scutil --proxy" "Снимаем системные прокси: scutil --proxy")"
say_step_detail "$(tx "Recording basic resolver facts (nameserver_count)" "Фиксируем базовые факты resolver (nameserver_count)")"
# 1. scutil DNS
echo "$(tx ">> scutil --dns (DNS settings)" ">> scutil --dns (DNS настройки)")" >> "$OUT"
SCUTIL_DNS_RAW="$(scutil --dns 2>&1 || true)"
printf '%s\n' "$SCUTIL_DNS_RAW" >> "$OUT"
echo -e "$(tx "\n>> scutil --proxy (proxy)" "\n>> scutil --proxy (прокси)")" >> "$OUT"
scutil --proxy >> "$OUT" 2>&1
SCUTIL_NS_COUNT="$(printf '%s\n' "$SCUTIL_DNS_RAW" | awk '/nameserver\[[0-9]+\]/{c++} END{print c+0}')"
emit_fact resolver nameserver_count "$SCUTIL_NS_COUNT" "scutil --dns"

say_step "$(tx "2/12 PF: status/anchors/rules" "2/12 PF: статус/анкоры/правила")"
say_step_detail "$(tx "Reading pfctl: info / anchors / rules" "Читаем pfctl: info / anchors / rules")"
say_step_detail "$(tx "Walking all anchors (including com.apple/*): looking for route-to/rdr/divert" "Обходим все анкеры (включая com.apple/*): ищем route-to/rdr/divert")"
say_step_detail "$(tx "Recording whether PF is enabled" "Фиксируем факт: PF включен или нет")"
# 2. PF полный
echo -e "$(tx "\n>> PF: status, anchors, rules" "\n>> PF: статус, анкоры, правила")" >> "$OUT"
run_sudo pfctl -s info >> "$OUT" 2>&1
run_sudo pfctl -s rules >> "$OUT" 2>&1
PF_ANCHOR_RAW="$(collect_pf_anchor_rules)"
PF_REDIRECTS="$(printf '%s\n' "$PF_ANCHOR_RAW" | parse_pf_redirect_rules)"
echo -e "$(tx "\n>> PF_ANCHOR_RULES (nat/rdr + filter per anchor)" "\n>> PF_ANCHOR_RULES (nat/rdr + filter по каждому анкеру)")" >> "$OUT"
printf '%s\n' "$PF_ANCHOR_RAW" >> "$OUT"
echo -e "\n>> PF_TRAFFIC_REDIRECTS (anchor|kind|target)" >> "$OUT"
if [ -n "$PF_REDIRECTS" ]; then
  printf '%s\n' "$PF_REDIRECTS" >> "$OUT"
else
  echo "none" >> "$OUT"
fi
if run_sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
  emit_fact policy pf_enabled yes "pfctl -s info"
else
  emit_fact policy pf_enabled no "pfctl -s info"
fi

say_step "$(tx "3/12 VPN/Proxy network extensions" "3/12 Сетевые расширения VPN/Прокси")"
say_step_detail "$(tx "Checking neagent (if available)" "Проверяем neagent (если доступен)")"
say_step_detail "$(tx "Reading systemextensionsctl list" "Снимаем systemextensionsctl list")"
# 3. Сетевые расширения (NetworkExtension)
echo -e "$(tx "\n>> VPN/Proxy network extensions" "\n>> Сетевые расширения VPN/Прокси")" >> "$OUT"
if command -v neagent >/dev/null 2>&1; then
  neagent list >> "$OUT" 2>&1
else
  echo "$(tx "neagent not found, skipping" "neagent не найден, пропуск")" >> "$OUT"
fi
echo -e "$(tx "\n>> systemextensionsctl list" "\n>> systemextensionsctl список")" >> "$OUT"
systemextensionsctl list >> "$OUT" 2>&1

say_step "$(tx "4/12 VPN/Proxy/PF processes" "4/12 Процессы VPN/Прокси/PF")"
say_step_detail "$(tx "Looking for VPN/Proxy/Filter/DPI-bypass processes via pgrep" "Ищем процессы VPN/Proxy/Filter/DPI-обхода через pgrep")"
# 4. ВСЕ процессы VPN/Прокси/PF (расширенный список)
VPN_PROCS="happ|ngate|cryptopro|xray|v2ray|v2rayn|qv2ray|nekoray|sing-box|clash|clashx|clashx-pro|clash-verge|shadowrocket|shadowsocksx|shadowsocksx-ng|shadowsocks|quantumult|surge|loon|stash|kitsunebi|v2box|napsternet|mosdns|dnscrypt-proxy|cloudflared|adguard|nextdns|smartdns|stubby|unbound|coredns|1\\.1\\.1\\.1|outline|wireguard|tailscale|headscale|mullvad|protonvpn|expressvpn|nordvpn|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vyprvpn|cyberghost|hide\\.me|zenmate|tunnelbear|astrill|hotspotshield|hma|openvpn|viscosity|tunnelblick|shimo|vpntracker|forticlient|paloaltonetworks|globalprotect|pulse|anyconnect|cisco|checkpoint|snx|sophos|sonicwall|zerotier|netbird|privoxy|polipo|3proxy|dante|tinyproxy|squid|mitmproxy|proxifier|proxychains|proxyswitcher|proxynotion|littlesnitch|lulu|tripmode|murus|goodbyedpi|zapret|antizapret|utunws|tpws|dvtws|nfqws|spoofdpi|byedpi|ciadpi|stunnel|obfs4proxy|meek-client|snowflake|tor|psiphon|safing|portmaster|proxynotion|ovpnproxy|unblockpro"
echo -e "$(tx "\n>> VPN/Proxy/PF PROCESSES" "\n>> ПРОЦЕССЫ VPN/Прокси/PF")" >> "$OUT"
# На macOS `pgrep -a` значит "включать предков" и печатает только PID; имя даёт -l.
pgrep -il "$VPN_PROCS|neagent|utun|pfctl|socketfilterfw" >> "$OUT" 2>&1 || true
PROC_NAMES="$(ps -axo comm= 2>/dev/null | awk -F/ '{print $NF}' | sort -u)"

say_step "$(tx "5/12 Launch services" "5/12 Службы запуска")"
say_step_detail "$(tx "Checking launchctl (user + system) and plist services of VPN/Proxy/DPI bypass" "Проверяем launchctl (user + system) и plist сервисы VPN/Proxy/DPI-обхода")"
# 5. Launch plist всех клиентов
LAUNCH_LIST="happ|ngate|cryptopro|xray|v2ray|qv2ray|clash|clashx|shadow|quantumult|surge|loon|stash|sing|nekoray|kitsunebi|v2box|napster|mosdns|dnscrypt|cloudflared|adguard|nextdns|smartdns|stubby|unbound|coredns|outline|wireguard|tailscale|headscale|mullvad|proton|expressvpn|nord|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vypr|cyberghost|tunnelbear|astrill|hotspotshield|hma|openvpn|viscosity|tunnelblick|shimo|vpntracker|forticlient|paloalto|globalprotect|pulse|anyconnect|cisco|checkpoint|snx|sophos|sonicwall|zerotier|netbird|privoxy|polipo|3proxy|dante|tinyproxy|squid|mitmproxy|proxifier|proxychains|proxyswitcher|socketfilterfw|littlesnitch|lulu|tripmode|murus|icefloor|goodbyedpi|zapret|antizapret|utunws|tpws|dvtws|nfqws|spoofdpi|byedpi|ciadpi|stunnel|obfs4|meek|snowflake|tor|psiphon|safing|portmaster|unblockpro"
echo -e "$(tx "\n>> Launch services (launchd) VPN/Proxy" "\n>> Службы запуска (launchd) VPN/Прокси")" >> "$OUT"
# Без sudo `launchctl list` видит только user-домен: системные демоны
# (/Library/LaunchDaemons, например io.github.flowseal.zapretmac) там не появляются.
LAUNCHD_USER="$(launchctl list 2>/dev/null | grep -iE "$LAUNCH_LIST")"
LAUNCHD_SYSTEM="$(run_sudo launchctl list 2>/dev/null | grep -iE "$LAUNCH_LIST")"
LAUNCHD_PLISTS="$(find /Library/Launch* ~/Library/Launch* -name "*.plist" -print0 2>/dev/null | xargs -0 grep -l -iE "$LAUNCH_LIST" 2>/dev/null | head -20)"
printf '%s\n' "$LAUNCHD_USER" >> "$OUT"
echo -e "$(tx "\n>> Launch services (launchd, system domain)" "\n>> Службы запуска (launchd, system-домен)")" >> "$OUT"
printf '%s\n' "$LAUNCHD_SYSTEM" >> "$OUT"
echo -e "$(tx "\n>> launch service plists" "\n>> plist служб запуска")" >> "$OUT"
printf '%s\n' "$LAUNCHD_PLISTS" >> "$OUT"
LAUNCHD_RAW="$(printf '%s\n%s\n%s\n' "$LAUNCHD_USER" "$LAUNCHD_SYSTEM" "$LAUNCHD_PLISTS")"

say_step "$(tx "6/12 DNS traffic and PF blocks" "6/12 DNS трафик и PF блоки")"
say_step_detail "$(tx "Short DNS/mDNS/LLMNR capture: tcpdump" "Короткий capture DNS/mDNS/LLMNR: tcpdump")"
say_step_detail "$(tx "Looking for PF block events from the last hour" "Ищем PF block события за 1 час")"
# 6. DNS трафик + блоки
echo -e "$(tx "\n>> DNS traffic (30 packets)" "\n>> DNS трафик (30 пакетов)")" >> "$OUT"
capture_dns_traffic 5
echo -e "$(tx "\n>> PF blocks (1h)" "\n>> PF блоки (1ч)")" >> "$OUT"
PF_BLOCKS="$(run_sudo log show --style compact --predicate 'subsystem == "com.apple.pf"' --last 1h --info 2>/dev/null | grep -i block | head -15 || true)"
if [ -n "$PF_BLOCKS" ]; then
  printf '%s\n' "$PF_BLOCKS" >> "$OUT"
  emit_fact policy pf_blocks_recent yes "log show com.apple.pf"
else
  echo "$(tx "No PF block events found in the last hour" "PF block-события за 1ч не обнаружены")" >> "$OUT"
  emit_fact policy pf_blocks_recent no "log show com.apple.pf"
fi

say_step "$(tx "7/12 App configs" "7/12 Конфиги приложений")"
info "$(tx "Looking for VPN/proxy configs by folder names in ~/Library (file contents are not read)." "Ищем конфиги VPN/прокси по именам папок в ~/Library (содержимое не читается).")"
info "$(tx "If some folders are not accessible, the script will offer to grant access (macOS may also ask on its own); without it this step will be incomplete." "Если доступа к части папок нет, скрипт предложит выдать его (macOS может спросить и сама) — без него шаг будет неполным.")"
say_step_detail "$(tx "Scanning typical VPN/Proxy app config paths" "Сканируем типовые пути конфигов VPN/Proxy приложений")"
say_step_detail "$(tx "Looking for DPI bypass tools (ZapretMac, zapret, SpoofDPI, ByeDPI)" "Ищем DPI-обходы (ZapretMac, zapret, SpoofDPI, ByeDPI)")"
# 7. Конфиги приложений (папки)
APPS_PATHS="happ|ngate|cryptopro|xray|v2ray|qv2ray|clash|clashx|shadowrocket|shadowsocks|quantumult|surge|loon|stash|adguard|nextdns|wireguard|tailscale|headscale|mullvad|proton|expressvpn|nordvpn|surfshark|pia|privateinternetaccess|ivpn|windscribe|purevpn|vypr|cyberghost|tunnelbear|astrill|openvpn|viscosity|tunnelblick|shimo|vpntracker|globalprotect|forticlient|anyconnect|cisco|zerotier|netbird|littlesnitch|lulu|tripmode|murus|goodbyedpi|zapret|antizapret|spoofdpi|byedpi|ciadpi|unblockpro"
echo -e "$(tx "\n>> App configs" "\n>> Конфиги приложений")" >> "$OUT"
APP_SCAN_ROOTS=(~/Library/Preferences ~/Library/Application\ Support ~/Library/Caches /Applications)
scan_app_config_paths "$APPS_PATHS" "${APP_SCAN_ROOTS[@]}"
request_app_scan_access "$APPS_PATHS" "${APP_SCAN_ROOTS[@]}"
printf '%s\n' "$APP_CONFIG_PATHS" >> "$OUT"
report_app_scan_access
print_app_scan_denied

# DPI-обходы (zapret и аналоги): сопоставляем launchd, процессы, пути и PF-анкеры.
DPI_INSTALL_PATHS="$(
  for p in "/Library/Application Support/ZapretMac" "$HOME/Library/Application Support/ZapretMac" \
    /opt/zapret /usr/local/bin/spoofdpi /opt/homebrew/bin/spoofdpi /usr/local/bin/ciadpi /opt/homebrew/bin/ciadpi; do
    [ -e "$p" ] && printf '%s\n' "$p"
  done
  printf '%s\n' "$APP_CONFIG_PATHS"
)"
detect_dpi_bypass "$LAUNCHD_RAW" "$PROC_NAMES" "$DPI_INSTALL_PATHS" "$PF_REDIRECTS"
echo -e "\n>> DPI_BYPASS" >> "$OUT"
echo "present=$(has_fact interceptor dpi_bypass_present yes && echo yes || echo no)" >> "$OUT"
echo "active=$(has_fact interceptor dpi_bypass_active yes && echo yes || echo no)" >> "$OUT"
awk -F'\t' '$2=="interceptor"&&$3=="dpi_bypass_tool"{print "tool: " $4}' "$FACTS_FILE" >> "$OUT"

say_step "$(tx "8/12 Local port listeners" "8/12 Локальные слушатели портов")"
say_step_detail "$(tx "Checking who holds /dev/pf" "Проверяем, кто держит /dev/pf")"
say_step_detail "$(tx "Checking TCP LISTEN and UDP sockets on DNS/Proxy ports" "Проверяем TCP LISTEN и UDP сокеты DNS/Proxy портов")"
# 8. lsof PF + порты прокси
echo -e "$(tx "\n>> /dev/pf users" "\n>> /dev/pf пользователи")" >> "$OUT"
run_sudo lsof /dev/pf 2>/dev/null | head -10 >> "$OUT"
echo -e "$(tx "\n>> Proxy/DNS TCP ports (LISTEN)" "\n>> Прокси/DNS TCP порты (LISTEN)")" >> "$OUT"
run_sudo lsof -nP -sTCP:LISTEN -iTCP:53 -iTCP:5353 -iTCP:1080 -iTCP:8080 -iTCP:40000-50000 2>/dev/null >> "$OUT"
echo -e "$(tx "\n>> DNS UDP sockets" "\n>> DNS UDP сокеты")" >> "$OUT"
run_sudo lsof -nP -iUDP:53 -iUDP:5353 -iUDP:5355 2>/dev/null >> "$OUT"

say_step "$(tx "9/12 Network services and proxies" "9/12 Сетевые сервисы и прокси")"
say_step_detail "$(tx "Walking network services" "Обходим network services")"
say_step_detail "$(tx "Reading DNS/proxy/PAC/bypass for each service" "Снимаем DNS/proxy/PAC/bypass для каждого сервиса")"
# 9. Сетевые сервисы + прокси настройки по каждому сервису
echo -e "$(tx "\n>> Network services" "\n>> Сетевые сервисы")" >> "$OUT"
networksetup -listallnetworkservices 2>/dev/null | sed '1d' >> "$OUT"
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  echo -e "$(tx "\n--- Service: $svc ---" "\n--- Сервис: $svc ---")" >> "$OUT"
  networksetup -getdnsservers "$svc" >> "$OUT" 2>&1
  networksetup -getwebproxy "$svc" >> "$OUT" 2>&1
  networksetup -getsecurewebproxy "$svc" >> "$OUT" 2>&1
  networksetup -getautoproxyurl "$svc" >> "$OUT" 2>&1
  networksetup -getproxybypassdomains "$svc" >> "$OUT" 2>&1
done < <(networksetup -listallnetworkservices 2>/dev/null | sed '1d')

say_step "$(tx "10/12 DNS resolver and network extension logs" "10/12 Логи DNS резолвера и сетевых расширений")"
say_step_detail "$(tx "Filtered mDNSResponder logs (query/fail/timeout)" "Фильтрованные логи mDNSResponder (query/fail/timeout)")"
say_step_detail "$(tx "Filtered NetworkExtension logs (dns/proxy/tunnel/fail)" "Фильтрованные логи NetworkExtension (dns/proxy/tunnel/fail)")"
# 10. Логи DNS-резолвера и NetworkExtension
echo -e "$(tx "\n>> mDNSResponder logs (3m)" "\n>> mDNSResponder логи (3м)")" >> "$OUT"
log show --style compact --predicate 'process == "mDNSResponder" AND (eventMessage CONTAINS[c] "query" OR eventMessage CONTAINS[c] "fail" OR eventMessage CONTAINS[c] "timeout" OR eventMessage CONTAINS[c] "nxdomain" OR eventMessage CONTAINS[c] "servfail")' --last 3m | head -500 >> "$OUT" 2>&1
echo -e "$(tx "\n>> Network extension logs (3m)" "\n>> Логи сетевых расширений (3м)")" >> "$OUT"
log show --style compact --predicate 'subsystem == "com.apple.networkextension" AND (eventMessage CONTAINS[c] "dns" OR eventMessage CONTAINS[c] "proxy" OR eventMessage CONTAINS[c] "tunnel" OR eventMessage CONTAINS[c] "drop" OR eventMessage CONTAINS[c] "deny" OR eventMessage CONTAINS[c] "fail")' --last 3m | head -500 >> "$OUT" 2>&1

say_step "$(tx "11/12 DNS availability check" "11/12 Проверка доступности DNS")"
say_step_detail "$(tx "Collecting DNS servers from scutil/networksetup/resolv.conf" "Собираем DNS servers из scutil/networksetup/resolv.conf")"
say_step_detail "$(tx "Reading default route and utun inventory (RFC198.18 marker)" "Снимаем default route и utun inventory (RFC198.18 маркер)")"
say_step_detail "$(tx "Reading the routing table: netstat -rn" "Снимаем таблицу маршрутизации: netstat -rn")"
say_step_detail "$(tx "Checking the domain via DNS servers and the system resolver (A)" "Проверяем домен через DNS servers и системный resolver (A)")"
# 11. Проверка доступности DNS
echo -e "$(tx "\n>> DNS availability ($TEST_DOMAIN)" "\n>> DNS доступность ($TEST_DOMAIN)")" >> "$OUT"
if [ "$TEST_DOMAIN_QUERY" != "$TEST_DOMAIN" ]; then
  echo "DNS query label (IDN->ASCII): $TEST_DOMAIN_QUERY" >> "$OUT"
fi
DNS_SERVERS="$(printf '%s\n' "$SCUTIL_DNS_RAW" | awk '/nameserver\[[0-9]+\]/{print $3}' | sort -u)"
if [ -z "$DNS_SERVERS" ]; then
  DNS_SERVERS="$(networksetup -listallnetworkservices 2>/dev/null | sed '1d' | while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    networksetup -getdnsservers "$svc" 2>/dev/null | awk '/^[0-9]/{print $1}'
  done | sort -u)"
fi
if [ -z "$DNS_SERVERS" ] && [ -r /etc/resolv.conf ]; then
  DNS_SERVERS="$(awk '/^nameserver /{print $2}' /etc/resolv.conf | sort -u)"
fi
echo "$(tx "DNS servers found: ${DNS_SERVERS:-none}" "DNS сервера обнаружены: ${DNS_SERVERS:-нет}")" >> "$OUT"
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
echo -e "$(tx "\n>> Routing (netstat -rn)" "\n>> Маршрутизация (netstat -rn)")" >> "$OUT"
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
  echo "$(tx "note=utun in default seen only in the general/IPv6-heavy netstat view; this can be normal for macOS" "note=utun в default замечены только в общем/часто IPv6 представлении netstat; это может быть штатно для macOS")" >> "$OUT"
fi

echo -e "$(tx "\n>> UTUN interfaces (inventory)" "\n>> UTUN интерфейсы (inventory)")" >> "$OUT"
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
        add_cause "$(tx "Default route via $ui with tunnel address $ip (198.18/15)" "Default route через $ui с tunnel-адресом $ip (198.18/15)")"
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
  echo -e "$(tx "\n>> Wi-Fi manual DNS/proxy" "\n>> Wi-Fi ручной DNS/прокси")" >> "$OUT"
  WIFI_DNS="$(networksetup -getdnsservers "$WIFI_SVC" 2>/dev/null)"
  if printf '%s' "$WIFI_DNS" | grep -q "There aren't any DNS Servers set"; then
    echo "$(tx "Wi-Fi DNS: not set manually (DHCP/Auto)" "Wi-Fi DNS: не задан вручную (DHCP/Авто)")" >> "$OUT"
  else
    echo "$(tx "Wi-Fi DNS: set manually -> $WIFI_DNS" "Wi-Fi DNS: вручную задан -> $WIFI_DNS")" >> "$OUT"
  fi
  WIFI_PROXY="$(networksetup -getwebproxy "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  WIFI_SPROXY="$(networksetup -getsecurewebproxy "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  WIFI_PAC="$(networksetup -getautoproxyurl "$WIFI_SVC" 2>/dev/null | awk -F': ' '/Enabled:/{print $2; exit}')"
  echo "$(tx "Wi-Fi HTTP proxy: ${WIFI_PROXY:-unknown}" "Wi-Fi HTTP прокси: ${WIFI_PROXY:-неизвестно}")" >> "$OUT"
  echo "$(tx "Wi-Fi HTTPS proxy: ${WIFI_SPROXY:-unknown}" "Wi-Fi HTTPS прокси: ${WIFI_SPROXY:-неизвестно}")" >> "$OUT"
  echo "$(tx "Wi-Fi PAC: ${WIFI_PAC:-unknown}" "Wi-Fi PAC: ${WIFI_PAC:-неизвестно}")" >> "$OUT"
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
    PROBE_IPS="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f4)"
    if [ "$PROBE_STATE" = "ok" ]; then
      echo "$(tx "OK $s [A] status=$PROBE_REASON answers=$PROBE_ANS ips=$PROBE_IPS" "УСПЕХ $s [A] status=$PROBE_REASON answers=$PROBE_ANS ips=$PROBE_IPS")" >> "$OUT"
      DNS_OK=$((DNS_OK + 1))
    else
      echo "$(tx "FAIL $s [A] reason=$PROBE_REASON answers=$PROBE_ANS" "СБОЙ $s [A] reason=$PROBE_REASON answers=$PROBE_ANS")" >> "$OUT"
      DNS_SERVER_FAILS+=("$s|$PROBE_REASON")
      DNS_FAIL=$((DNS_FAIL + 1))
    fi
    emit_fact resolver dns_server_probe "server=$s;rr=A;result=$PROBE_STATE;reason=$PROBE_REASON;answers=$PROBE_ANS;ips=$PROBE_IPS" "dig"
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
  PROBE_IPS="$(printf '%s' "$PROBE_RESULT" | cut -d'|' -f4)"
  if [ "$PROBE_STATE" = "ok" ]; then
    echo "$(tx "OK system resolver [A] status=$PROBE_REASON answers=$PROBE_ANS ips=$PROBE_IPS" "УСПЕХ системный резолвер [A] status=$PROBE_REASON answers=$PROBE_ANS ips=$PROBE_IPS")" >> "$OUT"
    SYS_OK=$((SYS_OK + 1))
  else
    echo "$(tx "FAIL system resolver [A] reason=$PROBE_REASON answers=$PROBE_ANS" "СБОЙ системный резолвер [A] reason=$PROBE_REASON answers=$PROBE_ANS")" >> "$OUT"
  fi
  emit_fact resolver system_probe "rr=A;result=$PROBE_STATE;reason=$PROBE_REASON;answers=$PROBE_ANS;ips=$PROBE_IPS" "dig system"
  if [ "$SYS_OK" -gt 0 ]; then
    emit_fact resolver system_resolver_ok yes "dig system"
  else
    add_cause "$(tx "The system resolver does not resolve $TEST_DOMAIN (A)" "Системный резолвер не резолвит $TEST_DOMAIN (A)")"
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
      echo "$(tx "FAIL $s [A] reason=$(printf '%s\n' "$NS_OUT" | head -1)" "СБОЙ $s [A] reason=$(printf '%s\n' "$NS_OUT" | head -1)")" >> "$OUT"
      DNS_SERVER_FAILS+=("$s|$(nslookup_probe "$TEST_DOMAIN_QUERY" "$s" | cut -d'|' -f2)")
      DNS_FAIL=$((DNS_FAIL + 1))
      emit_fact resolver dns_server_probe "server=$s;rr=MIXED;result=fail;reason=NSLOOKUP_ERROR;answers=0" "nslookup"
    else
      echo "$(tx "OK $s [A]" "УСПЕХ $s [A]")" >> "$OUT"
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
    echo "$(tx "FAIL system resolver [A]" "СБОЙ системный резолвер [A]")" >> "$OUT"
    add_cause "$(tx "The system resolver does not resolve $TEST_DOMAIN (nslookup)" "Системный резолвер не резолвит $TEST_DOMAIN (nslookup)")"
    emit_fact resolver system_resolver_ok no "nslookup system"
  else
    echo "$(tx "OK system resolver [A]" "УСПЕХ системный резолвер [A]")" >> "$OUT"
    emit_fact resolver system_resolver_ok yes "nslookup system"
  fi
else
  echo "$(tx "dig/nslookup not found, skipping the DNS check" "dig/nslookup не найден, пропуск проверки DNS")" >> "$OUT"
  emit_fact resolver probe_tool_available no "dig/nslookup"
fi

say_step "$(tx "12/12 Heuristics, scoped probe and final classification" "12/12 Эвристика, scoped probe и итоговая классификация")"
say_step_detail "$(tx "Applying cause heuristics (proxy/pf/hosts/resolver/utun)" "Применяем эвристики causes (proxy/pf/hosts/resolver/utun)")"
say_step_detail "$(tx "SCUTIL_SCOPED_NS_PROBE: checking the domain via scoped nameservers" "SCUTIL_SCOPED_NS_PROBE: проверка домена по scoped nameserver")"
say_step_detail "E2E curl probe: resolve/connect/tls/http"
say_step_detail "$(tx "Building DNS_ONLY_RESULT, E2E_RESULT, PRIMARY_CLASSIFICATION and EVIDENCE_MATRIX" "Формируем DNS_ONLY_RESULT, E2E_RESULT, PRIMARY_CLASSIFICATION и EVIDENCE_MATRIX")"
# 12. Эвристика: возможные причины проблем с DNS
if ! printf '%s\n' "$SCUTIL_DNS_RAW" | grep -q "nameserver\\["; then
  add_cause "$(tx "No DNS servers found in scutil --dns" "DNS серверы не обнаружены в scutil --dns")"
  emit_fact resolver nameserver_missing yes "scutil --dns"
else
  emit_fact resolver nameserver_missing no "scutil --dns"
fi

if scutil --proxy | grep -Eq "HTTPEnable : 1|HTTPSEnable : 1|SOCKSEnable : 1|ProxyAutoConfigEnable : 1"; then
  add_cause "$(tx "System proxy is enabled (scutil --proxy)" "Системный прокси включен (scutil --proxy)")"
  emit_fact interceptor system_proxy_enabled yes "scutil --proxy"
else
  emit_fact interceptor system_proxy_enabled no "scutil --proxy"
fi

if run_sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
  if run_sudo pfctl -s rules 2>/dev/null | grep -Eiq '(^|[[:space:]])(block|drop)[[:space:]]'; then
    add_cause "$(tx "PF is enabled and has block/drop rules: DNS filtering is possible" "PF включен и есть block/drop правила: возможна фильтрация DNS")"
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
  add_cause "$(tx "Local processes listen on port 53: $DNS_LISTEN" "Локальные процессы слушают 53 порт: $DNS_LISTEN")"
  emit_fact interceptor local_dns_listener_present yes "lsof :53"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    emit_fact interceptor local_dns_listener_process "$p" "lsof :53"
  done <<< "$DNS_LISTEN"
else
  emit_fact interceptor local_dns_listener_present no "lsof :53"
fi

if [ -d /etc/resolver ] && ls /etc/resolver >/dev/null 2>&1; then
  add_cause "$(tx "Custom resolver files exist in /etc/resolver" "Есть кастомные resolver-файлы в /etc/resolver")"
  echo -e "$(tx "\n>> /etc/resolver (files)" "\n>> /etc/resolver (файлы)")" >> "$OUT"
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
    add_cause "$(tx "A custom /etc/resolver scope applies to $TEST_DOMAIN" "Для $TEST_DOMAIN действует кастомный /etc/resolver scope")"
  fi
else
  emit_fact resolver custom_resolver_files no "/etc/resolver"
  emit_fact resolver test_domain_resolver_scope no "/etc/resolver scope"
fi

if grep -vE '^\s*#|^\s*$' /etc/hosts | grep -vE 'localhost|broadcasthost|ip6-' >/dev/null; then
  add_cause "$(tx "Custom entries exist in /etc/hosts" "Есть кастомные записи в /etc/hosts")"
  emit_fact resolver custom_hosts_entries yes "/etc/hosts"

  TEST_DOMAIN_ERE="$(escape_ere "$TEST_DOMAIN")"
  if grep -vE '^\s*#|^\s*$' /etc/hosts | grep -Eiq "(^|[[:space:]])$TEST_DOMAIN_ERE([[:space:]]|$)"; then
    emit_fact resolver test_domain_hosts_override yes "/etc/hosts"
    add_cause "$(tx "Domain $TEST_DOMAIN found in /etc/hosts" "Домен $TEST_DOMAIN найден в /etc/hosts")"
  else
    emit_fact resolver test_domain_hosts_override no "/etc/hosts"
  fi
else
  emit_fact resolver custom_hosts_entries no "/etc/hosts"
  emit_fact resolver test_domain_hosts_override no "/etc/hosts"
fi

if systemextensionsctl list 2>/dev/null | grep -Eiq 'activated[[:space:]]+enabled.*(tailscale|wireguard|cloudflare|nextdns|adguard|proton|mullvad|nord|surfshark|expressvpn|cisco|forti|globalprotect|littlesnitch|lulu|tripmode|clash|happ|ngate|v2ray|xray)'; then
  add_cause "$(tx "VPN/filtering network extensions are active: DNS filtering is possible" "Активны сетевые расширения VPN/фильтрации: возможна фильтрация DNS")"
  emit_fact interceptor active_network_extension yes "systemextensionsctl list"
else
  emit_fact interceptor active_network_extension no "systemextensionsctl list"
fi

ACTIVE_UTUNS="$(ifconfig 2>/dev/null | awk 'BEGIN{RS="";} $1 ~ /^utun[0-9]+:$/ {if ($0 ~ /UP/ && $0 ~ /RUNNING/ && $0 ~ /inet /) {sub(":","",$1); print $1}}' | sort -u)"
if [ -n "$ACTIVE_UTUNS" ]; then
  add_cause "$(tx "Active utun interfaces (UP+RUNNING+inet): $ACTIVE_UTUNS" "Активные utun-интерфейсы (UP+RUNNING+inet): $ACTIVE_UTUNS")"
  emit_fact route active_utun yes "ifconfig utun*"
else
  emit_fact route active_utun no "ifconfig utun*"
fi
if [ -n "$DEFAULT_UTUNS_V4" ]; then
  DEFAULT_UTUNS_INLINE="$(printf '%s' "$DEFAULT_UTUNS_V4" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  add_cause "$(tx "Default route via utun (IPv4 netstat -f inet): $DEFAULT_UTUNS_INLINE" "Маршрут по умолчанию через utun (IPv4 netstat -f inet): $DEFAULT_UTUNS_INLINE")"
fi
if [ -n "${DEFAULT_ROUTE_IF:-}" ] && printf '%s' "$DEFAULT_ROUTE_IF" | grep -q '^utun'; then
  add_cause "$(tx "Default route via utun (route get): $DEFAULT_ROUTE_IF" "Маршрут по умолчанию через utun (route get): $DEFAULT_ROUTE_IF")"
fi

run_scoped_resolver_probes "$SCUTIL_DNS_RAW" "$TEST_DOMAIN_QUERY"
classify_dns_server_failures
run_external_dns_probes "$TEST_DOMAIN_QUERY"
classify_external_probe_for_internal_domain
run_cross_resolver_consistency_check
run_e2e_curl_probe "$TEST_DOMAIN" "$TEST_DOMAIN_QUERY"
render_dual_mode_sections
render_evidence_sections

echo -e "$(tx "\n>> Possible causes of DNS problems" "\n>> Возможные причины проблем с DNS")" >> "$OUT"
if [ "${#CAUSES[@]}" -eq 0 ]; then
  echo "$(tx "No obvious causes found by the heuristics" "Не найдено явных причин по эвристикам")" >> "$OUT"
else
  for c in "${CAUSES[@]}"; do
    echo "- $c" >> "$OUT"
  done
fi
if [ "${#COVERAGE_GAPS[@]}" -gt 0 ]; then
  echo -e "$(tx "\n>> REPORT INCOMPLETE: check limitations" "\n>> ОТЧЁТ НЕПОЛНЫЙ: ограничения проверки")" >> "$OUT"
  for c in "${COVERAGE_GAPS[@]}"; do
    echo "- $c" >> "$OUT"
  done
fi
if [ "${#NOTES[@]}" -gt 0 ]; then
  echo -e "$(tx "\n>> For your information (not problems)" "\n>> К сведению (не проблемы)")" >> "$OUT"
  for c in "${NOTES[@]}"; do
    echo "- $c" >> "$OUT"
  done
fi

flush_step_details

title "$(tx "Check result" "Результат проверки")"
if [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$E2E_VERDICT" = "PASS" ]; then
  printf '  %s%s✓ %s%s\n' "$BOLD" "$GREEN" "$(tx "TEST PASSED: the host is reachable, TLS and HTTP are fine" "ТЕСТ УСПЕШНО ПРОЙДЕН: хост доступен, TLS и HTTP в норме")" "$RESET"
elif [ "$DNS_ONLY_VERDICT" = "PASS" ] && [ "$PRIMARY_CLASSIFICATION" = "tls_certificate_or_trust_issue" ]; then
  printf '  %s%s! %s%s\n' "$BOLD" "$YELLOW" "$(tx "TEST PARTIALLY PASSED: the host is reachable, but the TLS certificate failed the trust check" "ТЕСТ ЧАСТИЧНО ПРОЙДЕН: хост доступен, но TLS сертификат не прошел проверку доверия")" "$RESET"
else
  printf '  %s%s✗ %s%s\n' "$BOLD" "$RED" "$(tx "TEST FAILED: there are problems with reachability, resolving or TLS" "ТЕСТ НЕ ПРОЙДЕН: есть проблемы с доступностью, резолвингом или TLS")" "$RESET"
fi
if [ "${#CAUSES[@]}" -eq 0 ]; then
  ok "$(tx "No obvious DNS problems found by the heuristics." "Не найдено явных проблем с DNS по эвристике.")"
else
  title "$(tx "Possible problems" "Возможные проблемы")"
  for c in "${CAUSES[@]}"; do
    warn "$c"
  done
fi
if [ "${#NOTES[@]}" -gt 0 ]; then
  title "$(tx "For your information (not problems)" "К сведению (не проблемы)")"
  for c in "${NOTES[@]}"; do
    info "$c"
  done
fi
if [ "${#COVERAGE_GAPS[@]}" -gt 0 ]; then
  title "$(tx "Report incomplete: some checks were not performed" "Отчёт неполный: часть проверок не выполнена")"
  for c in "${COVERAGE_GAPS[@]}"; do
    warn "$c"
  done
fi
title "$(tx "Report" "Отчёт")"
info "$(tx "Saved to: ${MAGENTA}${OUT}${RESET}" "Сохранён в: ${MAGENTA}${OUT}${RESET}")"
reveal_report_in_finder "$OUT"
# «Полный доступ к диску» — широкое разрешение: предлагаем вернуть его обратно,
# но только если этот запуск сам его запрашивал.
if [ "$FDA_GRANTED_NOW" -eq 1 ]; then
  title "$(tx "Disk access" "Доступ к диску")"
  info "$(tx "Full Disk Access for $(terminal_app_name) was needed only while the script ran." "«Полный доступ к диску» для $(terminal_app_name) был нужен только на время работы скрипта.")"
  info "$(tx "You can turn it off: System Settings > Privacy & Security > Full Disk Access > switch off $(terminal_app_name)." "Его можно отключить: Системные настройки → Конфиденциальность и безопасность → Полный доступ к диску → выключите переключатель рядом с $(terminal_app_name).")"
fi
printf '\n'
