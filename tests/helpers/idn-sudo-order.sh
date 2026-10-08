#!/usr/bin/env bash
# Выполняет настоящий этап подготовки домена без установки пакетов и sudo.
set -eu
source "$(dirname "$0")/../lib/extract.bash"
source_fns start_sudo_keepalive stop_sudo_keepalive title info warn ok fail
trap stop_sudo_keepalive EXIT
FLAG_DOMAIN='честныйзнак.рф'
BOLD='' CYAN='' GREEN='' YELLOW='' RED='' MAGENTA='' DETAIL='' RESET=''
FLAG_YES=0
SUDO_TEST_AUTH=no
export SUDO_TEST_AUTH
sudo() {
  case "$1" in
    -v) SUDO_TEST_AUTH=yes; export SUDO_TEST_AUTH ;;
    -n) return 1 ;;
    *) return 1 ;;
  esac
}
# Имитируем машину без рабочего Python и Homebrew.
detect_primary_python3_bin() { PYTHON3_SKIP_REASON=apple_stub_missing_clt; return 1; }
detect_homebrew_python3_bin() { return 1; }
command() {
  if [ "${1:-}" = -v ] && [ "${2:-}" = brew ]; then return 1; fi
  builtin command "$@"
}
ask_yes_no() { return 0; }
BREW_INSTALL_RESULT=''
emit_fact() {
  printf '%s\n' "$*"
  if [ "$2" = brew_install_attempt ]; then BREW_INSTALL_RESULT="$3"; fi
}
curl() {
  # Неинтерактивный установщик требует заранее полученной sudo-сессии.
  cat <<'INSTALLER'
if [ "$SUDO_TEST_AUTH" != yes ]; then
  echo 'Insufficient permissions to install Homebrew' >&2
  exit 1
fi
exit 0
INSTALLER
}
# Сохраняем порядок выполнения из основного скрипта, включая вызов sudo.
eval "$(sed -n '/^TEST_DOMAIN=""$/,/^say_step "\$(tx "1\/12/{ /^say_step "\$(tx "1\/12/d; p; }' "$SCRIPT_UNDER_TEST")" 3<<< ''

[ "$BREW_INSTALL_RESULT" = success ] || { echo "Ошибка: установщик запущен без sudo-сессии" >&2; exit 1; }
