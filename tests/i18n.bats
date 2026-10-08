#!/usr/bin/env bats
# Двуязычный интерфейс: язык по DNS_DIAG_LANG или по языку macOS; английские
# строки есть у каждого пользовательского сообщения.

load 'lib/extract'

SCRIPT_BASH="${SCRIPT_BASH:-/bin/bash}"
# Кириллица в байтах UTF-8 (grep -P без -P-режима локали работает одинаково на macOS и Linux).
CYRILLIC=$'[\xd0\xd1][\x80-\xbf]'

setup() {
  source_fns detect_lang
  OUT_FILE="$(mktemp -u)/i18n_report.txt"
  mkdir -p "$(dirname "$OUT_FILE")"
}

teardown() {
  rm -f "$OUT_FILE"
}

@test "tx: выбирает строку по LANG_UI" {
  LANG_UI=ru
  [ "$(tx "english" "русский")" = "русский" ]
  LANG_UI=en
  [ "$(tx "english" "русский")" = "english" ]
}

@test "detect_lang: DNS_DIAG_LANG имеет приоритет над языком системы" {
  LANG=ru_RU.UTF-8 DNS_DIAG_LANG=en detect_lang
  [ "$LANG_UI" = "en" ]
  LANG=en_US.UTF-8 DNS_DIAG_LANG=ru detect_lang
  [ "$LANG_UI" = "ru" ]
}

@test "detect_lang: без DNS_DIAG_LANG берёт язык macOS (AppleLanguages), иначе локаль" {
  unset DNS_DIAG_LANG SUDO_USER
  defaults() { printf '(\n    "ru-RU",\n    "en-RU"\n)\n'; }
  detect_lang
  [ "$LANG_UI" = "ru" ]
  defaults() { printf '(\n    "en-RU",\n    "ru-RU"\n)\n'; }
  detect_lang
  [ "$LANG_UI" = "en" ]
  defaults() { return 1; }
  LC_ALL=ru_RU.UTF-8 detect_lang
  [ "$LANG_UI" = "ru" ]
  LC_ALL=de_DE.UTF-8 detect_lang
  [ "$LANG_UI" = "en" ]
}

@test "--help: английская и русская справка" {
  run env DNS_DIAG_LANG=en "$SCRIPT_BASH" "$SCRIPT_UNDER_TEST" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Skip the interactive prompt"* ]]
  run env DNS_DIAG_LANG=ru "$SCRIPT_BASH" "$SCRIPT_UNDER_TEST" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Пропустить интерактивный ввод"* ]]
}

@test "английский прогон: ни консоль, ни отчёт не содержат кириллицы" {
  run env DNS_DIAG_LANG=en timeout 90 "$SCRIPT_BASH" "$SCRIPT_UNDER_TEST" --domain=example.com --yes --no-open --no-external-dns --output="$OUT_FILE" < /dev/null
  [ "$status" -eq 0 ]
  ! printf '%s' "$output" | grep -q "$CYRILLIC"
  ! grep -q "$CYRILLIC" "$OUT_FILE"
  [[ "$output" == *"Check result"* ]]
}

@test "русский прогон: итоговый блок на русском" {
  run env DNS_DIAG_LANG=ru timeout 90 "$SCRIPT_BASH" "$SCRIPT_UNDER_TEST" --domain=example.com --yes --no-open --no-external-dns --output="$OUT_FILE" < /dev/null
  [ "$status" -eq 0 ]
  [[ "$output" == *"Результат проверки"* ]]
}

@test "в коде нет непереведённых строк: кириллица вне комментариев только внутри tx и справки" {
  # Разрешено: русская ветка --help, ответы д/н и продолжения многострочных tx.
  run awk '
    /<<.USAGE.$/ { in_usage = 1; next }
    /^USAGE$/ { in_usage = 0; next }
    in_usage || /^[[:space:]]*#/ { next }
    /[\xd0\xd1][\x80-\xbf]/ && $0 !~ /tx "/ && $0 !~ /hint="\[Д\/н\]"/ \
      && $0 !~ /y\|Y\|yes\|YES\|д/ && $0 !~ /n\|N\|no\|NO\|н/ \
      && $0 !~ /^Установка идёт автоматически/ && $0 !~ /^The installation is automatic/ { print NR": "$0 }
  ' "$SCRIPT_UNDER_TEST"
  [ -z "$output" ] || { echo "$output" >&3; false; }
}
