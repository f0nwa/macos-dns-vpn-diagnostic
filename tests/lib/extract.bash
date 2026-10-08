#!/usr/bin/env bash
# Извлекает тело именованной bash-функции из основного скрипта, чтобы тесты
# всегда работали с реальным кодом macos-dns-test.sh, а не с его копией.
# Формат функций в скрипте: "name() {" ... "}" (закрывающая скобка одна на строке).

SCRIPT_UNDER_TEST="${SCRIPT_UNDER_TEST:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/macos-dns-test.sh}"

extract_fn() {
  local fn="$1"
  awk -v fn="$fn" 'BEGIN{s=0} $0 ~ "^"fn"\\(\\) \\{$"{s=1} s{print} s && /^}$/{exit}' "$SCRIPT_UNDER_TEST"
}

# Тесты по умолчанию проверяют русский интерфейс (английский — в i18n.bats).
# Полные прогоны скрипта получают тот же язык через переменную окружения.
export DNS_DIAG_LANG="${DNS_DIAG_LANG:-ru}"
LANG_UI=ru

# Источники (source) набор функций из основного скрипта в текущий шелл теста.
# tx подключается всегда: через него идут все пользовательские строки.
source_fns() {
  local tmp
  tmp="$(mktemp)"
  for fn in tx "$@"; do
    extract_fn "$fn" >> "$tmp"
    echo >> "$tmp"
  done
  # shellcheck disable=SC1090
  source "$tmp"
  rm -f "$tmp"
}
