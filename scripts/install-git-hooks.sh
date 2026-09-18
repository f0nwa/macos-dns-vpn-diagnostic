#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Ошибка: $ROOT_DIR не является git-репозиторием."
  echo "Сначала выполните: git init"
  exit 1
fi

chmod +x "$ROOT_DIR/.githooks/pre-commit"
git -C "$ROOT_DIR" config core.hooksPath .githooks

echo "Git hooks включены: core.hooksPath=.githooks"
echo "Хук pre-commit будет автоматически обновлять '# Last Modified:' в macos-dns-test.sh"
