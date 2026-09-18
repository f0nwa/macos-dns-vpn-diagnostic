#!/usr/bin/env bash
# Пересчитывает checksums.txt для macos-dns-test.sh.
# Вызывается вручную (make/CI) или из .githooks/pre-commit при коммите.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

shasum -a 256 macos-dns-test.sh > checksums.txt
echo "checksums.txt обновлён:"
cat checksums.txt
