# macOS DNS/VPN Diagnostic Script

`macos-dns-test.sh` — интерактивный скрипт для глубокой диагностики DNS, VPN/Proxy и сетевой фильтрации на macOS.

Репозиторий: https://github.com/f0nwa/macos-dns-vpn-diagnostic

## Что делает

- Запрашивает домен для проверки.
- Для IDN-доменов:
  - конвертирует в punycode через `python3`, если он доступен;
  - если нет `python3` и `brew`, предлагает полную авто-установку Homebrew + `python3` (по подтверждению);
  - если `python3` отсутствует, а `brew` уже есть, предлагает установку `python3` через Homebrew;
  - если авто-конвертация недоступна, предлагает ввести punycode вручную.
- Снимает полный сетевой срез:
  - DNS/Proxy конфигурацию (`scutil`, `networksetup`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/resolver`).
  - Состояние PF firewall (`pfctl`, логи блокировок).
  - Активные VPN/Proxy/Filter процессы и system extensions.
  - Маршрутизацию, `utun`-интерфейсы и scoped-resolver пути.
- Проверяет резолвинг домена:
  - По каждому найденному DNS-серверу.
  - Через системный резолвер.
  - Через scoped nameserver (по данным `scutil --dns`).
- Делает e2e-проверку через `curl` (resolve/connect/TLS/HTTP).
- Формирует итоговую классификацию проблемы и матрицу гипотез с уровнем уверенности.

## Результат

Скрипт создает подробный отчет в текущей директории:

`<user>_<host>_dns_diag_<YYYYMMDD_HHMMSS>.txt`

В отчете есть ключевые секции, на которые стоит смотреть в первую очередь:

- `DNS_ONLY_RESULT` - что с DNS по серверам и системному резолверу.
- `E2E_RESULT` - где ломается цепочка (resolve/connect/tls/http).
- `PRIMARY_CLASSIFICATION` - итоговая классификация и вероятный слой проблемы.
- `EXEC_SUMMARY` и `EVIDENCE_MATRIX` - топ гипотез, уверенность и следующие проверки.
- `Возможные причины проблем с DNS` — человекочитаемый список вероятных причин.

## Требования

- macOS
- `bash`
- `sudo` (часть проверок требует повышенных прав)
- Желательно: `dig` (если нет, используется `nslookup`)
- Опционально: `python3` (автоматический IDN -> punycode)
- Опционально: `brew` (если отсутствует, скрипт может установить его автоматически по подтверждению)

## Протестировано

- macOS Tahoe 26.0

## Запуск по сети через GitHub Raw

Быстрый one-liner (сразу выполнение):

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh")
```

Рекомендуемый вариант (скачать, проверить, затем запустить):

```bash
RAW_URL="https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh"
curl -fL "$RAW_URL" -o /tmp/macos-dns-test.sh
chmod +x /tmp/macos-dns-test.sh
bash /tmp/macos-dns-test.sh
```

## Запуск

```bash
chmod +x macos-dns-test.sh
./macos-dns-test.sh
```

## Как использовать

1. Запустите скрипт и введите домен для проверки DNS (можно кириллицей (IDN) или латиницей) в формате `name.zone`.
2. Введите локальный пароль администратора, когда скрипт запросит `Password`.
3. Если `python3`/CLT недоступны для IDN-конвертации, согласитесь на установку `Homebrew + python3`.
4. На шаге `7/12` разрешите `Terminal` доступ к Apple Music/медиатеке (системный запрос macOS).
5. Дождитесь завершения всех этапов диагностики и формирования итогового отчета.

## Важно

- Скрипт читает и логирует много системной информации (сеть, сервисы, процессы, правила firewall).
- На шаге `7/12` (поиск конфигов приложений в `~/Library/...`) macOS может показать системный запрос доступа к Apple Music/медиатеке для `Terminal`.
- Причина запроса: ограничения приватности macOS (TCC) при обходе пользовательских директорий; это побочный системный диалог, а не обращение скрипта к Apple Music API.
- Перед публикацией отчета проверьте файл и удалите чувствительные данные (внутренние IP, имена хостов, пути и т.д.).

## Неинтерактивный режим

Для автоматизации и тестов есть флаги:

```bash
./macos-dns-test.sh --domain=ya.ru --yes --output=/tmp/report.txt
```

- `--domain=<host>` — не спрашивать домен интерактивно.
- `--yes` — автоматически отвечать "да" на все y/n запросы (в т.ч. установку Homebrew/python3 для IDN).
- `--output=<path>` — писать отчёт в конкретный файл вместо `$(pwd)/<user>_<host>_dns_diag_<ts>.txt`.
- `--verify-integrity` — перед запуском сверить свой sha256 с `checksums.txt` из репозитория (нужен локальный клон, не работает при `curl | bash`, см. ниже).

Без флагов поведение полностью прежнее, интерактивное.

## Разработка и тесты

Тесты лежат в `tests/` и написаны на [bats-core](https://github.com/bats-core/bats-core):

```bash
brew install bats-core shellcheck
shellcheck -S warning macos-dns-test.sh scripts/*.sh
bats tests/*.bats
```

- `tests/regex_regression.bats` — регрессия на баг с двойным бэкслешем в regex разбора `scutil --dns` (см. историю коммитов).
- `tests/hypotheses.bats` — движок гипотез (`build_hypotheses`/`confidence_label`) на синтетических наборах фактов.
- `tests/cli_flags.bats` — неинтерактивный режим, включая полный прогон скрипта целиком.

Тесты вытаскивают функции прямо из `macos-dns-test.sh` (`tests/lib/extract.bash`), а не дублируют их копией, — так тест всегда проверяет актуальный код.

CI (`.github/workflows/ci.yml`) гоняет то же самое на `macos-latest` при каждом push/PR.

### Git-хуки и проверка целостности (опционально)

```bash
./scripts/install-git-hooks.sh
```

Включает `.githooks/pre-commit`, который при коммите `macos-dns-test.sh`:

1. обновляет `# Last Modified:` на сегодняшнюю дату;
2. пересчитывает `checksums.txt` (`scripts/generate-checksums.sh`).

`checksums.txt` используется флагом `--verify-integrity`: скрипт хэширует сам себя (sha256) и сверяет с опубликованной в репозитории записью — это защищает **локальный клон** от случайной порчи файла. Для строгой защиты от подмены на raw.githubusercontent.com (MITM) `scripts/integrity-lib.sh` поддерживает и `minisign`-подпись (`VERIFY_MODE=strict` + `DNS_DIAG_MINISIGN_PUBKEY`), но ключи подписи в этом репозитории пока не заведены.

Важное ограничение: `--verify-integrity` требует, чтобы `scripts/integrity-lib.sh` лежал рядом со скриптом — то есть работает только при локальном клоне/скачивании репозитория, **не** при однострочном `curl | bash` из README (туда скачивается только сам `macos-dns-test.sh`).

## License

MIT. См. файл `LICENSE`.