# macOS DNS/VPN Diagnostic Script

**`macos-dns-test.sh`** — интерактивный скрипт для глубокой диагностики DNS, VPN/Proxy и сетевой фильтрации на macOS: снимает полный сетевой срез, проверяет резолвинг домена по каждому пути и через e2e-запрос, и выдаёт классификацию причины с матрицей гипотез и уровнем уверенности.

[![CI](https://github.com/f0nwa/macos-dns-vpn-diagnostic/actions/workflows/ci.yml/badge.svg)](https://github.com/f0nwa/macos-dns-vpn-diagnostic/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-black.svg?style=flat-square)](#требования)
[![Shell: Bash](https://img.shields.io/badge/shell-bash-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](macos-dns-test.sh)
[![Linted with ShellCheck](https://img.shields.io/badge/linted-shellcheck-yellow.svg?style=flat-square)](.github/workflows/ci.yml)

Репозиторий: https://github.com/f0nwa/macos-dns-vpn-diagnostic

## Оглавление

- [Что делает и что вы получите](#что-делает-и-что-вы-получите)
- [Быстрый старт](#быстрый-старт)
- [Важно](#важно)
- [Требования](#требования)
- [Неинтерактивный режим](#неинтерактивный-режим)
- [Для контрибьюторов](#для-контрибьюторов)
- [License](#license)

## Что делает и что вы получите

- Запрашивает домен для проверки (кириллица/IDN или латиница).
- Для IDN-доменов конвертирует в punycode через `python3`; если `python3`/`brew` не найдены — предлагает их установку по подтверждению, либо ручной ввод punycode.
- Снимает полный сетевой срез: DNS/Proxy-конфигурацию (`scutil`, `networksetup`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/resolver`), состояние PF firewall, активные VPN/Proxy/Filter процессы и system extensions, маршрутизацию, `utun`-интерфейсы и scoped-resolver пути.
- Проверяет резолвинг домена тремя путями: по каждому найденному DNS-серверу, через системный резолвер, через scoped nameserver (по данным `scutil --dns`).
- Делает e2e-проверку через `curl` (resolve → connect → TLS → HTTP).
- Формирует итоговую классификацию проблемы и матрицу гипотез с уровнем уверенности.

Результат — подробный отчёт в текущей директории: `<user>_<host>_dns_diag_<YYYYMMDD_HHMMSS>.txt`. Основные секции отчёта, на которые стоит смотреть в первую очередь (пример, значения иллюстративные):

```text
>> DNS_ONLY_RESULT
domain=example.com
resolvers_tested=2
a_ok=1
system_resolver_match=partial
dominant_failure_reason=SERVFAIL
scoped_resolvers_tested=1
scoped_resolvers_ok=0
verdict=FAIL

>> E2E_RESULT
url=https://example.com
resolve_phase=ok
connect_phase=ok
tls_phase=fail
http_phase=not_run
host_reachable=yes
tls_trust_ok=no
verdict=FAIL

>> PRIMARY_CLASSIFICATION
PRIMARY_CLASSIFICATION=tls_certificate_or_trust_issue
MOST_LIKELY_LAYER=tls
HUMAN_STATUS=ТЕСТ ЧАСТИЧНО ПРОЙДЕН: хост доступен, но TLS сертификат не прошел проверку доверия

>> EXEC_SUMMARY
1. [HIGH/70] TLS certificate untrusted (layer=tls)
   evidence: connect ok, tls handshake fail
   next: проверить сертификат перехватывающего прокси/фильтра

>> EVIDENCE_MATRIX
Symptom | Evidence | Layer | Confidence | Impact | Next check
...     | ...      | ...   | HIGH/70    | ...    | ...
```

Плюс человекочитаемый раздел «Возможные причины проблем с DNS» с итоговым списком гипотез.

## Быстрый старт

Самый быстрый способ — one-liner (сразу выполнение):

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh")
```

> [!TIP]
> Рекомендуемый вариант — сначала скачать и проверить, потом запустить:
> ```bash
> RAW_URL="https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh"
> curl -fL "$RAW_URL" -o /tmp/macos-dns-test.sh
> chmod +x /tmp/macos-dns-test.sh
> bash /tmp/macos-dns-test.sh
> ```

Или из локального клона:

```bash
chmod +x macos-dns-test.sh
./macos-dns-test.sh
```

Как это проходит:

1. Запустите скрипт и введите домен для проверки (кириллица/IDN или латиница) в формате `name.zone`.
2. Введите локальный пароль администратора, когда скрипт запросит `Password`.
3. Если `python3`/CLT недоступны для IDN-конвертации — согласитесь на установку `Homebrew + python3`.
4. На шаге `7/12` разрешите `Terminal` доступ к Apple Music/медиатеке (системный запрос macOS, см. ниже).
5. Дождитесь завершения всех этапов диагностики и итогового отчёта.

## Важно

> [!WARNING]
> - Скрипт читает и логирует много системной информации: сеть, сервисы, процессы, правила firewall.
> - На шаге `7/12` (поиск конфигов приложений в `~/Library/...`) macOS может показать системный запрос доступа к Apple Music/медиатеке для `Terminal`. Причина — ограничения приватности macOS (TCC) при обходе пользовательских директорий; это побочный системный диалог, а не обращение скрипта к Apple Music API.
> - **Перед публикацией отчёта** проверьте файл и удалите чувствительные данные (внутренние IP, имена хостов, пути и т.д.).

## Требования

| Компонент | Статус | Комментарий |
| --- | --- | --- |
| macOS | обязательно | протестировано на macOS Tahoe 26.0 |
| `bash` | обязательно | |
| `sudo` | обязательно | часть проверок требует повышенных прав |
| `dig` | желательно | при отсутствии используется `nslookup` |
| `python3` | опционально | для автоматического IDN → punycode |
| `brew` | опционально | при отсутствии скрипт может установить его сам по подтверждению |

## Неинтерактивный режим

Для автоматизации и тестов есть флаги (без флагов поведение полностью прежнее, интерактивное):

```bash
./macos-dns-test.sh --domain=ya.ru --yes --output=/tmp/report.txt
```

| Флаг | Назначение |
| --- | --- |
| `--domain=<host>` | не спрашивать домен интерактивно |
| `--yes` | автоматически отвечать «да» на все y/n запросы (в т.ч. установку Homebrew/python3 для IDN) |
| `--output=<path>` | писать отчёт в конкретный файл вместо `$(pwd)/<user>_<host>_dns_diag_<ts>.txt` |
| `--verify-integrity` | перед запуском сверить свой sha256 с `checksums.txt` из репозитория (нужен локальный клон, не работает при `curl \| bash` — см. [«Git-хуки и проверка целостности»](#для-контрибьюторов)) |

## Для контрибьюторов

<details>
<summary>Тесты, линтинг, CI, git-хуки и проверка целостности</summary>

### Тесты и линтинг

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

> [!NOTE]
> `--verify-integrity` требует, чтобы `scripts/integrity-lib.sh` лежал рядом со скриптом — то есть работает только при локальном клоне/скачивании репозитория, **не** при однострочном `curl | bash` из README (туда скачивается только сам `macos-dns-test.sh`).

</details>

## License

MIT. См. файл [`LICENSE`](LICENSE).
