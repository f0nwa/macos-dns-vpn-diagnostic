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

В отчете есть ключевые секции:

- `DNS_ONLY_RESULT`
- `E2E_RESULT`
- `PRIMARY_CLASSIFICATION`
- `EXEC_SUMMARY`
- `EVIDENCE_MATRIX`
- `Возможные причины проблем с DNS`

## Требования

- macOS
- `bash`
- `sudo` (часть проверок требует повышенных прав)
- Желательно: `dig` (если нет, используется `nslookup`)
- Опционально: `python3` (автоматический IDN -> punycode)
- Опционально: `brew` (если отсутствует, скрипт может установить его автоматически по подтверждению)

## Протестировано

- macOS Tahoe 26.0

## Запуск

```bash
chmod +x macos-dns-test.sh
./macos-dns-test.sh
```

После запуска введите домен в формате `name.zone`.

## Запуск по сети через GitHub Raw

Рекомендуемый вариант (скачать, проверить, затем запустить):

```bash
RAW_URL="https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh"
curl -fL "$RAW_URL" -o /tmp/macos-dns-test.sh
chmod +x /tmp/macos-dns-test.sh
bash /tmp/macos-dns-test.sh
```

Быстрый one-liner (менее безопасно, т.к. сразу выполнение):

```bash
curl -fsSL "https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/macos-dns-test.sh" | bash
```

Совет: для стабильности указывайте `tag` или конкретный commit SHA вместо плавающей ветки.

## Важно

- Скрипт читает и логирует много системной информации (сеть, сервисы, процессы, правила firewall).
- Перед публикацией отчета проверьте файл и удалите чувствительные данные (внутренние IP, имена хостов, пути и т.д.).

## License

MIT. См. файл `LICENSE`.
