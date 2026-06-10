# Proxy Manager

Streamlit-приложение для сбора MTProto-прокси (Telegram) и VLESS-ключей из нескольких независимых источников, с проверкой работоспособности.

## Возможности

- **MTProto**: сбор из нескольких репозиториев, дедупликация по `server:port`, проверка пинга.
- **VLESS**: каскадная фильтрация ключей на работоспособность:
  1. **TCP** — отсев мёртвых серверов (по уникальным `host:port`);
  2. **TLS handshake** — проверка рукопожатия с нужным SNI (для `tls`/`reality`);
  3. **Xray** — реальный URL-тест только по выжившим ключам.
- Пагинация, фильтр по тексту, выгрузка в `.txt`.

## Установка

```bash
pip install -r requirements.txt
streamlit run proxy_manager.py
```

## Опционально: реальный URL-тест через Xray

Для этапа 3 нужен бинарь `xray` ([Xray-core releases](https://github.com/XTLS/Xray-core/releases)) в `PATH` или рядом с `proxy_manager.py`. Без него каскад завершается на этапе TLS.

## Настройки

Константы в начале `proxy_manager.py`:

| Константа | Назначение | По умолчанию |
|---|---|---|
| `MAX_TCP_WORKERS` | потоков TCP-проверки | 100 |
| `MAX_TLS_WORKERS` | потоков TLS-проверки | 60 |
| `MAX_XRAY_WORKERS` | параллельных Xray url-тестов | 8 |
| `DEFAULT_TEST_URL` | URL для проверки (ожидается 200/204) | `https://www.gstatic.com/generate_204` |

## Источники

Списки прокси и ключей собираются из публичных репозиториев и подписок:

- [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) — WHITE/BLACK списки VLESS Reality (SNI/CIDR, мобильные)
- [AvenCores/goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs)
- [zieng2/wl](https://github.com/zieng2/wl)
- [Sanuyyq/sub-storage1](https://github.com/Sanuyyq/sub-storage1)
- [bywarm/rser](https://gitverse.ru/bywarm/rser) (GitVerse)
- [LowiK/LowiKLive](https://gitverse.ru/LowiK/LowiKLive) (GitVerse)
- [cid-uskoritel/cid-white](https://gitverse.ru/cid-uskoritel/cid-white) (GitVerse)
- wlrus.lol, nowmeow.pw — публичные подписки

MTProto-источники:

- [SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto)
- [ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy)
- [Grim1313/mtproto-for-telegram](https://github.com/Grim1313/mtproto-for-telegram)
- [Argh94/telegram-proxy-scraper](https://github.com/Argh94/telegram-proxy-scraper)

## Дисклеймер

Источники прокси/ключей — сторонние. Используйте на свой риск и в соответствии с законодательством вашей юрисдикции.
