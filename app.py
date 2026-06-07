import streamlit as st
import requests
import urllib.parse
import socket
import time
import random

# Настройка страницы в браузере
st.set_page_config(page_title="MTProto & VLESS Proxy Web", layout="centered")

# Список всех источников MTProto прокси
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/main/proxy.txt"
]

# Список источников VLESS ключей
VLESS_SOURCES = [
    "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
    "https://gitverse.ru/api/repos/LowiK/LowiKLive/raw/branch/main/ObhodBSfree.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://nowmeow.pw/8ybBd3fdCAQ6Ew5H0d66Y1hMbh63GpKUtEXQClIu/whitelist",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://wlrus.lol/confs/merged.txt",
    "https://wlrus.lol/confs/selected.txt",
    "https://raw.githubusercontent.com/Sanuyyq/sub-storage1/refs/heads/main/bs.txt",
    "https://raw.githubusercontent.com/Sanuyyq/sub-storage1/refs/heads/main/update.txt",
]


def extract_server_port(proxy_url):
    try:
        url_for_parsing = proxy_url.replace('tg://', 'http://')
        parsed = urllib.parse.urlparse(url_for_parsing)
        query_params = urllib.parse.parse_qs(parsed.query)
        server = query_params.get('server', [None])[0]
        port = query_params.get('port', [None])[0]
        return server, port
    except Exception:
        return None, None


def check_tcp_ping(host, port, timeout=0.4):
    if not host or not port:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        sock.connect((host, int(port)))
        end_time = time.time()
        sock.close()
        return int((end_time - start_time) * 1000)
    except Exception:
        return None


def extract_vless_name(vless_url):
    """Извлекает читаемое имя из VLESS URL (из фрагмента #...)"""
    try:
        if '#' in vless_url:
            fragment = vless_url.split('#', 1)[1]
            name = urllib.parse.unquote(fragment)
            # Убираем числовой префикс типа "1. 🇵🇱 VLESS | ..."
            name = name.strip()
            return name if name else "VLESS Ключ"
        return "VLESS Ключ"
    except Exception:
        return "VLESS Ключ"


def extract_vless_host(vless_url):
    """Извлекает хост:порт из VLESS URL для отображения"""
    try:
        # vless://uuid@host:port?params#name
        without_scheme = vless_url[len("vless://"):]
        at_idx = without_scheme.find('@')
        if at_idx == -1:
            return ""
        host_part = without_scheme[at_idx + 1:]
        # Убираем параметры
        if '?' in host_part:
            host_part = host_part.split('?')[0]
        elif '#' in host_part:
            host_part = host_part.split('#')[0]
        return host_part
    except Exception:
        return ""


st.title("🔐 Proxy Manager")
st.write("MTProto для Telegram и VLESS ключи из нескольких независимых источников.")

tab_mtproto, tab_vless = st.tabs(["📡 MTProto Proxies", "🔑 VLESS Keys"])

# ─── Вкладка MTProto ────────────────────────────────────────────────────────
with tab_mtproto:
    st.subheader("MTProto Proxy Manager")
    st.write("Сбор данных из 4 независимых репозиториев без дублирования серверов.")

    if 'working_proxies' not in st.session_state:
        st.session_state.working_proxies = []

    if st.button("Обновить базу и проверить пинг", use_container_width=True, key="btn_mtproto"):
        with st.spinner("Опрашиваем источники и фильтруем дубликаты..."):
            try:
                unique_proxies_set = set()

                for url in PROXY_SOURCES:
                    try:
                        response = requests.get(url, timeout=4)
                        if response.status_code == 200:
                            lines = response.text.split('\n')
                            for line in lines:
                                proxy = line.strip()
                                if proxy and (proxy.startswith("tg://") or proxy.startswith("https://t.me/")):
                                    unique_proxies_set.add(proxy)
                    except Exception:
                        continue

                proxies_list = list(unique_proxies_set)
                random.shuffle(proxies_list)

                found_proxies = []
                for proxy in proxies_list[:50]:
                    server, port = extract_server_port(proxy)
                    ping = check_tcp_ping(server, port)
                    if ping is not None:
                        found_proxies.append({"url": proxy, "ping": ping})

                found_proxies = sorted(found_proxies, key=lambda x: x['ping'])
                st.session_state.working_proxies = found_proxies

            except Exception as e:
                st.error(f"Ошибка при обработке списков: {e}")

    st.markdown("---")
    if st.session_state.working_proxies:
        st.write(f"Найдено уникальных активных прокси: {len(st.session_state.working_proxies)}")

        head_col1, head_col2, head_col3 = st.columns([1, 2, 5])
        head_col1.markdown("**Номер**")
        head_col2.markdown("**Пинг**")
        head_col3.markdown("**Действие**")
        st.markdown("<div style='margin-top: -10px; margin-bottom: 10px; border-top: 1px solid #ccc;'></div>",
                    unsafe_allow_html=True)

        for idx, proxy_data in enumerate(st.session_state.working_proxies):
            tg_link = proxy_data['url']
            if tg_link.startswith("https://t.me/"):
                tg_link = tg_link.replace("https://t.me/", "tg://")

            col1, col2, col3 = st.columns([1, 2, 5])

            col1.write(f"{idx + 1}")
            col2.markdown(f"<span style='color: #2a9d8f; font-weight: bold;'>{proxy_data['ping']} мс</span>",
                          unsafe_allow_html=True)

            col3.markdown(
                f"<a href='{tg_link}' style='display: inline-block; background-color: #3390ec; color: white; padding: 5px 10px; border-radius: 6px; text-decoration: none; font-size: 14px; font-weight: bold;'>Подключить в Telegram</a>",
                unsafe_allow_html=True)

            st.markdown(
                "<div style='margin-top: -5px; margin-bottom: -5px; border-top: 1px solid rgba(0,0,0,0.05);'></div>",
                unsafe_allow_html=True)
    else:
        st.info("Таблица пуста. Нажмите кнопку выше, чтобы запустить сканирование объединенной базы.")

# ─── Вкладка VLESS ──────────────────────────────────────────────────────────
with tab_vless:
    st.subheader("VLESS Keys")
    st.write("Ключи собраны из нескольких репозиториев. Проверку пинга выполните самостоятельно в вашем клиенте (v2rayN, Hiddify, Streisand и др.).")

    st.info(
        "💡 **Как использовать:** Скопируйте нужный ключ и импортируйте его в ваш VPN-клиент (v2rayN, Hiddify, Nekoray, Streisand и т.д.).",
        icon=None
    )

    if 'vless_keys' not in st.session_state:
        st.session_state.vless_keys = []
    if 'vless_loaded' not in st.session_state:
        st.session_state.vless_loaded = False

    col_btn1, col_btn2 = st.columns([3, 1])
    with col_btn1:
        if st.button("Загрузить / Обновить VLESS ключи", use_container_width=True, key="btn_vless"):
            with st.spinner("Загружаем ключи из источников..."):
                unique_vless = set()
                source_stats = {}

                for url in VLESS_SOURCES:
                    source_name = url.split("/")[-1]
                    try:
                        response = requests.get(url, timeout=10)
                        if response.status_code == 200:
                            count = 0
                            for line in response.text.splitlines():
                                line = line.strip()
                                if line.startswith("vless://"):
                                    unique_vless.add(line)
                                    count += 1
                            source_stats[source_name] = count
                        else:
                            source_stats[source_name] = 0
                    except Exception:
                        source_stats[source_name] = 0

                st.session_state.vless_keys = sorted(unique_vless)
                st.session_state.vless_loaded = True

                # Показываем статистику по источникам
                stats_msg = "✅ Загружено из источников: " + " | ".join(
                    f"**{k}**: {v}" for k, v in source_stats.items()
                )
                st.success(stats_msg)

    with col_btn2:
        if st.session_state.vless_keys:
            all_keys_text = "\n".join(st.session_state.vless_keys)
            st.download_button(
                label="⬇️ Скачать всё",
                data=all_keys_text,
                file_name="vless_keys.txt",
                mime="text/plain",
                use_container_width=True,
                key="btn_download_vless"
            )

    st.markdown("---")

    if st.session_state.vless_keys:
        keys = st.session_state.vless_keys
        st.write(f"Найдено уникальных VLESS ключей: **{len(keys)}**")

        # Поиск / фильтр
        search = st.text_input("🔍 Фильтр по тексту (SNI, хост, имя...)", key="vless_search", placeholder="например: yandex.ru")
        if search:
            keys = [k for k in keys if search.lower() in k.lower()]
            st.write(f"Показано после фильтра: **{len(keys)}**")

        # Заголовок таблицы
        h1, h2, h3 = st.columns([1, 4, 2])
        h1.markdown("**#**")
        h2.markdown("**Имя / Хост**")
        h3.markdown("**Копировать**")
        st.markdown("<div style='border-top: 1px solid #ccc; margin-bottom: 8px;'></div>", unsafe_allow_html=True)

        # Пагинация
        PAGE_SIZE = 50
        total_pages = max(1, (len(keys) + PAGE_SIZE - 1) // PAGE_SIZE)
        if 'vless_page' not in st.session_state:
            st.session_state.vless_page = 0
        # Сброс страницы при изменении поиска
        if search != st.session_state.get('vless_last_search', ''):
            st.session_state.vless_page = 0
            st.session_state.vless_last_search = search

        page = st.session_state.vless_page
        page_keys = keys[page * PAGE_SIZE: (page + 1) * PAGE_SIZE]

        for idx, key in enumerate(page_keys):
            global_idx = page * PAGE_SIZE + idx + 1
            name = extract_vless_name(key)
            host = extract_vless_host(key)
            display_name = name if name != "VLESS Ключ" else host

            c1, c2, c3 = st.columns([1, 4, 2])
            c1.write(str(global_idx))
            c2.markdown(
                f"<span title='{key}' style='font-size:13px; word-break:break-all;'>{display_name}</span>",
                unsafe_allow_html=True
            )
            # Кнопка копирования через st.code (компактная)
            c3.code(key[:30] + "…" if len(key) > 30 else key, language=None)

            st.markdown("<div style='border-top: 1px solid rgba(0,0,0,0.05); margin: 2px 0;'></div>",
                        unsafe_allow_html=True)

        # Навигация по страницам
        if total_pages > 1:
            st.markdown("---")
            nav1, nav2, nav3 = st.columns([1, 2, 1])
            with nav1:
                if st.button("← Назад", disabled=(page == 0), key="vless_prev"):
                    st.session_state.vless_page -= 1
                    st.rerun()
            with nav2:
                st.markdown(f"<div style='text-align:center; padding-top:6px;'>Страница {page + 1} из {total_pages}</div>",
                            unsafe_allow_html=True)
            with nav3:
                if st.button("Вперёд →", disabled=(page >= total_pages - 1), key="vless_next"):
                    st.session_state.vless_page += 1
                    st.rerun()

        st.markdown("---")
        st.markdown("### Все ключи (для быстрого копирования)")
        st.text_area(
            label="Все уникальные VLESS ключи",
            value="\n".join(st.session_state.vless_keys),
            height=200,
            key="vless_all_text",
            label_visibility="collapsed"
        )
    elif st.session_state.vless_loaded:
        st.warning("Не удалось загрузить VLESS ключи. Проверьте доступность источников.")
    else:
        st.info("Нажмите кнопку выше, чтобы загрузить VLESS ключи.")