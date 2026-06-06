import streamlit as st
import requests
import urllib.parse
import socket
import time
import random


st.set_page_config(page_title="MTProto Proxy Web", page_icon="💎", layout="centered")

GITHUB_URL = "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt"


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


st.title(" MTProto Proxy Manager")

if 'working_proxies' not in st.session_state:
    st.session_state.working_proxies = []


if st.button("Обновить и проверить список", use_container_width=True):
    with st.spinner("Проверяем прокси..."):
        try:
            response = requests.get(GITHUB_URL)
            response.raise_for_status()
            all_proxies = [line.strip() for line in response.text.split('\n') if line.strip()]

            random.shuffle(all_proxies)

            found_proxies = []
            for proxy in all_proxies[:40]:  # Увеличили пул проверки до 40
                server, port = extract_server_port(proxy)
                ping = check_tcp_ping(server, port)
                if ping is not None:
                    found_proxies.append({"url": proxy, "ping": ping})

            found_proxies = sorted(found_proxies, key=lambda x: x['ping'])
            st.session_state.working_proxies = found_proxies

        except Exception as e:
            st.error(f"Ошибка: {e}")

st.markdown("---")

if st.session_state.working_proxies:
    st.write(f" Найдено живых серверов: {len(st.session_state.working_proxies)}")
    head_col1, head_col2, head_col3 = st.columns([1, 2, 5])
    head_col1.markdown("**№**")
    head_col2.markdown("** Пинг**")
    head_col3.markdown("**Ссылка для подключения**")
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
        col3.markdown(f"[Подключить прокси в Telegram]({tg_link})")
        st.markdown(
            "<div style='margin-top: -5px; margin-bottom: -5px; border-top: 1px solid rgba(0,0,0,0.05);'></div>",
            unsafe_allow_html=True)
else:
    st.info("Список пуст. Нажмите кнопку выше для поиска активных прокси.")