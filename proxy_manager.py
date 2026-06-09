"""
MTProto & VLESS Proxy Manager (Streamlit)

Запуск:
    pip install -r requirements.txt
    streamlit run proxy_manager.py

requirements.txt:
    streamlit>=1.30
    requests[socks]>=2.31

Фильтрация VLESS идёт каскадом, чтобы не гонять всю базу через тяжёлый Xray:
    1) TCP        — отсев мёртвых серверов (по уникальным host:port)
    2) TLS        — handshake с нужным SNI (для tls/reality)
    3) Xray       — реальный url-тест только по выжившим ключам

Для этапа Xray нужен бинарь xray (xray-core) в PATH или рядом с файлом.
Скачать: https://github.com/XTLS/Xray-core/releases
"""

import streamlit as st
import requests
import urllib.parse
import socket
import ssl
import time
import random
import html
import os
import json
import shutil
import tempfile
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────────────────────────────────
#  Конфигурация
# ──────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="MTProto & VLESS Proxy Web", layout="centered")

MTPROTO_PREVIEW_LIMIT = 80      # сколько MTProto прокси максимум пинговать
VLESS_TABLE_LIMIT = 100         # сколько строк показывать в таблице
PAGE_SIZE = 50                  # размер страницы пагинации
MAX_TCP_WORKERS = 100           # параллельных TCP-проверок
MAX_TLS_WORKERS = 60            # параллельных TLS-handshake проверок
MAX_XRAY_WORKERS = 8            # параллельных xray url-тестов (тяжелее)
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (ProxyManager/1.0)"}

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/main/proxy.txt",
]

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

_here = os.path.dirname(os.path.abspath(__file__))
XRAY_BIN = shutil.which("xray") or (
    os.path.join(_here, "xray") if os.path.exists(os.path.join(_here, "xray")) else None
)


# ──────────────────────────────────────────────────────────────────────────
#  Сетевые помощники
# ──────────────────────────────────────────────────────────────────────────
def http_get(url, timeout=10):
    return requests.get(url, timeout=timeout, headers=HTTP_HEADERS)


def check_tcp_ping(host, port, timeout=1.0):
    """Задержка TCP-handshake в мс или None. IPv4/IPv6."""
    if not host or not port:
        return None
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return None


def check_tls_handshake(host, port, server_name=None, timeout=2.5):
    """Пробует завершить TLS-handshake с указанным SNI. Задержка в мс или None.
    Проверка сертификата отключена: для Reality/самоподписанных это норма."""
    if not host or not port:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name or host) as ssock:
                ssock.do_handshake()
                return int((time.time() - start) * 1000)
    except Exception:
        return None


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ──────────────────────────────────────────────────────────────────────────
#  Парсинг MTProto
# ──────────────────────────────────────────────────────────────────────────
def extract_server_port(proxy_url):
    try:
        url_for_parsing = proxy_url.replace("tg://", "http://").replace(
            "https://t.me/", "http://"
        )
        parsed = urllib.parse.urlparse(url_for_parsing)
        q = urllib.parse.parse_qs(parsed.query)
        return q.get("server", [None])[0], q.get("port", [None])[0]
    except Exception:
        return None, None


# ──────────────────────────────────────────────────────────────────────────
#  Парсинг VLESS
# ──────────────────────────────────────────────────────────────────────────
def parse_vless(vless_url):
    """vless://uuid@host:port?params#name -> dict или None."""
    try:
        if not vless_url.startswith("vless://"):
            return None
        without_scheme = vless_url[len("vless://"):]

        name = ""
        if "#" in without_scheme:
            without_scheme, frag = without_scheme.split("#", 1)
            name = urllib.parse.unquote(frag).strip()

        query = {}
        if "?" in without_scheme:
            without_scheme, qs = without_scheme.split("?", 1)
            query = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}

        at_idx = without_scheme.find("@")
        if at_idx == -1:
            return None
        uuid = without_scheme[:at_idx]
        host_part = without_scheme[at_idx + 1:]

        if host_part.startswith("["):  # IPv6 в скобках: [::1]:443
            bracket_end = host_part.find("]")
            if bracket_end == -1:
                return None
            host = host_part[1:bracket_end]
            rest = host_part[bracket_end + 1:]
            port = rest[1:] if rest.startswith(":") else None
        elif ":" in host_part:
            host, port = host_part.rsplit(":", 1)
        else:
            host, port = host_part, None

        if not host or not port or not port.isdigit():
            return None

        return {
            "raw": vless_url,
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "name": name,
            "params": query,
        }
    except Exception:
        return None


def vless_host_display(info):
    return f"{info['host']}:{info['port']}" if info else ""


def vless_display_name(info):
    if not info:
        return "VLESS"
    return info["name"] if info["name"] else vless_host_display(info)


def vless_security(info):
    return info["params"].get("security", "none") if info else "none"


def vless_sni(info):
    p = info["params"]
    return p.get("sni") or p.get("host") or info["host"]


# ──────────────────────────────────────────────────────────────────────────
#  Xray outbound и реальный url-тест
# ──────────────────────────────────────────────────────────────────────────
def vless_to_outbound(info):
    """xray outbound из распарсенного vless. tcp/ws/grpc + tls/reality."""
    p = info["params"]
    network = p.get("type", "tcp")
    security = p.get("security", "none")

    user = {"id": info["uuid"], "encryption": p.get("encryption", "none")}
    if p.get("flow"):
        user["flow"] = p["flow"]

    stream = {"network": network, "security": security}

    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": p.get("sni", p.get("host", info["host"])),
            "fingerprint": p.get("fp", "chrome"),
            "allowInsecure": p.get("allowInsecure", "0") in ("1", "true"),
        }
        if p.get("alpn"):
            stream["tlsSettings"]["alpn"] = p["alpn"].split(",")
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
        }

    if network == "ws":
        stream["wsSettings"] = {
            "path": p.get("path", "/"),
            "headers": {"Host": p.get("host", info["host"])},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    elif network == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {"headers": {"Host": [p.get("host", info["host"])]}}}
        }

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": info["host"], "port": info["port"], "users": [user]}]
        },
        "streamSettings": stream,
    }


def url_test_vless(info, test_url=DEFAULT_TEST_URL, timeout=8):
    """Реальный url-тест через локальный xray (socks5). Задержка в мс или None."""
    if not XRAY_BIN:
        return None
    try:
        outbound = vless_to_outbound(info)
    except Exception:
        return None

    socks_port = free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound],
    }

    cfg_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            cfg_path = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)  # даём xray стартовать

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        start = time.time()
        r = requests.get(test_url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS)
        if r.status_code in (200, 204):
            return int((time.time() - start) * 1000)
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────
#  Загрузка источников
# ──────────────────────────────────────────────────────────────────────────
def fetch_lines(url):
    try:
        r = http_get(url)
        if r.status_code == 200:
            return r.text.splitlines()
    except Exception:
        pass
    return []


def load_all(sources):
    out = {}
    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {ex.submit(fetch_lines, u): u for u in sources}
        for fut in as_completed(futures):
            out[futures[fut]] = fut.result()
    return out


def load_vless_infos():
    """Скачивает, дедупит и парсит все VLESS-ключи. Возвращает list[info]."""
    seen = set()
    infos = []
    for lines in load_all(VLESS_SOURCES).values():
        for line in lines:
            line = line.strip()
            if line.startswith("vless://") and line not in seen:
                seen.add(line)
                info = parse_vless(line)
                if info:
                    infos.append(info)
    return infos


def run_stage(label, items, worker_fn, max_workers, report_every=20):
    """Общий раннер этапа с прогресс-баром.
    items — list ключей; worker_fn(key) -> ping|None.
    Возвращает set ключей, прошедших проверку."""
    ok = set()
    total = len(items)
    if total == 0:
        return ok
    bar = st.progress(0.0, text=f"{label}: 0 / {total}")
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fmap = {ex.submit(worker_fn, it): it for it in items}
        for fut in as_completed(fmap):
            done += 1
            if fut.result() is not None:
                ok.add(fmap[fut])
            if done % report_every == 0 or done == total:
                bar.progress(done / total,
                             text=f"{label}: {done} / {total} (прошло: {len(ok)})")
    bar.empty()
    return ok


def divider(alpha="0.05"):
    st.markdown(
        f"<div style='border-top:1px solid rgba(0,0,0,{alpha}); margin:2px 0;'></div>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════════════════
st.title("\U0001F510 Proxy Manager")
st.write("MTProto для Telegram и VLESS ключи из нескольких независимых источников.")

if not XRAY_BIN:
    st.caption(
        "\u2139\uFE0F xray не найден — каскад завершится на этапе TLS. "
        "Для url-теста положите бинарь `xray` рядом с приложением или в PATH."
    )

tab_mtproto, tab_vless = st.tabs(["\U0001F4E1 MTProto Proxies", "\U0001F511 VLESS Keys"])

# ─── Вкладка MTProto ──────────────────────────────────────────────────────
with tab_mtproto:
    st.subheader("MTProto Proxy Manager")
    st.write("Сбор данных из репозиториев с дедупликацией по server:port.")

    st.session_state.setdefault("working_proxies", [])

    if st.button("Обновить базу и проверить пинг", use_container_width=True, key="btn_mtproto"):
        with st.spinner("Опрашиваем источники и фильтруем дубликаты..."):
            seen_servers = set()
            proxies_list = []
            for lines in load_all(PROXY_SOURCES).values():
                for line in lines:
                    proxy = line.strip()
                    if not proxy or not (
                        proxy.startswith("tg://") or proxy.startswith("https://t.me/")
                    ):
                        continue
                    server, port = extract_server_port(proxy)
                    key = (server, port)
                    if server and port and key not in seen_servers:
                        seen_servers.add(key)
                        proxies_list.append((proxy, server, port))

            random.shuffle(proxies_list)
            subset = proxies_list[:MTPROTO_PREVIEW_LIMIT]

            found = []
            with ThreadPoolExecutor(max_workers=MAX_TCP_WORKERS) as ex:
                fut_map = {
                    ex.submit(check_tcp_ping, s, p): proxy for proxy, s, p in subset
                }
                for fut in as_completed(fut_map):
                    ping = fut.result()
                    if ping is not None:
                        found.append({"url": fut_map[fut], "ping": ping})

            found.sort(key=lambda x: x["ping"])
            st.session_state.working_proxies = found

    st.markdown("---")
    proxies = st.session_state.working_proxies
    if proxies:
        st.write(f"Найдено уникальных доступных прокси (TCP): {len(proxies)}")
        h1, h2, h3 = st.columns([1, 2, 5])
        h1.markdown("**Номер**")
        h2.markdown("**Пинг**")
        h3.markdown("**Действие**")
        divider("0.2")
        for idx, data in enumerate(proxies):
            tg_link = data["url"].replace("https://t.me/", "tg://")
            safe_link = html.escape(tg_link, quote=True)
            c1, c2, c3 = st.columns([1, 2, 5])
            c1.write(str(idx + 1))
            c2.markdown(
                f"<span style='color:#2a9d8f;font-weight:bold;'>{data['ping']} мс</span>",
                unsafe_allow_html=True,
            )
            c3.markdown(
                f"<a href=\"{safe_link}\" style='display:inline-block;background:#3390ec;"
                f"color:white;padding:5px 10px;border-radius:6px;text-decoration:none;"
                f"font-size:14px;font-weight:bold;'>Подключить в Telegram</a>",
                unsafe_allow_html=True,
            )
            divider()
    else:
        st.info("Таблица пуста. Нажмите кнопку выше, чтобы запустить сканирование.")

# ─── Вкладка VLESS ────────────────────────────────────────────────────────
with tab_vless:
    st.subheader("VLESS Keys")
    st.write("Ключи собраны из нескольких репозиториев.")

    st.markdown("### \U0001F3AF Умный подбор (каскад TCP → TLS → Xray)")
    st.caption(
        "База сначала фильтруется быстрыми проверками, и только выжившие ключи "
        "проверяются через Xray — это многократно ускоряет обработку больших списков."
    )

    enable_xray = False
    test_url = DEFAULT_TEST_URL
    if XRAY_BIN:
        enable_xray = st.checkbox(
            "Этап 3: финальная проверка через Xray (реальная работоспособность)",
            value=True, key="vless_enable_xray",
        )
        if enable_xray:
            test_url = st.text_input(
                "URL для теста (должен вернуть 200/204):",
                value=DEFAULT_TEST_URL, key="vless_test_url",
            )

    col_input, col_btn = st.columns([2, 3])
    with col_input:
        wanted = st.number_input(
            "Нужно рабочих ключей:", min_value=1, max_value=500, value=50, step=10,
            key="vless_wanted",
        )
    with col_btn:
        st.write("")
        st.write("")
        run_smart = st.button(
            f"\U0001F680 Найти {int(wanted)} рабочих ключей",
            use_container_width=True, key="btn_vless_smart",
        )

    st.session_state.setdefault("smart_vless_keys", [])
    st.session_state.setdefault("smart_vless_done", False)
    st.session_state.setdefault("smart_vless_label", "")

    if run_smart:
        target = int(wanted)
        status_text = st.empty()

        # Загрузка + парсинг + дедуп
        with st.spinner("Загружаем и парсим базу ключей..."):
            all_infos = load_vless_infos()
        total = len(all_infos)

        if total == 0:
            status_text.error("\u274C Не удалось загрузить ключи.")
        else:
            # ЭТАП 1: TCP по уникальным endpoint'ам
            endpoints = sorted({(i["host"], i["port"]) for i in all_infos})
            st.write(
                f"\U0001F4E6 Загружено **{total}** ключей "
                f"(**{len(endpoints)}** уникальных серверов)."
            )
            tcp_ok = run_stage(
                "Этап 1/3 — TCP", endpoints,
                lambda hp: check_tcp_ping(hp[0], hp[1], 1.0),
                MAX_TCP_WORKERS, report_every=25,
            )
            after_tcp = [i for i in all_infos if (i["host"], i["port"]) in tcp_ok]
            st.write(f"\u2705 После TCP: **{len(after_tcp)}** ключей на **{len(tcp_ok)}** серверах.")

            # ЭТАП 2: TLS handshake (только tls/reality), по уникальным (host,port,sni)
            need_tls = [i for i in after_tcp if vless_security(i) in ("tls", "reality")]
            passthrough = [i for i in after_tcp if vless_security(i) not in ("tls", "reality")]
            tls_targets = sorted({(i["host"], i["port"], vless_sni(i)) for i in need_tls})
            tls_ok = run_stage(
                "Этап 2/3 — TLS", tls_targets,
                lambda t: check_tls_handshake(t[0], t[1], t[2], 2.5),
                MAX_TLS_WORKERS, report_every=20,
            )
            after_tls = passthrough + [
                i for i in need_tls if (i["host"], i["port"], vless_sni(i)) in tls_ok
            ]
            st.write(
                f"\u2705 После TLS: **{len(after_tls)}** ключей "
                f"(без TLS пропущено напрямую: {len(passthrough)})."
            )
            random.shuffle(after_tls)

            # ЭТАП 3: Xray url-тест (с ранней остановкой по target)
            found_keys = []
            if enable_xray and XRAY_BIN:
                p3 = st.progress(0.0, text=f"Этап 3/3 — Xray: 0 / {target}")
                checked = 0
                with ThreadPoolExecutor(max_workers=MAX_XRAY_WORKERS) as ex:
                    futures = [ex.submit(url_test_vless, i, test_url) for i in after_tls]
                    fut_info = dict(zip(futures, after_tls))
                    for fut in as_completed(futures):
                        checked += 1
                        ping = fut.result()
                        if ping is not None:
                            info = fut_info[fut]
                            found_keys.append({"info": info, "key": info["raw"], "ping": ping})
                        if checked % 3 == 0 or found_keys:
                            p3.progress(
                                min(len(found_keys) / target, 1.0),
                                text=f"Этап 3/3 — Xray: найдено {len(found_keys)} / {target} "
                                f"(проверено {checked} / {len(after_tls)})",
                            )
                        if len(found_keys) >= target:
                            for f in futures:
                                f.cancel()
                            break
                p3.empty()
                check_label = "URL-тест (TCP + TLS + Xray)"
            else:
                # Без xray: рабочими считаем прошедших TCP+TLS, пинг берём по TCP
                for info in after_tls:
                    ping = check_tcp_ping(info["host"], info["port"], 1.0) or 0
                    found_keys.append({"info": info, "key": info["raw"], "ping": ping})
                    if len(found_keys) >= target:
                        break
                check_label = "TCP + TLS"

            found_keys.sort(key=lambda x: x["ping"])
            found_keys = found_keys[:target]
            st.session_state.smart_vless_keys = found_keys
            st.session_state.smart_vless_done = True
            st.session_state.smart_vless_label = check_label

            if not found_keys:
                status_text.error("\u274C Не найдено ни одного рабочего ключа.")
            elif len(found_keys) < target:
                status_text.warning(f"\u26A0\uFE0F Найдено {len(found_keys)} из {target} запрошенных.")
            else:
                status_text.success(f"\U0001F389 Готово! Найдено {len(found_keys)} ключей.")

    if st.session_state.smart_vless_done and st.session_state.smart_vless_keys:
        smart_keys = st.session_state.smart_vless_keys
        label = st.session_state.get("smart_vless_label", "")
        st.markdown(f"**Ключей:** {len(smart_keys)} | Проверка: {label} | сортировка по пингу ⬆️")
        s1, s2, s3 = st.columns([1, 4, 2])
        s1.markdown("**#**")
        s2.markdown("**Хост / Имя**")
        s3.markdown("**Пинг**")
        divider("0.2")
        for si, item in enumerate(smart_keys[:VLESS_TABLE_LIMIT]):
            info = item["info"]
            display = html.escape(vless_display_name(info))
            title = html.escape(item["key"], quote=True)
            c1, c2, c3 = st.columns([1, 4, 2])
            c1.write(str(si + 1))
            c2.markdown(
                f"<span title=\"{title}\" style='font-size:12px;word-break:break-all;'>{display}</span>",
                unsafe_allow_html=True,
            )
            c3.markdown(
                f"<span style='color:#2a9d8f;font-weight:bold;'>{item['ping']} мс</span>",
                unsafe_allow_html=True,
            )
            divider()
        if len(smart_keys) > VLESS_TABLE_LIMIT:
            st.info(f"Показаны первые {VLESS_TABLE_LIMIT} из {len(smart_keys)}.")

        smart_bytes = "\n".join(item["key"] for item in smart_keys).encode("utf-8")
        st.download_button(
            label=f"\u2B07\uFE0F Скачать {len(smart_keys)} ключей (vless_working.txt)",
            data=smart_bytes, file_name="vless_working.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_smart_vless",
        )

    st.markdown("---")
    st.markdown("### \U0001F4CB Все ключи без проверки")
    st.info("\U0001F4A1 Скопируйте ключ и импортируйте в v2rayN, Hiddify, Nekoray, Streisand и т.д.")

    st.session_state.setdefault("vless_keys", [])
    st.session_state.setdefault("vless_loaded", False)

    if st.button("\U0001F504 Загрузить / Обновить VLESS ключи", use_container_width=True, key="btn_vless"):
        with st.spinner("Загружаем ключи из источников..."):
            unique_vless = set()
            stats = {}
            for url, lines in load_all(VLESS_SOURCES).items():
                name = url.split("/")[-1]
                count = 0
                for line in lines:
                    line = line.strip()
                    if line.startswith("vless://"):
                        unique_vless.add(line)
                        count += 1
                stats[name] = count
            st.session_state.vless_keys = sorted(unique_vless)
            st.session_state.vless_loaded = True
            st.success(
                "\u2705 Загружено: "
                + " | ".join(f"**{k}**: {v}" for k, v in stats.items())
            )

    st.markdown("---")
    if st.session_state.vless_keys:
        keys = st.session_state.vless_keys
        st.write(f"Найдено уникальных VLESS ключей: **{len(keys)}**")

        search = st.text_input(
            "\U0001F50D Фильтр по тексту (SNI, хост, имя...)",
            key="vless_search", placeholder="например: yandex.ru",
        )
        if search:
            keys = [k for k in keys if search.lower() in k.lower()]
            st.write(f"Показано после фильтра: **{len(keys)}**")

        h1, h2, h3 = st.columns([1, 4, 2])
        h1.markdown("**#**")
        h2.markdown("**Имя / Хост**")
        h3.markdown("**Копировать**")
        divider("0.2")

        total_pages = max(1, (len(keys) + PAGE_SIZE - 1) // PAGE_SIZE)
        st.session_state.setdefault("vless_page", 0)
        if search != st.session_state.get("vless_last_search", ""):
            st.session_state.vless_page = 0
            st.session_state.vless_last_search = search
        page = min(st.session_state.vless_page, total_pages - 1)
        page_keys = keys[page * PAGE_SIZE: (page + 1) * PAGE_SIZE]

        for idx, key in enumerate(page_keys):
            global_idx = page * PAGE_SIZE + idx + 1
            info = parse_vless(key)
            display = html.escape(vless_display_name(info))
            title = html.escape(key, quote=True)
            c1, c2, c3 = st.columns([1, 4, 2])
            c1.write(str(global_idx))
            c2.markdown(
                f"<span title=\"{title}\" style='font-size:13px;word-break:break-all;'>{display}</span>",
                unsafe_allow_html=True,
            )
            c3.code(key[:30] + "…" if len(key) > 30 else key, language=None)
            divider()

        if total_pages > 1:
            st.markdown("---")
            n1, n2, n3 = st.columns([1, 2, 1])
            with n1:
                if st.button("← Назад", disabled=(page == 0), key="vless_prev"):
                    st.session_state.vless_page = page - 1
                    st.rerun()
            with n2:
                st.markdown(
                    f"<div style='text-align:center;padding-top:6px;'>Страница {page + 1} из {total_pages}</div>",
                    unsafe_allow_html=True,
                )
            with n3:
                if st.button("Вперёд →", disabled=(page >= total_pages - 1), key="vless_next"):
                    st.session_state.vless_page = page + 1
                    st.rerun()

        st.markdown("---")
        all_keys_bytes = "\n".join(st.session_state.vless_keys).encode("utf-8")
        st.download_button(
            label="\u2B07\uFE0F Скачать все ключи (vless_keys.txt)",
            data=all_keys_bytes, file_name="vless_keys.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_vless",
        )
        st.text_area(
            label="Все уникальные VLESS ключи",
            value="\n".join(st.session_state.vless_keys),
            height=200, key="vless_all_text", label_visibility="collapsed",
        )
    elif st.session_state.vless_loaded:
        st.warning("Не удалось загрузить VLESS ключи. Проверьте доступность источников.")
    else:
        st.info("Нажмите кнопку выше, чтобы загрузить VLESS ключи.")
