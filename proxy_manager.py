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
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
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


def parse_vless_text(text):
    """Парсит сырой текст: оставляет vless://, дедупит, возвращает list[info]."""
    seen = set()
    infos = []
    for line in text.splitlines():
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


def inject_theme():
    """Тёмная glass-тема в стиле лаунчера: без градиентов, с тёплым accent."""
    st.markdown(
        """
        <style>
        :root {
            --bg: #0a0a0f;
            --bg-soft: #0d0d12;
            --card: #14141a;
            --card-hover: #1a1a22;
            --card-border: #1e1e28;
            --glass: #17171d;
            --glass-border: #2d2c35;
            --accent: #e8a87c;
            --accent-hover: #d4956a;
            --accent-dim: #2a1f18;
            --text: #e8e8ed;
            --text-secondary: #9a94a6;
            --text-muted: #5f5a68;
            --success: #4ade80;
            --warning: #fbbf24;
            --danger: #f87171;
        }

        html, body, [data-testid="stAppViewContainer"] {
            background: var(--bg) !important;
            color: var(--text) !important;
        }
        [data-testid="stAppViewContainer"]::before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background:
                rgba(232,168,124,.018);
            box-shadow:
                inset 0 0 180px rgba(0,0,0,.58),
                inset 0 0 0 1px rgba(255,255,255,.018);
        }
        [data-testid="stHeader"] { background: transparent !important; }
        [data-testid="stToolbar"] { color: var(--text-secondary); }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 980px;
        }

        .pm-shell {
            background: rgba(20,20,26,.92);
            border: 1px solid rgba(255,255,255,.09);
            border-radius: 24px;
            padding: 28px 30px;
            margin-bottom: 22px;
            box-shadow: 0 18px 48px rgba(0,0,0,.48);
            position: relative;
            overflow: hidden;
        }
        .pm-shell::after {
            content:"";
            position:absolute;
            right:-72px;
            top:-72px;
            width:190px;
            height:190px;
            border-radius:50%;
            background: rgba(232,168,124,.075);
            border: 1px solid rgba(232,168,124,.12);
        }
        .pm-badge {
            display:inline-flex;
            align-items:center;
            gap:8px;
            background: var(--accent-dim);
            color: var(--accent);
            border: 1px solid rgba(232,168,124,.32);
            border-radius: 10px;
            padding: 9px 13px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: .08em;
            text-transform: uppercase;
        }
        .pm-hero h1 {
            margin: 16px 0 6px;
            color: var(--text);
            font-size: 42px;
            line-height: 1.04;
            font-weight: 850;
            letter-spacing: -1.1px;
        }
        .pm-hero p {
            max-width: 690px;
            margin: 0;
            color: var(--text-secondary);
            font-size: 15px;
            line-height: 1.55;
        }
        .pm-hero-meta {
            display:flex;
            flex-wrap:wrap;
            gap:10px;
            margin-top:18px;
        }
        .pm-mini-card {
            background: rgba(255,255,255,.025);
            border: 1px solid rgba(255,255,255,.07);
            border-radius: 14px;
            padding: 10px 13px;
            color: var(--text-secondary);
            font-size: 12px;
        }
        .pm-mini-card b { color: var(--text); font-weight: 750; }

        h1, h2, h3, h4, h5, h6, p, label, span, div {
            color: inherit;
        }
        .stMarkdown, .stText, [data-testid="stMarkdownContainer"] {
            color: var(--text) !important;
        }
        [data-testid="stCaptionContainer"] {
            color: var(--text-muted) !important;
        }
        .stAlert {
            background: rgba(255,255,255,.035) !important;
            border: 1px solid rgba(255,255,255,.08) !important;
            border-radius: 14px !important;
            color: var(--text-secondary) !important;
        }

        .stButton > button, .stDownloadButton > button {
            min-height: 44px;
            border-radius: 14px !important;
            border: 1px solid rgba(232,168,124,.42) !important;
            background: var(--accent) !important;
            color: #17110d !important;
            font-weight: 800 !important;
            letter-spacing: .01em;
            box-shadow: 0 12px 28px rgba(0,0,0,.28);
            transition: transform .12s ease, background-color .15s ease, border-color .15s ease, box-shadow .15s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            background: var(--accent-hover) !important;
            border-color: rgba(232,168,124,.68) !important;
            transform: translateY(-1px);
            box-shadow: 0 16px 34px rgba(0,0,0,.35);
        }
        .stButton > button:disabled {
            background: rgba(255,255,255,.08) !important;
            color: var(--text-muted) !important;
            border-color: rgba(255,255,255,.08) !important;
            box-shadow: none;
            transform: none;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
            background: rgba(13,13,18,.72);
            border: 1px solid rgba(255,255,255,.07);
            border-radius: 16px;
            padding: 6px;
            box-shadow: 0 12px 32px rgba(0,0,0,.22);
        }
        .stTabs [data-baseweb="tab"] {
            border-radius: 12px;
            padding: 10px 18px;
            color: var(--text-secondary);
            font-weight: 750;
        }
        .stTabs [aria-selected="true"] {
            background: var(--accent-dim) !important;
            color: var(--accent) !important;
            border: 1px solid rgba(232,168,124,.25);
        }

        div[data-baseweb="input"] > div,
        .stNumberInput input,
        .stTextInput input,
        textarea {
            background: var(--glass) !important;
            color: var(--text) !important;
            border: 1px solid var(--glass-border) !important;
            border-radius: 14px !important;
        }
        .stTextInput input:focus, .stNumberInput input:focus, textarea:focus {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 1px rgba(232,168,124,.28) !important;
        }

        [data-testid="stProgress"] > div { background: rgba(255,255,255,.06) !important; }
        [data-testid="stProgress"] > div > div > div > div {
            background: var(--accent) !important;
        }

        .pm-row {
            display:flex;
            align-items:center;
            gap:12px;
            padding:12px 14px;
            margin:8px 0;
            border-radius:16px;
            background: var(--card);
            border:1px solid var(--card-border);
            box-shadow: 0 10px 26px rgba(0,0,0,.20);
            transition: background-color .14s ease, border-color .14s ease, transform .12s ease;
        }
        .pm-row:hover {
            background: var(--card-hover);
            border-color: rgba(232,168,124,.28);
            transform: translateY(-1px);
        }
        .pm-idx {
            display:inline-flex;
            align-items:center;
            justify-content:center;
            min-width:32px;
            height:32px;
            border-radius:10px;
            background: rgba(255,255,255,.035);
            border: 1px solid rgba(255,255,255,.06);
            color: var(--text-muted);
            font-weight:800;
            font-size:12px;
        }
        .pm-name {
            flex:1;
            color: var(--text-secondary);
            font-size:13px;
            line-height:1.35;
            word-break:break-all;
        }
        .ping-badge {
            font-weight:800;
            font-size:12px;
            padding:5px 11px;
            border-radius:999px;
            background: rgba(74,222,128,.11);
            border: 1px solid rgba(74,222,128,.24);
            color: var(--success);
            white-space:nowrap;
        }
        .ping-badge.slow {
            background: rgba(251,191,36,.10);
            border-color: rgba(251,191,36,.24);
            color: var(--warning);
        }
        .tg-btn {
            display:inline-flex;
            align-items:center;
            justify-content:center;
            background: var(--accent-dim);
            color: var(--accent) !important;
            border: 1px solid rgba(232,168,124,.38);
            padding:8px 14px;
            border-radius:12px;
            text-decoration:none;
            font-size:12px;
            font-weight:800;
            white-space:nowrap;
            transition: background-color .15s ease, border-color .15s ease;
        }
        .tg-btn:hover {
            background: rgba(232,168,124,.16);
            border-color: rgba(232,168,124,.60);
        }
        .pm-stat {
            display:inline-flex;
            align-items:center;
            gap:6px;
            padding:8px 13px;
            margin:4px 7px 10px 0;
            border-radius:12px;
            background: rgba(232,168,124,.08);
            border:1px solid rgba(232,168,124,.22);
            color: var(--text-secondary);
            font-size:12px;
            font-weight:650;
        }
        .pm-stat b { color: var(--accent); }
        code, pre {
            background: #101016 !important;
            border: 1px solid rgba(255,255,255,.07) !important;
            border-radius: 12px !important;
            color: var(--text-secondary) !important;
        }
        hr { border-color: rgba(255,255,255,.07) !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def ping_badge(ms):
    """HTML-бейдж пинга: зелёный для быстрых, янтарный для медленных."""
    cls = "ping-badge" if (ms or 0) < 300 else "ping-badge slow"
    return f"<span class='{cls}'>{ms} мс</span>"


# ══════════════════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════════════════
inject_theme()
st.markdown(
    """
    <section class='pm-shell pm-hero'>
        <div class='pm-badge'>PROXY MANAGER // DARK UI</div>
        <h1>Proxy Manager</h1>
        <p>Сбор MTProto и VLESS из независимых источников. Быстрая дедупликация, TCP/TLS-фильтр и финальная Xray-проверка для рабочих ключей.</p>
        <div class='pm-hero-meta'>
            <div class='pm-mini-card'><b>TCP</b> быстрый отсев</div>
            <div class='pm-mini-card'><b>TLS</b> handshake</div>
            <div class='pm-mini-card'><b>Xray</b> url-test</div>
        </div>
    </section>
    """,
    unsafe_allow_html=True,
)

if not XRAY_BIN:
    st.caption(
        "\u2139\uFE0F xray не найден — каскад завершится на этапе TLS. "
        "Для url-теста положите бинарь `xray` рядом с приложением или в PATH."
    )

tab_mtproto, tab_vless = st.tabs(["MTProto Proxies", "VLESS Keys"])

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
        st.markdown(
            f"<div class='pm-stat'>Доступных прокси (TCP): <b>{len(proxies)}</b></div>",
            unsafe_allow_html=True,
        )
        for idx, data in enumerate(proxies):
            tg_link = data["url"].replace("https://t.me/", "tg://")
            safe_link = html.escape(tg_link, quote=True)
            server, port = extract_server_port(data["url"])
            name = html.escape(f"{server}:{port}" if server else "MTProto прокси")
            st.markdown(
                f"<div class='pm-row'>"
                f"<span class='pm-idx'>{idx + 1}</span>"
                f"{ping_badge(data['ping'])}"
                f"<span class='pm-name'>{name}</span>"
                f"<a class='tg-btn' href=\"{safe_link}\">Подключить</a>"
                f"</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("Таблица пуста. Нажмите кнопку выше, чтобы запустить сканирование.")

# ─── Вкладка VLESS ────────────────────────────────────────────────────────
with tab_vless:
    st.subheader("VLESS Keys")
    st.write("Ключи собраны из нескольких репозиториев.")

    st.markdown("### Умный подбор (каскад TCP -> TLS -> Xray)")
    st.caption(
        "База сначала фильтруется быстрыми проверками, и только выжившие ключи "
        "проверяются через Xray — это многократно ускоряет обработку больших списков."
    )

    own_keys = st.checkbox(
        "Проверить свои ключи (из .txt файла)",
        key="vless_own_enable",
    )

    own_path = ""
    own_uploaded = None
    if own_keys:
        own_path = st.text_input(
            "Путь к .txt с VLESS ключами",
            placeholder="C:\\keys\\my_vless.txt", key="vless_own_path",
        )
        own_uploaded = st.file_uploader(
            "...или загрузите .txt файл", type=["txt"], key="vless_own_file",
        )
        st.caption(
            "Приоритет у загруженного файла. Проверяются ВСЕ ключи из файла "
            "(без ограничения по количеству)."
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

    if own_keys:
        wanted = 0
        run_smart = st.button(
            "Проверить мои ключи",
            use_container_width=True, key="btn_vless_smart",
        )
    else:
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
                f"Найти {int(wanted)} рабочих ключей",
                use_container_width=True, key="btn_vless_smart",
            )

    st.session_state.setdefault("smart_vless_keys", [])
    st.session_state.setdefault("smart_vless_done", False)
    st.session_state.setdefault("smart_vless_label", "")

    if run_smart:
        status_text = st.empty()

        # Источник ключей: свой .txt файл или встроенные источники
        all_infos = []
        input_error = False
        if own_keys:
            try:
                if own_uploaded is not None:
                    raw_text = own_uploaded.getvalue().decode("utf-8", "ignore")
                    all_infos = parse_vless_text(raw_text)
                elif own_path.strip():
                    with open(own_path.strip(), encoding="utf-8", errors="ignore") as fh:
                        all_infos = parse_vless_text(fh.read())
                else:
                    input_error = True
                    status_text.warning("Укажите путь к .txt файлу или загрузите файл.")
            except FileNotFoundError:
                input_error = True
                status_text.error("Файл не найден. Проверьте путь.")
            except OSError as err:
                input_error = True
                status_text.error(f"Не удалось прочитать файл: {err}")
        else:
            with st.spinner("Загружаем и парсим базу ключей..."):
                all_infos = load_vless_infos()

        total = len(all_infos)
        # Свои ключи проверяем целиком, без лимита N
        target = total if own_keys else int(wanted)

        if input_error:
            pass
        elif total == 0:
            status_text.error(
                "В файле не найдено ключей vless://."
                if own_keys else "Не удалось загрузить ключи."
            )
        else:
            # ЭТАП 1: TCP по уникальным endpoint'ам
            endpoints = sorted({(i["host"], i["port"]) for i in all_infos})
            st.write(
                f"Загружено **{total}** ключей "
                f"(**{len(endpoints)}** уникальных серверов)."
            )
            tcp_ok = run_stage(
                "Этап 1/3 — TCP", endpoints,
                lambda hp: check_tcp_ping(hp[0], hp[1], 1.0),
                MAX_TCP_WORKERS, report_every=25,
            )
            after_tcp = [i for i in all_infos if (i["host"], i["port"]) in tcp_ok]
            st.write(f"После TCP: **{len(after_tcp)}** ключей на **{len(tcp_ok)}** серверах.")

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
                f"После TLS: **{len(after_tls)}** ключей "
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
                status_text.error("Не найдено ни одного рабочего ключа.")
            elif own_keys:
                status_text.success(
                    f"Готово! Рабочих: {len(found_keys)} из {total} проверенных."
                )
            elif len(found_keys) < target:
                status_text.warning(f"Найдено {len(found_keys)} из {target} запрошенных.")
            else:
                status_text.success(f"Готово! Найдено {len(found_keys)} ключей.")

    if st.session_state.smart_vless_done and st.session_state.smart_vless_keys:
        smart_keys = st.session_state.smart_vless_keys
        label = st.session_state.get("smart_vless_label", "")
        st.markdown(
            f"<div class='pm-stat'>Рабочих ключей: <b>{len(smart_keys)}</b></div>"
            f"<div class='pm-stat'>Проверка: <b>{html.escape(label)}</b></div>"
            f"<div class='pm-stat'>сортировка по пингу</div>",
            unsafe_allow_html=True,
        )
        for si, item in enumerate(smart_keys[:VLESS_TABLE_LIMIT]):
            info = item["info"]
            display = html.escape(vless_display_name(info))
            title = html.escape(item["key"], quote=True)
            st.markdown(
                f"<div class='pm-row' title=\"{title}\">"
                f"<span class='pm-idx'>{si + 1}</span>"
                f"{ping_badge(item['ping'])}"
                f"<span class='pm-name'>{display}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        if len(smart_keys) > VLESS_TABLE_LIMIT:
            st.info(f"Показаны первые {VLESS_TABLE_LIMIT} из {len(smart_keys)}.")

        smart_bytes = "\n".join(item["key"] for item in smart_keys).encode("utf-8")
        st.download_button(
            label=f"Скачать {len(smart_keys)} ключей (vless_working.txt)",
            data=smart_bytes, file_name="vless_working.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_smart_vless",
        )

    st.markdown("---")
    st.markdown("### Все ключи без проверки")
    st.info("Скопируйте ключ и импортируйте в v2rayN, Hiddify, Nekoray, Streisand и т.д.")

    st.session_state.setdefault("vless_keys", [])
    st.session_state.setdefault("vless_loaded", False)

    if st.button("Загрузить / Обновить VLESS ключи", use_container_width=True, key="btn_vless"):
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
                "Загружено: "
                + " | ".join(f"**{k}**: {v}" for k, v in stats.items())
            )

    st.markdown("---")
    if st.session_state.vless_keys:
        keys = st.session_state.vless_keys
        st.write(f"Найдено уникальных VLESS ключей: **{len(keys)}**")

        search = st.text_input(
            "Фильтр по тексту (SNI, хост, имя...)",
            key="vless_search", placeholder="например: yandex.ru",
        )
        if search:
            keys = [k for k in keys if search.lower() in k.lower()]
            st.write(f"Показано после фильтра: **{len(keys)}**")

        st.caption("Имя / хост слева, справа — ключ с кнопкой копирования")

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
            label="Скачать все ключи (vless_keys.txt)",
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
