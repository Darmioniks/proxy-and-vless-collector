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
import base64
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

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

HISTORY_FILE = os.path.join(_here, "history.json")
HISTORY_LIMIT = 300
WORKING_DB_FILE = os.path.join(_here, "working_vless.json")
WORKING_DB_LIMIT = 1000
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"


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


def speed_test_vless(info, speed_url=DEFAULT_SPEED_URL, timeout=12):
    """Мини speed-test через xray. Возвращает Mbps или None."""
    if not XRAY_BIN:
        return None
    try:
        outbound = vless_to_outbound(info)
    except Exception:
        return None

    socks_port = free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
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
        time.sleep(0.8)
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        start = time.time()
        r = requests.get(speed_url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS, stream=True)
        if r.status_code not in (200, 204):
            return None
        size = 0
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                size += len(chunk)
        elapsed = max(time.time() - start, 0.001)
        if size <= 0:
            return None
        return round((size * 8) / elapsed / 1_000_000, 2)
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


def make_subscription(keys):
    """base64-подписка из списка vless-ключей (импорт одной ссылкой)."""
    blob = "\n".join(keys).strip()
    return base64.b64encode(blob.encode("utf-8")).decode("ascii")


def load_history():
    """Читает историю замеров из history.json. Возвращает list[record]."""
    try:
        with open(HISTORY_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def append_history(counts):
    """Добавляет запись {ts, counts} в историю и обрезает до HISTORY_LIMIT."""
    hist = load_history()
    hist.append({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "counts": {k: int(v) for k, v in counts.items()},
    })
    hist = hist[-HISTORY_LIMIT:]
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as fh:
            json.dump(hist, fh, ensure_ascii=False)
    except Exception:
        pass
    return hist


def render_bar_chart(items):
    """items: list[(label, value)] -> красивые пастельные столбики (HTML/CSS)."""
    items = [(lbl, float(val)) for lbl, val in items]
    if not items:
        st.info("Нет данных для графика.")
        return
    max_val = max((v for _, v in items), default=0) or 1
    cols = []
    for label, value in items:
        pct = max(4, round(value / max_val * 100))
        lbl = html.escape(str(label))
        val_int = int(round(value))
        cols.append(
            f"<div class='pm-bar-col'>"
            f"<div class='pm-bar-val'>{val_int}</div>"
            f"<div class='pm-bar' style='height:{pct}%' title='{lbl}: {val_int}'></div>"
            f"<div class='pm-bar-lbl'>{lbl}</div>"
            f"</div>"
        )
    st.markdown(f"<div class='pm-chart'>{''.join(cols)}</div>", unsafe_allow_html=True)


def load_working_db():
    """Рабочая база: последние реально найденные ключи с метриками."""
    try:
        with open(WORKING_DB_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_working_db(items):
    """Сохраняет базу рабочих ключей, дедуп по raw, лучшие/свежие сверху."""
    merged = {}
    for item in items:
        key = item.get("key") or item.get("raw")
        if not key:
            continue
        merged[key] = item
    out = sorted(
        merged.values(),
        key=lambda x: (int(x.get("score", 0)), str(x.get("last_checked", ""))),
        reverse=True,
    )[:WORKING_DB_LIMIT]
    try:
        with open(WORKING_DB_FILE, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return out


def upsert_working_db(found_items):
    old = load_working_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    by_key = {x.get("key"): x for x in old if x.get("key")}
    for item in found_items:
        info = item.get("info") or parse_vless(item.get("key", ""))
        if not info:
            continue
        meta = vless_meta(info)
        rec = {
            "key": item["key"],
            "name": vless_display_name(info),
            "host": info["host"],
            "port": info["port"],
            "security": meta["security"],
            "network": meta["network"],
            "sni": meta["sni"],
            "ping": int(item.get("ping") or 0),
            "speed": item.get("speed"),
            "score": vless_score(info, item.get("ping"), item.get("speed")),
            "last_checked": now,
        }
        by_key[item["key"]] = rec
    return save_working_db(list(by_key.values()))


def vless_meta(info):
    p = info.get("params", {}) if info else {}
    return {
        "security": p.get("security", "none"),
        "network": p.get("type", "tcp"),
        "sni": p.get("sni") or p.get("host") or "",
        "flow": p.get("flow", ""),
        "fp": p.get("fp", ""),
    }


def vless_score(info, ping=None, speed=None):
    """Простая оценка качества 0..100: ping + скорость + тип конфига."""
    meta = vless_meta(info)
    score = 50
    if ping is not None:
        if ping <= 120:
            score += 25
        elif ping <= 250:
            score += 18
        elif ping <= 500:
            score += 10
        else:
            score += 3
    if speed is not None:
        if speed >= 30:
            score += 20
        elif speed >= 10:
            score += 14
        elif speed >= 3:
            score += 8
        else:
            score += 2
    if meta["security"] == "reality":
        score += 5
    if meta["sni"]:
        score += 3
    if meta["flow"]:
        score += 2
    return max(0, min(100, int(score)))


def score_label(score):
    if score >= 90:
        return "Отличный"
    if score >= 75:
        return "Хороший"
    if score >= 60:
        return "Средний"
    return "Слабый"


def filter_vless_infos(infos, only_reality=False, only_tls=False, only_tcp=False,
                       exclude_ws=False, require_sni=False):
    out = []
    for info in infos:
        meta = vless_meta(info)
        if only_reality and meta["security"] != "reality":
            continue
        if only_tls and meta["security"] != "tls":
            continue
        if only_tcp and meta["network"] != "tcp":
            continue
        if exclude_ws and meta["network"] == "ws":
            continue
        if require_sni and not meta["sni"]:
            continue
        out.append(info)
    return out


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


def inject_theme(dark=False):
    """Светлая пастельно-оранжевая тема: скользящий индикатор вкладок и плавные экспандеры."""
    st.markdown(
        """
        <style>
        :root {
            --bg: #fff7f0;
            --bg-soft: #fffdfb;
            --card: #ffffff;
            --card-2: #fff3e8;
            --card-hover: #fff1e3;
            --border: #f4ddc8;
            --border-strong: #eccbaa;
            --accent: #f0a868;
            --accent-strong: #e8915f;
            --accent-soft: #fde7d2;
            --accent-tint: #fff1e3;
            --text: #4a3b30;
            --text-secondary: #8a7867;
            --text-muted: #b5a292;
            --success: #6cbf8b;
            --success-soft: #e3f3ea;
            --success-bd: #c8e6d5;
            --warning: #e0a64b;
            --warning-soft: #fbeed2;
            --warning-bd: #f0dca8;
            --danger: #e07a5f;
            --shadow: 0 14px 36px rgba(224,150,80,.14);
            --shadow-sm: 0 6px 16px rgba(224,150,80,.10);
            --hero-glow: #ffe9d4;
            --code-bg: #fffaf4;
        }
        [data-theme="dark"] {
            --bg: #0f0d12;
            --bg-soft: #16131a;
            --card: #1a161f;
            --card-2: #211c28;
            --card-hover: #2a252f;
            --border: #2c2533;
            --border-strong: #3a3142;
            --accent: #f0a868;
            --accent-strong: #f6bd84;
            --accent-soft: #3a2a1d;
            --accent-tint: #241a14;
            --text: #f0e7df;
            --text-secondary: #b6a695;
            --text-muted: #7c6d60;
            --success: #7fd6a1;
            --success-soft: #16271d;
            --success-bd: #244a33;
            --warning: #f0c061;
            --warning-soft: #2a2113;
            --warning-bd: #473918;
            --danger: #f87171;
            --shadow: 0 18px 44px rgba(0,0,0,.5);
            --shadow-sm: 0 8px 20px rgba(0,0,0,.4);
            --hero-glow: #2a1d12;
            --code-bg: #120f16;
        }

        @keyframes pmFadeUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        @keyframes pmFadeIn { from { opacity:0; } to { opacity:1; } }

        html, body, [data-testid="stAppViewContainer"] {
            background: var(--bg) !important;
            color: var(--text) !important;
        }
        [data-testid="stApp"], [data-testid="stAppViewContainer"] {
            background:
                radial-gradient(1200px 480px at 50% -120px, var(--hero-glow) 0%, rgba(255,233,212,0) 70%),
                radial-gradient(540px 540px at 6% 12%, rgba(240,168,104,0.30) 0%, rgba(240,168,104,0) 68%),
                radial-gradient(560px 560px at 97% 22%, rgba(224,138,138,0.24) 0%, rgba(224,138,138,0) 68%),
                radial-gradient(680px 680px at 94% 95%, rgba(240,168,104,0.28) 0%, rgba(240,168,104,0) 70%),
                radial-gradient(520px 520px at 2% 92%, rgba(108,191,139,0.20) 0%, rgba(108,191,139,0) 68%),
                var(--bg) !important;
            background-repeat: no-repeat, no-repeat, no-repeat, no-repeat, no-repeat !important;
        }
        [data-testid="stHeader"] { background: transparent !important; }
        [data-testid="stToolbar"] { color: var(--text-secondary); }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 880px;
        }

        .pm-shell {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 28px 30px;
            margin-bottom: 22px;
            box-shadow: var(--shadow);
            position: relative;
            overflow: hidden;
            animation: pmFadeUp .5s ease both;
        }
        .pm-shell::after {
            content:"";
            position:absolute;
            right:-72px;
            top:-72px;
            width:190px;
            height:190px;
            border-radius:50%;
            background: var(--accent-tint);
            border: 1px solid var(--accent-soft);
        }
        .pm-badge {
            display:inline-flex;
            align-items:center;
            gap:8px;
            background: var(--accent-tint);
            color: var(--accent-strong);
            border: 1px solid var(--accent-soft);
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
        /* theme toggle button */
        #themeBtn {
            position: fixed;
            top: 18px;
            right: 18px;
            z-index: 1000;
            width: 42px;
            height: 42px;
            border-radius: 999px;
            border: 1px solid var(--border);
            background: var(--card);
            color: var(--accent-strong);
            font-size: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: var(--shadow-sm);
            transition: transform .2s ease, background .2s ease;
        }
        #themeBtn:hover { transform: scale(1.05); }
        .pm-mini-card {
            background: var(--card-2);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 10px 13px;
            color: var(--text-secondary);
            font-size: 12px;
            transition: transform .16s ease, border-color .16s ease, color .16s ease;
        }
        .pm-mini-card:hover { transform: translateY(-2px); border-color: var(--accent); color: var(--text); }
        .pm-mini-card b { color: var(--accent-strong); font-weight: 800; }

        .stMarkdown, .stText, [data-testid="stMarkdownContainer"] {
            color: var(--text) !important;
        }
        [data-testid="stCaptionContainer"] {
            color: var(--text-muted) !important;
        }
        .stAlert {
            background: var(--card-2) !important;
            border: 1px solid var(--border) !important;
            border-radius: 14px !important;
            color: var(--text-secondary) !important;
        }

        .stButton > button, .stDownloadButton > button {
            min-height: 50px;
            width: 100%;
            padding: 0 22px !important;
            border-radius: 14px !important;
            border: 1px solid var(--accent-strong) !important;
            background: var(--accent) !important;
            color: #3b2a1c !important;
            font-weight: 800 !important;
            letter-spacing: .01em;
            box-shadow: var(--shadow-sm);
            transition: transform .14s ease, background-color .16s ease, border-color .16s ease, box-shadow .16s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            background: var(--accent-strong) !important;
            border-color: var(--accent-strong) !important;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .stButton > button:active, .stDownloadButton > button:active { transform: translateY(0); }
        .stButton > button[kind="primary"],
        .stButton > button[data-testid="stBaseButton-primary"] {
            background: #e6a0a0 !important;
            border-color: #db8a8a !important;
            color: #5a2b2b !important;
        }
        .stButton > button[kind="primary"]:hover,
        .stButton > button[data-testid="stBaseButton-primary"]:hover {
            background: #db8a8a !important;
            border-color: #db8a8a !important;
        }
        .stDownloadButton > button[kind="primary"],
        .stDownloadButton > button[data-testid="stBaseButton-primary"] {
            background: var(--card-2) !important;
            border-color: var(--border-strong) !important;
            color: var(--text-secondary) !important;
        }
        .stDownloadButton > button[kind="primary"]:hover,
        .stDownloadButton > button[data-testid="stBaseButton-primary"]:hover {
            background: var(--card-hover) !important;
            border-color: var(--border-strong) !important;
            color: var(--text) !important;
        }
        .stButton > button:disabled {
            background: var(--card-2) !important;
            color: var(--text-muted) !important;
            border-color: var(--border) !important;
            box-shadow: none;
            transform: none;
        }

        /* TABS — sliding pill indicator (BaseWeb highlight animates left/width) */
        .stTabs [data-baseweb="tab-list"] {
            display: flex;
            width: 100%;
            gap: 8px;
            background: var(--card-2);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 6px;
            position: relative;
            box-shadow: var(--shadow-sm);
        }
        .stTabs [data-baseweb="tab"] {
            flex: 1 1 0;
            justify-content: center;
            text-align: center;
            border-radius: 11px;
            padding: 10px 18px;
            color: var(--text-secondary);
            font-weight: 750;
            background: transparent !important;
            position: relative;
            z-index: 1;
            transition: color .25s ease;
        }
        .stTabs [data-baseweb="tab"]:hover { color: var(--text); }
        .stTabs [aria-selected="true"] { color: var(--accent-strong) !important; }
        .stTabs [data-baseweb="tab-highlight"] {
            height: auto !important;
            top: 6px !important;
            bottom: 6px !important;
            border-radius: 11px !important;
            background: var(--card) !important;
            border: 1px solid var(--border);
            box-shadow: var(--shadow-sm);
            z-index: 0 !important;
        }
        .stTabs [data-baseweb="tab-border"] { display: none !important; }
        [data-baseweb="tab-panel"] { animation: pmFadeIn .45s ease both; }

        div[data-baseweb="input"] > div,
        .stNumberInput input,
        .stTextInput input,
        textarea,
        .stSelectbox div[data-baseweb="select"] > div {
            background: var(--bg-soft) !important;
            color: var(--text) !important;
            border: 1px solid var(--border) !important;
            border-radius: 13px !important;
        }
        .stTextInput input:focus, .stNumberInput input:focus, textarea:focus {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 1px var(--accent-soft) !important;
        }
        /* remove gray borders under inputs in light theme */
        .stTextInput, .stNumberInput, .stTextArea, .stSelectbox {
            border: none !important;
            box-shadow: none !important;
        }
        .stTextInput > div, .stNumberInput > div, .stTextArea > div {
            border: none !important;
            box-shadow: none !important;
        }

        [data-testid="stProgress"] > div { background: #e8e4df !important; }
        [data-testid="stProgress"] > div > div > div > div {
            background: var(--accent) !important;
        }

        /* EXPANDERS — smooth open animation */
        [data-testid="stExpander"] details {
            border: 1px solid var(--border) !important;
            border-radius: 13px !important;
            background: var(--bg-soft) !important;
            overflow: hidden;
            transition: border-color .18s ease;
        }
        [data-testid="stExpander"] details:hover { border-color: var(--border-strong) !important; }
        [data-testid="stExpander"] summary {
            border-radius: 13px !important;
            font-weight: 700;
            color: var(--text);
        }
        [data-testid="stExpander"] summary:hover { color: var(--accent-strong); }
        [data-testid="stExpander"] details[open] [data-testid="stExpanderDetails"] {
            animation: pmFadeUp .34s cubic-bezier(.4,.05,.2,1) both;
        }

        .pm-row {
            display:flex;
            align-items:center;
            gap:12px;
            padding:12px 14px;
            margin:8px 0;
            border-radius:16px;
            background: var(--card);
            border:1px solid var(--border);
            box-shadow: var(--shadow-sm);
            transition: background-color .14s ease, border-color .14s ease, transform .12s ease, box-shadow .14s ease;
        }
        .pm-row:hover {
            background: var(--card-hover);
            border-color: var(--accent);
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .pm-idx {
            display:inline-flex;
            align-items:center;
            justify-content:center;
            min-width:32px;
            height:32px;
            border-radius:10px;
            background: var(--accent-tint);
            border: 1px solid var(--accent-soft);
            color: var(--accent-strong);
            font-weight:800;
            font-size:12px;
            transition: transform .14s ease, background-color .14s ease;
        }
        .pm-row:hover .pm-idx { transform: rotate(-6deg) scale(1.05); }
        .pm-chart {
            display:flex;
            align-items:flex-end;
            gap:10px;
            height:240px;
            padding:18px 16px 14px;
            margin:6px 0 4px;
            background: linear-gradient(180deg, var(--accent-tint) 0%, var(--bg-soft) 100%);
            border: 1px solid var(--border);
            border-radius:18px;
            box-shadow: var(--shadow-sm);
        }
        .pm-bar-col {
            flex:1;
            min-width:0;
            height:100%;
            display:flex;
            flex-direction:column;
            align-items:center;
            justify-content:flex-end;
            gap:6px;
        }
        .pm-bar-val {
            font-size:12px;
            font-weight:800;
            color: var(--accent-strong);
            white-space:nowrap;
        }
        .pm-bar {
            width:100%;
            max-width:48px;
            background: linear-gradient(180deg, var(--accent) 0%, var(--accent-strong) 100%);
            border-radius:8px 8px 4px 4px;
            opacity:.92;
            transform-origin:bottom;
            animation: pmGrowBar .8s cubic-bezier(.22,.9,.3,1) both;
            box-shadow: 0 6px 14px rgba(240,168,104,.30);
            transition: opacity .15s ease, filter .15s ease;
        }
        .pm-bar:hover { opacity:1; filter:brightness(1.05); }
        .pm-bar-lbl {
            font-size:11px;
            color: var(--text-muted);
            text-align:center;
            white-space:nowrap;
            overflow:hidden;
            text-overflow:ellipsis;
            max-width:100%;
        }
        @keyframes pmGrowBar {
            from { transform: scaleY(0); opacity:0; }
            to   { transform: scaleY(1); opacity:.92; }
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
            background: var(--success-soft);
            border: 1px solid var(--success-bd);
            color: #3f8b63;
            white-space:nowrap;
        }
        .ping-badge.slow {
            background: var(--warning-soft);
            border-color: var(--warning-bd);
            color: #9a7220;
        }
        .tg-btn {
            display:inline-flex;
            align-items:center;
            justify-content:center;
            background: var(--accent-tint);
            color: var(--accent-strong) !important;
            border: 1px solid var(--accent-soft);
            padding:8px 14px;
            border-radius:12px;
            text-decoration:none;
            font-size:12px;
            font-weight:800;
            white-space:nowrap;
            transition: background-color .15s ease, border-color .15s ease, transform .12s ease;
        }
        .tg-btn:hover {
            background: var(--accent-soft);
            border-color: var(--accent);
            transform: translateY(-1px);
        }
        .pm-stat {
            display:inline-flex;
            align-items:center;
            gap:6px;
            padding:8px 13px;
            margin:4px 7px 10px 0;
            border-radius:12px;
            background: var(--accent-tint);
            border:1px solid var(--accent-soft);
            color: var(--text-secondary);
            font-size:12px;
            font-weight:650;
        }
        .pm-stat b { color: var(--accent-strong); }
        .pm-stat-grid {
            display: flex;
            gap: 12px;
            margin: 4px 0 16px 0;
            flex-wrap: wrap;
        }
        .pm-stat-card {
            flex: 1 1 0;
            min-width: 150px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px 18px;
            box-shadow: var(--shadow-sm);
        }
        .pm-stat-card .pm-stat-label {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: .03em;
            margin-bottom: 6px;
        }
        .pm-stat-card .pm-stat-value {
            font-size: 30px;
            font-weight: 850;
            color: var(--accent-strong);
            line-height: 1.1;
        }
        code, pre {
            background: var(--code-bg) !important;
            border: 1px solid var(--border) !important;
            border-radius: 12px !important;
            color: var(--text-secondary) !important;
        }
        hr { border-color: var(--border) !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    if dark:
        st.markdown(
            """
            <style>
            :root {
                --bg: #0f0d12;
                --bg-soft: #16131a;
                --card: #1a161f;
                --card-2: #211c28;
                --card-hover: #2a252f;
                --border: #2c2533;
                --border-strong: #3a3142;
                --accent: #f0a868;
                --accent-strong: #f6bd84;
                --accent-soft: #3a2a1d;
                --accent-tint: #241a14;
                --text: #f0e7df;
                --text-secondary: #b6a695;
                --text-muted: #7c6d60;
                --success: #7fd6a1;
                --success-soft: #16271d;
                --success-bd: #244a33;
                --warning: #f0c061;
                --warning-soft: #2a2113;
                --warning-bd: #473918;
                --danger: #f87171;
                --shadow: 0 18px 44px rgba(0,0,0,.5);
                --shadow-sm: 0 8px 20px rgba(0,0,0,.4);
                --hero-glow: #2a1d12;
                --code-bg: #120f16;
            }
            [data-testid="stProgress"] > div { background: #3a3142 !important; }
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
_pm_dark = st.session_state.get("pm_dark", False)
inject_theme(dark=_pm_dark)
st.markdown(
    """
    <section class='pm-shell pm-hero'>
        <div class='pm-badge'>PROXY MANAGER // FRESH UI</div>
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

_tcol_sp, _tcol_tg = st.columns([5, 1])
with _tcol_tg:
    st.toggle("🌙 Тёмная", key="pm_dark")

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
        st.info("Таблиц�� пуста. Нажмите кнопку выше, чтобы запустить сканирование.")

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

    with st.expander("Фильтры VLESS перед проверкой", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            security_filter = st.selectbox(
                "Security", ["Любой", "reality", "tls"], key="vless_security_filter",
            )
            only_tcp = st.checkbox("Только type=tcp", key="vless_only_tcp")
        with c2:
            require_sni = st.checkbox("Только ключи с SNI/Host", key="vless_require_sni")
            exclude_ws = st.checkbox("Исключить WebSocket", key="vless_exclude_ws")

    enable_xray = False
    enable_speed = False
    test_url = DEFAULT_TEST_URL
    speed_url = DEFAULT_SPEED_URL
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
            enable_speed = st.checkbox(
                "Speed-test для найденных ключей (медленнее, но точнее)",
                value=False, key="vless_enable_speed",
            )
            if enable_speed:
                speed_url = st.text_input(
                    "URL файла для speed-test:",
                    value=DEFAULT_SPEED_URL, key="vless_speed_url",
                )

    if own_keys:
        wanted = 0
        run_smart = st.button(
            "Проверить мои ключи",
            use_container_width=True, key="btn_vless_smart",
        )
    else:
        col_input, col_btn = st.columns([3, 2])
        with col_input:
            wanted = st.number_input(
                "Нужно рабочих ключей:", min_value=1, max_value=500, value=50, step=10,
                key="vless_wanted",
            )
        with col_btn:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
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

        if not input_error:
            before_filter = len(all_infos)
            all_infos = filter_vless_infos(
                all_infos,
                only_reality=(security_filter == "reality"),
                only_tls=(security_filter == "tls"),
                only_tcp=only_tcp,
                exclude_ws=exclude_ws,
                require_sni=require_sni,
            )
            if before_filter != len(all_infos):
                st.write(f"После фильтров: **{len(all_infos)}** из **{before_filter}** ключей.")

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

            if enable_speed and XRAY_BIN and found_keys:
                speed_bar = st.progress(0.0, text=f"Speed-test: 0 / {len(found_keys)}")
                done_speed = 0
                with ThreadPoolExecutor(max_workers=min(4, MAX_XRAY_WORKERS)) as ex:
                    fmap = {ex.submit(speed_test_vless, item["info"], speed_url): item for item in found_keys}
                    for fut in as_completed(fmap):
                        done_speed += 1
                        fmap[fut]["speed"] = fut.result()
                        speed_bar.progress(done_speed / len(found_keys), text=f"Speed-test: {done_speed} / {len(found_keys)}")
                speed_bar.empty()

            for item in found_keys:
                item["score"] = vless_score(item["info"], item.get("ping"), item.get("speed"))
            found_keys.sort(key=lambda x: (x.get("score", 0), -(x.get("ping") or 999999)), reverse=True)
            upsert_working_db(found_keys)

            st.session_state.smart_vless_keys = found_keys
            st.session_state.smart_vless_done = True
            st.session_state.smart_vless_label = check_label + (" + speed-test" if enable_speed else "")
            st.session_state.smart_page = 0

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
        SMART_PER_PAGE = 5
        total_smart_pages = max(1, (len(smart_keys) + SMART_PER_PAGE - 1) // SMART_PER_PAGE)
        st.session_state.setdefault("smart_page", 0)
        smart_page = min(st.session_state.smart_page, total_smart_pages - 1)
        page_slice = smart_keys[smart_page * SMART_PER_PAGE:(smart_page + 1) * SMART_PER_PAGE]
        for off, item in enumerate(page_slice):
            si = smart_page * SMART_PER_PAGE + off
            info = item["info"]
            meta = vless_meta(info)
            display = html.escape(vless_display_name(info))
            host = html.escape(vless_host_display(info))
            sni = html.escape(meta.get("sni") or "-")
            score = int(item.get("score") or vless_score(info, item.get("ping"), item.get("speed")))
            speed = item.get("speed")
            speed_text = f"{speed} Mbps" if speed is not None else "-"
            st.markdown(
                f"<div class='pm-row'>"
                f"<span class='pm-idx'>{si + 1}</span>"
                f"{ping_badge(item['ping'])}"
                f"<span class='pm-name'>{display}<br>"
                f"<span style='color:var(--text-secondary);font-size:12px;'>"
                f"{host} · {html.escape(meta['security'])}/{html.escape(meta['network'])} · SNI: {sni} · "
                f"Speed: {speed_text} · Score: {score} ({score_label(score)})"
                f"</span></span>"
                f"</div>",
                unsafe_allow_html=True,
            )
            with st.expander(f"Ключ #{si + 1}: скопировать"):
                st.code(item["key"], language=None)

        if total_smart_pages > 1:
            sp_prev, sp_mid, sp_next = st.columns([1, 2, 1])
            with sp_prev:
                if st.button("← Назад", disabled=(smart_page == 0), key="smart_prev", use_container_width=True):
                    st.session_state.smart_page = smart_page - 1
                    st.rerun()
            with sp_mid:
                st.markdown(
                    f"<div style='text-align:center;padding-top:12px;color:var(--text-secondary);font-weight:650;'>"
                    f"Страница {smart_page + 1} из {total_smart_pages}</div>",
                    unsafe_allow_html=True,
                )
            with sp_next:
                if st.button("Вперёд →", disabled=(smart_page >= total_smart_pages - 1), key="smart_next", use_container_width=True):
                    st.session_state.smart_page = smart_page + 1
                    st.rerun()

        smart_bytes = "\n".join(item["key"] for item in smart_keys).encode("utf-8")
        st.download_button(
            label=f"Скачать {len(smart_keys)} ключей (vless_working.txt)",
            data=smart_bytes, file_name="vless_working.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_smart_vless",
        )
        sub_b64 = make_subscription([item["key"] for item in smart_keys])
        st.download_button(
            label="Скачать как подписку (base64, vless_sub.txt)",
            data=sub_b64.encode("utf-8"), file_name="vless_sub.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_smart_sub",
        )
        with st.expander("Подписка (base64) — скопировать"):
            st.caption(
                "Вставьте этот текст как содержимое подписки или импортируйте файл "
                "vless_sub.txt в клиент (v2rayN, Hiddify, Nekobox, Streisand)."
            )
            st.code(sub_b64, language=None)

    st.markdown("---")
    st.markdown("### Рабочая база")
    working_db = load_working_db()
    if working_db:
        last_ping_vals = [int(x.get("ping", 0)) for x in working_db if int(x.get("ping", 0)) > 0]
        _best_score = max(int(x.get("score", 0)) for x in working_db)
        _best_ping = f"{min(last_ping_vals)} ms" if last_ping_vals else "-"
        st.markdown(
            f"""
            <div class='pm-stat-grid'>
                <div class='pm-stat-card'>
                    <div class='pm-stat-label'>Ключей в базе</div>
                    <div class='pm-stat-value'>{len(working_db)}</div>
                </div>
                <div class='pm-stat-card'>
                    <div class='pm-stat-label'>Лучший score</div>
                    <div class='pm-stat-value'>{_best_score}</div>
                </div>
                <div class='pm-stat-card'>
                    <div class='pm-stat-label'>Лучший ping</div>
                    <div class='pm-stat-value'>{_best_ping}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        db_col1, db_col2 = st.columns(2)
        with db_col1:
            if st.button("Перепроверить рабочую базу", key="btn_recheck_working", use_container_width=True):
                rechecked = []
                infos = [parse_vless(x.get("key", "")) for x in working_db]
                infos = [i for i in infos if i]
                if infos:
                    with st.spinner("Перепроверяем старые рабочие ключи..."):
                        with ThreadPoolExecutor(max_workers=MAX_XRAY_WORKERS if XRAY_BIN else MAX_TCP_WORKERS) as ex:
                            if XRAY_BIN:
                                fmap = {ex.submit(url_test_vless, i, DEFAULT_TEST_URL): i for i in infos}
                            else:
                                fmap = {ex.submit(check_tcp_ping, i["host"], i["port"], 1.0): i for i in infos}
                            for fut in as_completed(fmap):
                                ping = fut.result()
                                if ping is not None:
                                    info = fmap[fut]
                                    rechecked.append({"info": info, "key": info["raw"], "ping": ping})
                    save_working_db([])
                    upsert_working_db(rechecked)
                    st.success(f"Живых после перепроверки: {len(rechecked)}")
                    st.rerun()
        with db_col2:
            if st.button("Очистить рабочую базу", key="btn_clear_working", type="primary", use_container_width=True):
                try:
                    os.remove(WORKING_DB_FILE)
                except Exception:
                    pass
                st.rerun()

        top_db = sorted(working_db, key=lambda x: int(x.get("score", 0)), reverse=True)
        WORK_PER_PAGE = 5
        total_work_pages = max(1, (len(top_db) + WORK_PER_PAGE - 1) // WORK_PER_PAGE)
        st.session_state.setdefault("working_page", 0)
        work_page = min(st.session_state.working_page, total_work_pages - 1)
        work_slice = top_db[work_page * WORK_PER_PAGE:(work_page + 1) * WORK_PER_PAGE]
        for off, rec in enumerate(work_slice):
            idx = work_page * WORK_PER_PAGE + off
            name = html.escape(rec.get("name") or rec.get("host") or "VLESS")
            host = html.escape(f"{rec.get('host','')}:{rec.get('port','')}")
            score = int(rec.get("score", 0))
            ping = rec.get("ping", "-")
            speed = rec.get("speed")
            speed_text = f"{speed} Mbps" if speed is not None else "-"
            st.markdown(
                f"<div class='pm-row'>"
                f"<span class='pm-idx'>{idx + 1}</span>"
                f"<span class='ping-badge'>{ping} мс</span>"
                f"<span class='pm-name'>{name}<br>"
                f"<span style='color:var(--text-secondary);font-size:12px;'>"
                f"{host} · {html.escape(rec.get('security',''))}/{html.escape(rec.get('network',''))} · "
                f"Speed: {speed_text} · Score: {score} ({score_label(score)}) · {html.escape(rec.get('last_checked',''))}"
                f"</span></span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        if total_work_pages > 1:
            wp_prev, wp_mid, wp_next = st.columns([1, 2, 1])
            with wp_prev:
                if st.button("← Назад", disabled=(work_page == 0), key="work_prev", use_container_width=True):
                    st.session_state.working_page = work_page - 1
                    st.rerun()
            with wp_mid:
                st.markdown(
                    f"<div style='text-align:center;padding-top:12px;color:var(--text-secondary);font-weight:650;'>"
                    f"Страница {work_page + 1} из {total_work_pages}</div>",
                    unsafe_allow_html=True,
                )
            with wp_next:
                if st.button("Вперёд →", disabled=(work_page >= total_work_pages - 1), key="work_next", use_container_width=True):
                    st.session_state.working_page = work_page + 1
                    st.rerun()
        db_keys = [x["key"] for x in working_db if x.get("key")]
        st.download_button("Скачать рабочую базу (working_vless.txt)", "\n".join(db_keys).encode("utf-8"),
                           file_name="working_vless.txt", mime="text/plain; charset=utf-8",
                           use_container_width=True, key="btn_download_working_db")
        st.download_button("Скачать рабочую базу как подписку", make_subscription(db_keys).encode("utf-8"),
                           file_name="working_vless_sub.txt", mime="text/plain; charset=utf-8",
                           type="primary", use_container_width=True, key="btn_download_working_db_sub")
    else:
        st.info("Рабочая база пока пуста. После умного подбора найденные ключи сохранятся сюда автоматически.")

    st.markdown("---")
    st.markdown("### История источников")
    st.caption(
        "График показывает, сколько vless-ключей отдавал каждый источник при "
        "каждом обновлении базы — видно, какие репозитории деградируют."
    )
    _hist = load_history()
    if _hist:
        rows = []
        for rec in _hist:
            row = {"Время": rec.get("ts", "")}
            row.update(rec.get("counts", {}))
            rows.append(row)
        hist_df = pd.DataFrame(rows).set_index("Время").fillna(0)
        total_series = hist_df.sum(axis=1)
        c1, c2 = st.columns(2)
        c1.metric("Замеров в истории", len(_hist))
        c2.metric("Всего ключей (последний замер)", int(total_series.iloc[-1]))
        view = st.radio(
            "Что показать:", ["Всего по времени", "По источникам"],
            horizontal=True, key="hist_view",
        )
        if view == "Всего по времени":
            series = total_series.tail(14)
            render_bar_chart([
                (str(idx).split(" ")[-1], val)
                for idx, val in zip(series.index, series.values)
            ])
        else:
            last_row = hist_df.iloc[-1].sort_values(ascending=False)
            last_row = last_row[last_row > 0].head(14)
            render_bar_chart([
                (str(src), val) for src, val in zip(last_row.index, last_row.values)
            ])
        if st.button("Очистить историю", key="btn_clear_history"):
            try:
                os.remove(HISTORY_FILE)
            except Exception:
                pass
            st.rerun()
    else:
        st.info(
            "История пока пуста. Нажмите «Загрузить / Обновить VLESS ключи» ниже — "
            "каждое обновление добавляет замер."
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
            st.session_state.vless_source_health = [
                {"Источник": k, "Ключей": int(v), "Статус": "OK" if int(v) > 0 else "Пусто/ошибка"}
                for k, v in stats.items()
            ]
            append_history(stats)
            st.success(
                "Загружено: "
                + " | ".join(f"**{k}**: {v}" for k, v in stats.items())
            )

    st.markdown("---")
    if st.session_state.get("vless_source_health"):
        with st.expander("Здоровье источников", expanded=True):
            st.dataframe(pd.DataFrame(st.session_state.vless_source_health), use_container_width=True)

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
        all_sub_b64 = make_subscription(st.session_state.vless_keys)
        st.download_button(
            label="Скачать все как подписку (base64)",
            data=all_sub_b64.encode("utf-8"), file_name="vless_sub_all.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
            key="btn_download_vless_sub",
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
