"""
Headless-фильтр VLESS-ключей для GitHub Actions.

Читает vless.txt, прогоняет ключи каскадом:
    1) TCP        — отсев мёртвых серверов (по уникальным host:port)
    2) TLS        — handshake с нужным SNI (для tls/reality)
    3) Xray       — реальный url-тест только по выжившим ключам (с ранней остановкой)

Пишет первые N ключей, прошедших все этапы, в vless_filtered.txt.

Запуск:
    python filter_vless.py --input vless.txt --output vless_filtered.txt --count 10
Для этапа Xray нужен бинарь xray (xray-core) в PATH или рядом с файлом.
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

# ── Настройки ─────────────────────────────────────────────────────
MAX_TCP_WORKERS = 100
MAX_TLS_WORKERS = 60
MAX_XRAY_WORKERS = 8
TCP_TIMEOUT = 1.5
TLS_TIMEOUT = 3.0
XRAY_TIMEOUT = 8
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (ProxyManager/1.0)"}

_here = os.path.dirname(os.path.abspath(__file__))


def find_xray():
    import shutil
    cand = shutil.which("xray")
    if cand:
        return cand
    local = os.path.join(_here, "xray")
    return local if os.path.exists(local) else None


XRAY_BIN = find_xray()


# ── Парсинг VLESS ──────────────────────────────────────────────
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


def vless_security(info):
    return info["params"].get("security", "none") if info else "none"


def vless_sni(info):
    p = info["params"]
    return p.get("sni") or p.get("host") or info["host"]


# ── Сетевые проверки ───────────────────────────────────────
def check_tcp_ping(host, port, timeout=TCP_TIMEOUT):
    if not host or not port:
        return None
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return None


def check_tls_handshake(host, port, server_name=None, timeout=TLS_TIMEOUT):
    """TLS-handshake с указанным SNI. Проверка сертификата отключена."""
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


# ── Xray outbound + url-тест ───────────────────────────────────
def vless_to_outbound(info):
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


def url_test_vless(info, test_url=DEFAULT_TEST_URL, timeout=XRAY_TIMEOUT):
    """Реальный url-тест через локальный xray (socks5). Задержка в мс или None."""
    if not XRAY_BIN or requests is None:
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
        time.sleep(0.8)

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


# ── Этапы каскада ────────────────────────────────────────
def load_infos(path):
    seen = set()
    infos = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("vless://") and line not in seen:
                seen.add(line)
                info = parse_vless(line)
                if info:
                    infos.append(info)
    return infos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="vless.txt")
    ap.add_argument("--output", default="vless_filtered.txt")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--test-url", default=DEFAULT_TEST_URL)
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] файл {args.input} не найден", file=sys.stderr)
        sys.exit(1)

    infos = load_infos(args.input)
    print(f"[*] загружено уникальных VLESS-ключей: {len(infos)}")
    if not infos:
        print("[!] нечего проверять", file=sys.stderr)
        sys.exit(1)

    # ─── Этап 1: TCP по уникальным host:port ───
    endpoints = sorted({(i["host"], i["port"]) for i in infos})
    print(f"[1/3] TCP: проверяем {len(endpoints)} уникальных серверов...")
    alive_ep = set()
    with ThreadPoolExecutor(max_workers=MAX_TCP_WORKERS) as ex:
        fmap = {ex.submit(check_tcp_ping, h, p): (h, p) for h, p in endpoints}
        for fut in as_completed(fmap):
            if fut.result() is not None:
                alive_ep.add(fmap[fut])
    after_tcp = [i for i in infos if (i["host"], i["port"]) in alive_ep]
    print(f"[1/3] TCP: живых серверов {len(alive_ep)}, ключей осталось {len(after_tcp)}")

    # ─── Этап 2: TLS handshake (только tls/reality) ───
    need_tls = [i for i in after_tcp if vless_security(i) in ("tls", "reality")]
    passthrough = [i for i in after_tcp if vless_security(i) not in ("tls", "reality")]
    tls_targets = sorted({(i["host"], i["port"], vless_sni(i)) for i in need_tls})
    print(f"[2/3] TLS: проверяем {len(tls_targets)} уникальных host:port:sni "
          f"({len(passthrough)} ключей без TLS проходят напрямую)...")
    ok_tls = set()
    with ThreadPoolExecutor(max_workers=MAX_TLS_WORKERS) as ex:
        fmap = {ex.submit(check_tls_handshake, h, p, s): (h, p, s) for h, p, s in tls_targets}
        for fut in as_completed(fmap):
            if fut.result() is not None:
                ok_tls.add(fmap[fut])
    after_tls = passthrough + [
        i for i in need_tls if (i["host"], i["port"], vless_sni(i)) in ok_tls
    ]
    print(f"[2/3] TLS: прошло рукопожатие {len(ok_tls)} серверов, ключей осталось {len(after_tls)}")

    # ─── Этап 3: Xray url-тест с ранней остановкой ───
    target = args.count
    working = []
    if not XRAY_BIN:
        print("[3/3] Xray: бинарь не найден — берём ключи, прошедшие TCP+TLS", file=sys.stderr)
        working = [i["raw"] for i in after_tls[:target]]
    else:
        print(f"[3/3] Xray: url-тест, нужно {target} ключей (ранняя остановка)...")
        with ThreadPoolExecutor(max_workers=MAX_XRAY_WORKERS) as ex:
            fmap = {ex.submit(url_test_vless, i, args.test_url): i for i in after_tls}
            try:
                for fut in as_completed(fmap):
                    ping = fut.result()
                    if ping is not None:
                        working.append((ping, fmap[fut]["raw"]))
                        print(f"    + рабочий ({ping} мс), всего {len(working)}/{target}")
                        if len(working) >= target:
                            break
            finally:
                for fut in fmap:
                    fut.cancel()
        working.sort(key=lambda x: x[0])
        working = [raw for _, raw in working]

    # ─── Запись ───
    with open(args.output, "w", encoding="utf-8") as f:
        for raw in working:
            f.write(raw + "\n")
    print(f"[✓] записано {len(working)} ключей в {args.output}")


if __name__ == "__main__":
    main()
