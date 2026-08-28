import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (ProxyManager/2.0)"}
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
VALIDATION_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
]
VALIDATION_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
VALIDATION_MIN_SUCCESS = 2
VALIDATION_MIN_BYTES = 256 * 1024
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
_local_xray = "xray.exe" if os.name == "nt" else "xray"
XRAY_BIN = shutil.which("xray") or (
    os.path.join(_here, _local_xray)
    if os.path.exists(os.path.join(_here, _local_xray)) else None
)


def parse_vless(raw):
    try:
        if not raw.startswith("vless://"):
            return None
        body = raw[len("vless://"):]
        name = ""
        if "#" in body:
            body, frag = body.split("#", 1)
            name = urllib.parse.unquote(frag).strip()
        params = {}
        if "?" in body:
            body, qs = body.split("?", 1)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
        if "@" not in body:
            return None
        uuid, host_part = body.split("@", 1)
        if host_part.startswith("["):
            end = host_part.find("]")
            if end == -1:
                return None
            host = host_part[1:end]
            rest = host_part[end + 1:]
            port = rest[1:] if rest.startswith(":") else ""
        elif ":" in host_part:
            host, port = host_part.rsplit(":", 1)
        else:
            return None
        if not uuid or not host or not port.isdigit():
            return None
        return {
            "raw": raw, "uuid": uuid, "host": host, "port": int(port),
            "name": name, "params": params,
        }
    except Exception:
        return None


def parse_text(text):
    seen = set()
    out = []
    for line in text.splitlines():
        raw = line.strip()
        if raw in seen or not raw.startswith("vless://"):
            continue
        seen.add(raw)
        info = parse_vless(raw)
        if info:
            out.append(info)
    return out


def load_sources(report=None):
    texts = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        fmap = {
            ex.submit(requests.get, url, timeout=12, headers=HTTP_HEADERS): url
            for url in VLESS_SOURCES
        }
        for fut in as_completed(fmap):
            url = fmap[fut]
            try:
                resp = fut.result()
                texts[url] = resp.text if resp.status_code == 200 else ""
            except Exception:
                texts[url] = ""
            if report:
                report(url, len(parse_text(texts[url])))
    return parse_text("\n".join(texts.values()))


def filter_infos(infos, security="any", only_tcp=False, require_sni=False, exclude_ws=False):
    out = []
    for info in infos:
        p = info["params"]
        sec = p.get("security", "none")
        network = p.get("type", "tcp")
        sni = p.get("sni") or p.get("host") or ""
        if security != "any" and sec != security:
            continue
        if only_tcp and network != "tcp":
            continue
        if require_sni and not sni:
            continue
        if exclude_ws and network == "ws":
            continue
        out.append(info)
    return out


def resolve_hosts(hosts, report=None, stop_event=None):
    resolved = {}

    def resolve(host):
        try:
            rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ipv4 = [row[4][0] for row in rows if row[0] == socket.AF_INET]
            return ipv4[0] if ipv4 else rows[0][4][0]
        except Exception:
            return None

    hosts = list(dict.fromkeys(hosts))
    done = 0
    with ThreadPoolExecutor(max_workers=80) as ex:
        fmap = {ex.submit(resolve, host): host for host in hosts}
        for fut in as_completed(fmap):
            if stop_event and stop_event.is_set():
                for pending in fmap:
                    pending.cancel()
                break
            done += 1
            ip = fut.result()
            if ip:
                resolved[fmap[fut]] = ip
            if report and (done % 100 == 0 or done == len(hosts)):
                report("dns", done, len(hosts), len(resolved))
    return resolved


def lookup_ip_countries(ips, cached=None, save=None, report=None, stop_event=None):
    countries = dict(cached or {})
    missing = [ip for ip in dict.fromkeys(ips) if ip not in countries]
    total = len(missing)
    done = 0
    for offset in range(0, total, 100):
        if stop_event and stop_event.is_set():
            break
        chunk = missing[offset:offset + 100]
        response = None
        for _ in range(3):
            try:
                response = requests.post(
                    "http://ip-api.com/batch?fields=status,countryCode,query",
                    json=chunk, timeout=20, headers=HTTP_HEADERS,
                )
            except Exception:
                response = None
                break
            if response.status_code != 429:
                break
            wait_for = max(1, int(response.headers.get("X-Ttl", "60") or 60) + 1)
            if stop_event and stop_event.wait(wait_for):
                return countries
            time.sleep(wait_for) if not stop_event else None
        fresh = {}
        if response is not None and response.status_code == 200:
            try:
                for row in response.json():
                    if row.get("status") == "success" and row.get("query"):
                        fresh[row["query"]] = (row.get("countryCode") or "").upper()
            except Exception:
                fresh = {}
        countries.update(fresh)
        if save and fresh:
            save(fresh)
        done += len(chunk)
        if report:
            report("geo", done, total, len(fresh))
        remaining = int(response.headers.get("X-Rl", "1") or 1) if response is not None else 1
        if remaining == 0 and done < total:
            wait_for = max(1, int(response.headers.get("X-Ttl", "60") or 60) + 1)
            if stop_event:
                if stop_event.wait(wait_for):
                    break
            else:
                time.sleep(wait_for)
    return countries


def check_tcp(host, port, timeout=1.5):
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return None


def check_tls(host, port, sni, timeout=3.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as sock:
                sock.do_handshake()
        return int((time.time() - start) * 1000)
    except Exception:
        return None


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
            "serverName": p.get("sni", ""), "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""),
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
            "header": {"type": "http", "request": {
                "headers": {"Host": [p.get("host", info["host"])]}
            }}
        }
    return {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": info["host"], "port": info["port"], "users": [user]
        }]},
        "streamSettings": stream,
    }


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_xray(info):
    port = _free_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [vless_to_outbound(info)],
    }
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(cfg, fh)
    finally:
        fh.close()
    popen_args = {}
    if os.name == "nt":
        popen_args["creationflags"] = subprocess.CREATE_NO_WINDOW
    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-c", fh.name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **popen_args,
    )
    time.sleep(0.8)
    return proc, fh.name, {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }


def _stop_xray(proc, path):
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass


def check_xray(info, test_url=DEFAULT_TEST_URL, timeout=8):
    if not XRAY_BIN:
        return None
    proc = None
    path = None
    try:
        proc, path, proxies = _start_xray(info)
        urls = []
        for url in [test_url] + VALIDATION_URLS:
            if url and url not in urls:
                urls.append(url)
        successes = 0
        best_ping = None
        for url in urls:
            try:
                start = time.time()
                resp = requests.get(url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS)
                if resp.status_code in (200, 204):
                    successes += 1
                    ping = int((time.time() - start) * 1000)
                    best_ping = ping if best_ping is None else min(best_ping, ping)
                    if successes >= VALIDATION_MIN_SUCCESS:
                        break
            except Exception:
                continue
        if successes < VALIDATION_MIN_SUCCESS:
            return None
        start = time.time()
        resp = requests.get(
            VALIDATION_DOWNLOAD_URL, proxies=proxies, timeout=timeout,
            headers=HTTP_HEADERS, stream=True,
        )
        if resp.status_code not in (200, 204):
            return None
        size = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                size += len(chunk)
            if size >= VALIDATION_MIN_BYTES or time.time() - start > timeout:
                break
        return best_ping if size >= VALIDATION_MIN_BYTES else None
    except Exception:
        return None
    finally:
        _stop_xray(proc, path)


def check_speed(info, url=DEFAULT_SPEED_URL, timeout=12):
    if not XRAY_BIN:
        return None
    proc = None
    path = None
    try:
        proc, path, proxies = _start_xray(info)
        start = time.time()
        resp = requests.get(
            url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS, stream=True,
        )
        if resp.status_code not in (200, 204):
            return None
        size = sum(len(chunk) for chunk in resp.iter_content(65536) if chunk)
        elapsed = max(time.time() - start, 0.001)
        return round(size * 8 / elapsed / 1_000_000, 2) if size else None
    except Exception:
        return None
    finally:
        _stop_xray(proc, path)


class CheckCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.values = {}
        self.pending = {}

    def get(self, key, fn):
        with self.lock:
            if key in self.values:
                return self.values[key]
            event = self.pending.get(key)
            owner = event is None
            if owner:
                event = threading.Event()
                self.pending[key] = event
        if not owner:
            event.wait()
            with self.lock:
                return self.values.get(key)
        try:
            value = fn()
        except Exception:
            value = None
        with self.lock:
            self.values[key] = value
            self.pending.pop(key, None)
            event.set()
        return value


def score(info, ping=None, speed=None):
    p = info["params"]
    total = 50
    if ping is not None:
        total += 25 if ping <= 120 else 18 if ping <= 250 else 10 if ping <= 500 else 3
    if speed is not None:
        total += 20 if speed >= 30 else 14 if speed >= 10 else 8 if speed >= 3 else 2
    if p.get("security") == "reality":
        total += 5
    if p.get("sni") or p.get("host"):
        total += 3
    if p.get("flow"):
        total += 2
    return max(0, min(100, total))


def shuffle_infos(infos, preferred=None):
    preferred = preferred or set()
    known = [item for item in infos if item["raw"] in preferred]
    rest = [item for item in infos if item["raw"] not in preferred]
    random.shuffle(known)
    random.shuffle(rest)
    return known + rest
