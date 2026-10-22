import ipaddress
import json
import os
import random
import re
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

# Глобальный предел одновременно запущенных процессов Xray для всех заданий.
XRAY_CONCURRENCY = int(os.environ.get("PM_XRAY_CONCURRENCY", "8"))
XRAY_SLOTS = threading.BoundedSemaphore(XRAY_CONCURRENCY)
XRAY_START_TIMEOUT = 5.0
# Сколько держать проверенные ключи в рабочей базе.
WORKING_TTL_DAYS = int(os.environ.get("PM_WORKING_TTL_DAYS", "30"))

SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade", "raw", "kcp"}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# xhttp mode -> Xray xHTTP mode. Неизвестные значения игнорируются.
XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
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
# Speed measurement stops at this many bytes or at its timeout, whichever comes first.
SPEED_MAX_BYTES = 10 * 1024 * 1024
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
            # '+' is a literal plus in VLESS URIs; parse_qs would turn it into a space.
            # Values are decoded exactly once here and nowhere else.
            params = {k: v[0] for k, v in urllib.parse.parse_qs(qs.replace("+", "%2B")).items()}
        if "@" not in body:
            return None
        uuid, host_part = body.split("@", 1)
        host, port = split_host_port(host_part)
        if not host or port is None:
            return None
        params = normalize_params(params)
        network = params.get("type", "tcp")
        if network not in SUPPORTED_NETWORKS:
            return None
        security = params.get("security", "none")
        if security not in ("none", "tls", "reality"):
            return None
        if not UUID_RE.match(uuid):
            return None
        if security == "reality" and not (params.get("pbk") and params.get("sni")):
            return None
        return {
            "raw": raw, "uuid": uuid, "host": host, "port": port,
            "name": name, "params": params,
        }
    except Exception:
        return None


def split_host_port(host_part):
    """Разделяет host:port, включая IPv6 в скобках и голый IPv6 без порта."""
    host_part = host_part.strip()
    if not host_part or any(ch in host_part for ch in (' ', '<', '>', '"', "'", '/', '\\')):
        return None, None
    if host_part.startswith("["):
        end = host_part.find("]")
        if end == -1:
            return None, None
        host = host_part[1:end]
        rest = host_part[end + 1:]
        if rest.startswith(":"):
            port = rest[1:]
        elif not rest:
            port = "443"
        else:
            return None, None
    elif host_part.count(":") > 1:
        host, port = host_part, "443"
    elif ":" in host_part:
        host, port = host_part.rsplit(":", 1)
    else:
        host, port = host_part, "443"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return None, None
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return None, None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None, None
    return host, int(port)


def normalize_params(params):
    """Снимает HTML-экранирование amp; и приводит известные ключи."""
    out = {}
    for key, value in params.items():
        key = key.replace("amp;", "").strip()
        if not key or key in out:
            continue
        out[key] = value.strip()
    if "allowInsecure" not in out and "allowinsecure" in out:
        out["allowInsecure"] = out["allowinsecure"]
    if "allowInsecure" not in out and "insecure" in out:
        out["allowInsecure"] = out["insecure"]
    return out


def is_private_ip(ip):
    """True for any address that is not globally routable (CGNAT, loopback, LAN, ...)."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast or ip.is_unspecified


def is_private_host(host):
    """True for a private IP literal or a local host name. Names are not resolved here."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost", "localhost.localdomain") or host.endswith(
            (".local", ".localhost", ".internal")
        )
    return is_private_ip(ip)


def resolve_pinned(host):
    """The one address to connect to for host, or None if the host is unusable.

    None means: the name does not resolve, or any address it resolves to is not
    globally routable. Callers connect to the returned address, so a later lookup
    cannot return a different (rebinding) address.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return None if is_private_ip(literal) else host
    try:
        rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None
    addresses = []
    for row in rows:
        try:
            ip = ipaddress.ip_address(row[4][0].split("%", 1)[0])
        except ValueError:
            continue
        if is_private_ip(ip):
            return None
        addresses.append(str(ip))
    if not addresses:
        return None
    ipv4 = [address for address in addresses if ":" not in address]
    return (ipv4 or addresses)[0]


def key_identity(info):
    """Идентичность ключа без фрагмента #name: одинаковые параметры = один ключ."""
    params = info["params"]
    items = tuple(sorted(
        (k, v) for k, v in params.items() if k not in ("note", "name")
    ))
    return (info["uuid"], info["host"], info["port"], items)


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


def resolve_hosts(hosts, report=None, stop_event=None, cache=None):
    """Map each host to its pinned address (see resolve_pinned); unusable hosts are left out.

    Pass the job's cache so the probe reuses these lookups instead of resolving again.
    """
    resolved = {}

    def resolve(host):
        if cache is not None:
            return cache.get(host, lambda: resolve_pinned(host))
        return resolve_pinned(host)

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


def _header_int(response, name, default):
    """Число из заголовка ip-api. Некорректное значение не роняет задание."""
    raw = (response.headers.get(name) or "").strip()
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


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
        limited = False
        for _ in range(3):
            try:
                response = requests.post(
                    "http://ip-api.com/batch?fields=status,countryCode,query",
                    json=chunk, timeout=20, headers=HTTP_HEADERS,
                )
            except Exception:
                # Сетевая ошибка: страны неизвестны, задание продолжается.
                response = None
                break
            if response.status_code != 429:
                break
            limited = True
            wait_for = max(1, _header_int(response, "X-Ttl", 60) + 1)
            if stop_event:
                if stop_event.wait(wait_for):
                    return countries
            else:
                time.sleep(wait_for)
        fresh = {}
        if response is not None and response.status_code == 200:
            try:
                rows = response.json()
            except Exception:
                rows = []
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    if row.get("status") == "success" and row.get("query"):
                        fresh[row["query"]] = (row.get("countryCode") or "").upper()
        countries.update(fresh)
        if save and fresh:
            save(fresh)
        done += len(chunk)
        if report:
            report("geo", done, total, len(fresh))
        remaining = _header_int(response, "X-Rl", 1) if response is not None else 1
        if (limited or remaining <= 0) and done < total and response is not None:
            wait_for = max(1, _header_int(response, "X-Ttl", 60) + 1)
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


def _path_value(value, default="/"):
    """path/spiderX as parsed by parse_vless (already decoded once)."""
    text = (value or "").strip() or default
    return text if text.startswith("/") else "/" + text


def _xhttp_extra(raw):
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def vless_to_outbound(info):
    """xhttp and httpupgrade handled below"""
    p = info["params"]
    network = p.get("type", "tcp")
    if network == "raw":
        network = "tcp"
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
            "spiderX": _path_value(p.get("spx"), "/"),
        }
    if network == "ws":
        stream["wsSettings"] = {
            "path": _path_value(p.get("path"), "/"),
            "headers": {"Host": p.get("host", info["host"])},
        }
    elif network == "grpc":
        # Authority and Host name the server, not the address: with a pinned IP, Xray would
        # otherwise send the IP as Host/:authority (wrong behind CDNs).
        stream["grpcSettings"] = {
            "serviceName": p.get("serviceName", ""),
            "authority": p.get("authority") or p.get("host") or p.get("sni") or info["host"],
        }
    elif network == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {
                "headers": {"Host": [p.get("host", info["host"])]}
            }}
        }
    elif network == "xhttp":
        settings = {
            "path": _path_value(p.get("path"), "/"),
            "host": p.get("host") or p.get("sni") or info["host"],
        }
        mode = p.get("mode", "")
        if mode in XHTTP_MODES:
            settings["mode"] = mode
        extra = _xhttp_extra(p.get("extra"))
        for key in ("xPaddingBytes", "scMaxEachPostBytes", "noGRPCHeader"):
            if key in extra:
                settings[key] = extra[key]
        stream["xhttpSettings"] = settings
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": _path_value(p.get("path"), "/"),
            "host": p.get("host", info["host"]),
        }
    elif network == "kcp":
        stream["kcpSettings"] = {"header": {"type": p.get("headerType", "none")}}
    return {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": info.get("connect_host", info["host"]), "port": info["port"],
            "users": [user],
        }]},
        "streamSettings": stream,
    }



def _port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _wait_socks(port, proc, stop_event=None, timeout=XRAY_START_TIMEOUT):
    """Wait until the local SOCKS port accepts. False on death, timeout or cancel."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return False
        if proc.poll() is not None:
            return False
        if _port_open(port):
            return True
        time.sleep(0.05)
    return proc.poll() is None and _port_open(port)


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_xray(info, stop_event=None):
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
    if not _wait_socks(port, proc, stop_event):
        _stop_xray(proc, fh.name)
        raise RuntimeError("xray failed to start")
    proxy = "socks5h://127.0.0.1:%d" % port
    return proc, fh.name, {"http": proxy, "https": proxy}


def _stop_xray(proc, path):
    if proc is not None and proc.poll() is None:
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


def _acquire_xray_slot(stop_event):
    """Wait for a global Xray slot; only a stop request cancels the wait.

    Slots are always released in finally, so the wait ends when another check
    finishes. A deadline here would turn a busy slot into a fake xray_failed.
    """
    while True:
        if stop_event is not None and stop_event.is_set():
            return False
        if XRAY_SLOTS.acquire(timeout=0.2):
            return True


def _download_bytes(url, proxies, timeout, stop_event, min_bytes):
    """Stream up to min_bytes and always close the response."""
    resp = None
    try:
        start = time.time()
        resp = requests.get(
            url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS, stream=True,
        )
        if resp.status_code not in (200, 204):
            return False
        size = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if stop_event is not None and stop_event.is_set():
                return False
            if chunk:
                size += len(chunk)
            if size >= min_bytes or time.time() - start > timeout:
                break
        return size >= min_bytes
    except Exception:
        return False
    finally:
        if resp is not None:
            resp.close()


def check_xray(info, test_url=DEFAULT_TEST_URL, timeout=8, stop_event=None,
               download_url=VALIDATION_DOWNLOAD_URL, min_success=VALIDATION_MIN_SUCCESS,
               min_bytes=VALIDATION_MIN_BYTES):
    if not XRAY_BIN or not _acquire_xray_slot(stop_event):
        return None
    proc = None
    path = None
    try:
        proc, path, proxies = _start_xray(info, stop_event)
        urls = []
        for url in [test_url] + VALIDATION_URLS:
            if url and url not in urls:
                urls.append(url)
        successes = 0
        best_ping = None
        for url in urls:
            if stop_event is not None and stop_event.is_set():
                return None
            resp = None
            try:
                start = time.time()
                resp = requests.get(
                    url, proxies=proxies, timeout=timeout, headers=HTTP_HEADERS,
                )
                if resp.status_code in (200, 204):
                    successes += 1
                    ping = int((time.time() - start) * 1000)
                    best_ping = ping if best_ping is None else min(best_ping, ping)
                    if successes >= min_success:
                        break
            except Exception:
                continue
            finally:
                if resp is not None:
                    resp.close()
        if successes < min_success:
            return None
        if not download_url or min_bytes <= 0:
            return best_ping
        return best_ping if _download_bytes(
            download_url, proxies, timeout, stop_event, min_bytes,
        ) else None
    except Exception:
        return None
    finally:
        _stop_xray(proc, path)
        XRAY_SLOTS.release()


def check_speed(info, urls=None, timeout=12, stop_event=None):
    """Measure speed. One answering URL is enough."""
    if isinstance(urls, str):
        urls = [urls]
    urls = [url for url in (urls or [DEFAULT_SPEED_URL]) if url]
    if not XRAY_BIN or not urls or not _acquire_xray_slot(stop_event):
        return None
    proc = None
    path = None
    try:
        proc, path, proxies = _start_xray(info, stop_event)
        for url in urls:
            if stop_event is not None and stop_event.is_set():
                return None
            resp = None
            try:
                start = time.time()
                resp = requests.get(
                    url, proxies=proxies, timeout=timeout,
                    headers=HTTP_HEADERS, stream=True,
                )
                if resp.status_code not in (200, 204):
                    continue
                size = 0
                for chunk in resp.iter_content(65536):
                    if stop_event is not None and stop_event.is_set():
                        return None
                    if chunk:
                        size += len(chunk)
                    # A large speed_url must not hold the Xray slot for minutes.
                    if size >= SPEED_MAX_BYTES or time.time() - start > timeout:
                        break
                elapsed = max(time.time() - start, 0.001)
                if size:
                    return round(size * 8 / elapsed / 1_000_000, 2)
            except Exception:
                continue
            finally:
                if resp is not None:
                    resp.close()
        return None
    except Exception:
        return None
    finally:
        _stop_xray(proc, path)
        XRAY_SLOTS.release()



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
