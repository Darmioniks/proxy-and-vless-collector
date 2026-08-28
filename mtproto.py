import random
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import checker


SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/main/proxy.txt",
]

LINK_PATTERN = re.compile(r"(?:tg://proxy|https://t\.me/proxy)\?[^\s<>\"']+")


def parse_link(raw):
    link = raw.strip().rstrip(".,);]")
    if not link.startswith(("tg://proxy?", "https://t.me/proxy?")):
        return None
    try:
        query = urllib.parse.urlparse(link).query
        params = urllib.parse.parse_qs(query)
        host = params.get("server", [""])[0].strip()
        port = int(params.get("port", [0])[0])
        secret = params.get("secret", [""])[0].strip()
    except (TypeError, ValueError):
        return None
    if not host or not secret or not 1 <= port <= 65535:
        return None
    telegram = "tg://proxy?" + urllib.parse.urlencode({
        "server": host,
        "port": port,
        "secret": secret,
    })
    return {"url": telegram, "host": host, "port": port}


def extract_links(text):
    return [item for raw in LINK_PATTERN.findall(text) if (item := parse_link(raw))]


def load_source(url, timeout=12):
    response = requests.get(url, timeout=timeout, headers=checker.HTTP_HEADERS)
    response.raise_for_status()
    return extract_links(response.text)


def scan(limit=80, workers=100):
    source_counts = {}
    candidates = []
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        futures = {executor.submit(load_source, url): url for url in SOURCES}
        for future in as_completed(futures):
            url = futures[future]
            try:
                items = future.result()
            except requests.RequestException:
                items = []
            source_counts[url] = len(items)
            candidates.extend(items)

    unique = {}
    for item in candidates:
        unique.setdefault((item["host"], item["port"]), item)
    candidates = list(unique.values())
    random.shuffle(candidates)
    subset = candidates[:limit]

    working = []
    if subset:
        with ThreadPoolExecutor(max_workers=min(workers, len(subset))) as executor:
            futures = {
                executor.submit(checker.check_tcp, item["host"], item["port"]): item
                for item in subset
            }
            for future in as_completed(futures):
                ping = future.result()
                if ping is not None:
                    item = dict(futures[future])
                    item["ping"] = ping
                    working.append(item)
    working.sort(key=lambda item: item["ping"])
    return {
        "sources": source_counts,
        "total": len(candidates),
        "tested": len(subset),
        "working": working,
    }
