"""
Headless-фильтр VLESS-ключей для GitHub Actions.

Использует те же правила, что и приложение (checker.py, см. jobs.py):
    0) разбор и валидация ключей, дедупликация без фрагмента #name
    1) отсев приватных адресов, TCP по host:port с кэшем
    2) TLS-handshake только для security=tls; Reality проверяется Xray
    3) Xray: два успешных ответа и загрузка минимум 256 КБ, с ранней остановкой

Пишет лучшие ключи, прошедшие все этапы, в файл выхода (по убыванию score).

Запуск:
    python filter_vless.py --input vless.txt --output vless_filtered.txt --count 100
Нужен бинарь xray в PATH или рядом с checker.py.
"""

import argparse
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import checker


# Дешёвые TCP/TLS-проверки идут широким пулом, Xray — по числу слотов приложения.
PROBE_WORKERS = 64
XRAY_WORKERS = 8


def load_infos(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        infos = checker.parse_text(fh.read())
    seen = {}
    for info in infos:
        seen.setdefault(checker.key_identity(info), info)
    return list(seen.values())


def probe(info, tcp_cache, tls_cache):
    """Returns info if the server accepts TCP (and TLS for security=tls)."""
    host = info["host"]
    port = info["port"]
    if checker.is_private_host(host):
        return None
    if tcp_cache.get((host, port), lambda: checker.check_tcp(host, port)) is None:
        return None
    p = info["params"]
    if p.get("security", "none") == "tls":
        sni = p.get("sni") or p.get("host") or host
        if tls_cache.get((host, port, sni), lambda: checker.check_tls(host, port, sni)) is None:
            return None
    return info


def xray_check(info, test_url, stop):
    ping = checker.check_xray(info, test_url, stop_event=stop)
    if ping is None:
        return None
    return {"info": info, "ping": ping, "score": checker.score(info, ping)}


def run_pool(items, fn, workers, stop, limit=None):
    """Apply fn to items in parallel and keep non-None results.

    Once `limit` results are kept, stop is set and pending items are cancelled.
    """
    kept = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fn, item) for item in items]
        for fut in as_completed(futures):
            result = fut.result()
            if result is None:
                continue
            kept.append(result)
            if limit and len(kept) >= limit:
                stop.set()
                for pending in futures:
                    pending.cancel()
                break
    return kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="vless.txt")
    ap.add_argument("--output", default="vless_filtered.txt")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--test-url", default=checker.DEFAULT_TEST_URL)
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] файл {args.input} не найден", file=sys.stderr)
        sys.exit(1)
    if not checker.XRAY_BIN:
        print("[!] xray не найден: проверка без Xray не публикуется", file=sys.stderr)
        sys.exit(1)
    probe_run = subprocess.run([checker.XRAY_BIN, "version"], capture_output=True, timeout=10)
    if probe_run.returncode != 0:
        err = probe_run.stderr.decode(errors="ignore")[:200]
        print(f"[!] xray не запускается: {err}", file=sys.stderr)
        sys.exit(1)

    infos = load_infos(args.input)
    print(f"[*] уникальных VLESS-ключей: {len(infos)}")
    if not infos:
        print("[!] нечего проверять", file=sys.stderr)
        sys.exit(1)

    stop = threading.Event()
    tcp_cache = checker.CheckCache()
    tls_cache = checker.CheckCache()

    print(f"[1/2] TCP/TLS: проверяем {len(infos)} ключей...")
    survivors = run_pool(
        infos, lambda info: probe(info, tcp_cache, tls_cache), PROBE_WORKERS, stop,
    )
    print(f"[1/2] TCP/TLS: прошли {len(survivors)} ключей")

    print(f"[2/2] Xray: нужно {args.count} рабочих ключей (ранняя остановка)...")
    found = run_pool(
        survivors, lambda info: xray_check(info, args.test_url, stop),
        XRAY_WORKERS, stop, limit=args.count,
    )
    if not found:
        # Пустой результат не должен затирать уже опубликованный список,
        # а временная недоступность источников не должна краснить CI.
        print("[!] рабочих ключей не найдено, файл не изменён")
        return

    found.sort(key=lambda item: (-item["score"], item["ping"]))
    with open(args.output, "w", encoding="utf-8") as fh:
        for item in found:
            fh.write(item["info"]["raw"] + "\n")
    print(f"[✓] записано {len(found)} ключей в {args.output}")


if __name__ == "__main__":
    main()
