import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait

import checker
import store


TERMINAL_STATES = {"completed", "stopped", "failed"}


def public_result(item):
    info = item["info"]
    p = info["params"]
    return {
        "key": info["raw"],
        "name": info["name"] or f"{info['host']}:{info['port']}",
        "host": info["host"],
        "port": info["port"],
        "security": p.get("security", "none"),
        "network": p.get("type", "tcp"),
        "sni": p.get("sni") or p.get("host") or "",
        "country": info.get("country", ""),
        "ping": item.get("ping"),
        "speed": item.get("speed"),
        "score": item["score"],
    }


class Job:
    def __init__(self, cfg):
        self.id = uuid.uuid4().hex
        self.cfg = cfg
        self.created = time.time()
        self.state = "queued"
        self.message = "Задание создано"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.events = []
        self.results = []
        self.total = 0
        self.checked = 0
        self.counters = {
            "tcp_failed": 0, "tls_failed": 0, "xray_failed": 0, "found": 0,
            "geo_total": 0, "geo_done": 0, "geo_matched": 0, "geo_unknown": 0,
        }
        self.tcp_cache = checker.CheckCache()
        self.tls_cache = checker.CheckCache()
        self.emit("created", {"message": self.message})

    def emit(self, kind, data=None):
        with self.lock:
            event = {
                "id": len(self.events) + 1,
                "type": kind,
                "data": data or {},
                "ts": time.time(),
            }
            self.events.append(event)
            if len(self.events) > 10000:
                self.events = self.events[-8000:]
            return event

    def set_state(self, state, message):
        with self.lock:
            self.state = state
            self.message = message
        self.emit("state", {"state": state, "message": message})

    def snapshot(self):
        with self.lock:
            return {
                "id": self.id,
                "state": self.state,
                "message": self.message,
                "created": self.created,
                "target": self.cfg["count"],
                "total": self.total,
                "checked": self.checked,
                "counters": dict(self.counters),
                "results": [public_result(item) for item in self.results],
                "xray": bool(checker.XRAY_BIN),
            }

    def events_after(self, event_id):
        with self.lock:
            return [event for event in self.events if event["id"] > event_id]

    def stop(self):
        self.stop_event.set()
        self.emit("stopping", {"message": "Останавливаю новые проверки"})

    def _load(self):
        if self.cfg["source"] == "custom":
            return checker.parse_text(self.cfg.get("text", ""))
        counts = {}

        def report(url, count):
            counts[url] = count
            self.emit("source", {"source": url.rsplit("/", 1)[-1], "count": count})

        infos = checker.load_sources(report)
        store.save_source_counts(counts)
        return infos

    def _check_one(self, info):
        if self.stop_event.is_set():
            return "stopped", None
        host = info["host"]
        port = info["port"]
        tcp_key = (host, port)
        tcp = self.tcp_cache.get(tcp_key, lambda: checker.check_tcp(host, port))
        if tcp is None:
            return "tcp_failed", None
        p = info["params"]
        security = p.get("security", "none")
        if security in ("tls", "reality"):
            sni = p.get("sni") or p.get("host") or host
            tls_key = (host, port, sni)
            tls = self.tls_cache.get(tls_key, lambda: checker.check_tls(host, port, sni))
            if tls is None:
                return "tls_failed", None
        if self.stop_event.is_set():
            return "stopped", None
        ping = tcp
        if self.cfg["enable_xray"]:
            ping = checker.check_xray(info, self.cfg["test_url"])
            if ping is None:
                return "xray_failed", None
        item = {"info": info, "ping": ping, "speed": None}
        item["score"] = checker.score(info, ping)
        return "found", item

    def _filter_countries(self, infos):
        selected = set(self.cfg["filters"].get("countries") or [])
        excluded = set(self.cfg["filters"].get("excluded_countries") or [])
        if not selected and not excluded:
            return infos
        self.set_state("geolocating", "Определяю IP и страны серверов")

        def report(stage, done, total, resolved):
            with self.lock:
                self.counters["geo_done"] = done
                self.counters["geo_total"] = total
            self.emit("geo_progress", {
                "stage": stage, "done": done, "total": total, "resolved": resolved,
            })

        host_ip = checker.resolve_hosts(
            [info["host"] for info in infos], report=report,
            stop_event=self.stop_event,
        )
        ips = list(dict.fromkeys(host_ip.values()))
        cached = store.get_geo(ips)
        with self.lock:
            self.counters["geo_done"] = len(cached)
            self.counters["geo_total"] = len(ips)
        countries = checker.lookup_ip_countries(
            ips, cached=cached, save=store.save_geo, report=report,
            stop_event=self.stop_event,
        )
        out = []
        unknown = 0
        for info in infos:
            country = countries.get(host_ip.get(info["host"], ""), "")
            allowed = country not in excluded and (not selected or country in selected)
            if allowed:
                info["country"] = country
                out.append(info)
            if not country:
                unknown += 1
        with self.lock:
            self.counters["geo_matched"] = len(out)
            self.counters["geo_unknown"] = unknown
        self.emit("geo_complete", {
            "selected": sorted(selected), "excluded": sorted(excluded), "matched": len(out),
            "unknown": unknown, "before": len(infos),
        })
        return out

    def _measure_speed(self):
        self.set_state("measuring", "Ключи готовы, измеряю скорость")
        with ThreadPoolExecutor(max_workers=min(4, self.cfg["workers"])) as ex:
            fmap = {
                ex.submit(checker.check_speed, item["info"], self.cfg["speed_url"]): item
                for item in self.results
            }
            for fut in as_completed(fmap):
                if self.stop_event.is_set():
                    break
                item = fmap[fut]
                item["speed"] = fut.result()
                item["score"] = checker.score(item["info"], item["ping"], item["speed"])
                store.save_result(item)
                self.emit("result_updated", public_result(item))

    def run(self):
        try:
            self.set_state("loading", "Загружаю и разбираю ключи")
            infos = self._load()
            filters = self.cfg["filters"]
            infos = checker.filter_infos(
                infos,
                security=filters["security"],
                only_tcp=filters["only_tcp"],
                require_sni=filters["require_sni"],
                exclude_ws=filters["exclude_ws"],
            )
            infos = self._filter_countries(infos)
            if self.stop_event.is_set():
                self.set_state("stopped", "Остановлено во время определения стран")
                return
            infos = checker.shuffle_infos(infos, store.preferred_keys())
            max_checks = self.cfg.get("max_checks")
            if max_checks is not None:
                infos = infos[:max_checks]
            with self.lock:
                self.total = len(infos)
            self.emit("loaded", {"total": len(infos)})
            if not infos:
                self.set_state("failed", "После загрузки и фильтров ключей не осталось")
                return
            self.set_state("running", "Проверяю каждый ключ через полный каскад")
            iterator = iter(infos)
            pending = set()
            executor = ThreadPoolExecutor(max_workers=self.cfg["workers"])
            try:
                for _ in range(min(self.cfg["workers"], len(infos))):
                    pending.add(executor.submit(self._check_one, next(iterator)))
                while pending and not self.stop_event.is_set():
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for fut in done:
                        stage, item = fut.result()
                        with self.lock:
                            self.checked += 1
                            if stage != "found" and stage in self.counters:
                                self.counters[stage] += 1
                        if stage == "found" and item is not None:
                            accept = False
                            with self.lock:
                                if len(self.results) < self.cfg["count"]:
                                    self.results.append(item)
                                    self.counters["found"] += 1
                                    accept = True
                            if accept:
                                store.save_result(item)
                                self.emit("key_found", public_result(item))
                        self.emit("progress", self.snapshot())
                    if len(self.results) >= self.cfg["count"]:
                        break
                    for _ in range(len(done)):
                        try:
                            pending.add(executor.submit(self._check_one, next(iterator)))
                        except StopIteration:
                            break
                for fut in pending:
                    fut.cancel()
            finally:
                executor.shutdown(wait=True, cancel_futures=True)
            if self.stop_event.is_set():
                self.set_state("stopped", f"Остановлено, найдено ключей: {len(self.results)}")
                return
            if self.cfg["speed"] and self.results and checker.XRAY_BIN:
                self._measure_speed()
            found = len(self.results)
            if found >= self.cfg["count"]:
                self.set_state("completed", f"Найдено {found} ключей")
            else:
                self.set_state("completed", f"Проверка завершена: найдено {found} из {self.cfg['count']}")
        except Exception as exc:
            self.set_state("failed", f"Ошибка задания: {exc}")


class Jobs:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = {}

    def create(self, cfg):
        job = Job(cfg)
        with self.lock:
            self.items[job.id] = job
        threading.Thread(target=job.run, daemon=True).start()
        return job

    def get(self, job_id):
        with self.lock:
            return self.items.get(job_id)


jobs = Jobs()
