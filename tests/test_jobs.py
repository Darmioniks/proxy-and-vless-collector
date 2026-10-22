import os
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import checker
import store
from jobs import Job


class JobTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old_db = store.DB_FILE
        store.DB_FILE = os.path.join(self.dir.name, "test.db")
        store.init_db()

    def tearDown(self):
        store.DB_FILE = self.old_db
        self.dir.cleanup()

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_xray_starts_without_console_window(self):
        with patch("checker.XRAY_BIN", "xray.exe"), \
                patch("checker.vless_to_outbound", return_value={}), \
                patch("checker.subprocess.Popen") as popen, \
                patch("checker._wait_socks", return_value=True):
            _, path, _ = checker._start_xray({})

        try:
            self.assertEqual(
                popen.call_args.kwargs["creationflags"],
                subprocess.CREATE_NO_WINDOW,
            )
        finally:
            os.unlink(path)

    @staticmethod
    def cfg(text, count, workers=4):
        return {
            "count": count,
            "source": "custom",
            "text": text,
            "workers": workers,
            "max_checks": 100,
            "enable_xray": False,
            "speed": False,
            "test_url": checker.DEFAULT_TEST_URL,
            "speed_url": checker.DEFAULT_SPEED_URL,
            "filters": {
                "security": "any",
                "only_tcp": False,
                "require_sni": False,
                "exclude_ws": False,
            },
        }

    def test_stops_scheduling_after_target(self):
        keys = "\n".join(
            f"vless://00000000-0000-0000-0000-{i:012d}@host{i}.example:443"
            f"?security=none&type=tcp#K{i}"
            for i in range(20)
        )
        calls = 0
        lock = threading.Lock()

        def tcp(*args, **kwargs):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.01)
            return 20

        with patch("checker.check_tcp", side_effect=tcp):
            job = Job(self.cfg(keys, count=3))
            job.run()

        self.assertEqual(job.state, "completed")
        self.assertEqual(len(job.results), 3)
        self.assertLessEqual(calls, 20)

    def test_tcp_is_cached_for_same_endpoint(self):
        keys = "\n".join(
            f"vless://11111111-1111-1111-1111-{i:012d}@same.example:443"
            f"?security=none&type=tcp#S{i}"
            for i in range(2)
        )
        with patch("checker.check_tcp", return_value=20) as tcp:
            job = Job(self.cfg(keys, count=2, workers=2))
            job.run()

        self.assertEqual(len(job.results), 2)
        self.assertEqual(tcp.call_count, 1)

    def test_country_filter_runs_before_cascade(self):
        keys = "\n".join([
            "vless://11111111-1111-1111-1111-111111111111@ru.example:443"
            "?security=none&type=tcp#RU",
            "vless://22222222-2222-2222-2222-222222222222@de.example:443"
            "?security=none&type=tcp#DE",
        ])
        cfg = self.cfg(keys, count=1, workers=2)
        cfg["filters"]["countries"] = ["RU"]
        host_ip = {"ru.example": "1.1.1.1", "de.example": "2.2.2.2"}
        countries = {"1.1.1.1": "RU", "2.2.2.2": "DE"}

        with patch("checker.resolve_hosts", return_value=host_ip), \
                patch("checker.lookup_ip_countries", return_value=countries), \
                patch("checker.check_tcp", return_value=20) as tcp:
            job = Job(cfg)
            job.run()

        self.assertEqual(job.state, "completed")
        self.assertEqual(len(job.results), 1)
        self.assertEqual(job.results[0]["info"]["country"], "RU")
        self.assertEqual(job.counters["geo_matched"], 1)
        self.assertEqual(tcp.call_count, 1)

    def test_excluded_country_is_removed_before_cascade(self):
        keys = "\n".join([
            "vless://11111111-1111-1111-1111-111111111111@ru.example:443"
            "?security=none&type=tcp#RU",
            "vless://22222222-2222-2222-2222-222222222222@de.example:443"
            "?security=none&type=tcp#DE",
            "vless://33333333-3333-3333-3333-333333333333@unknown.example:443"
            "?security=none&type=tcp#Unknown",
        ])
        cfg = self.cfg(keys, count=3, workers=3)
        cfg["filters"]["excluded_countries"] = ["DE"]
        host_ip = {
            "ru.example": "1.1.1.1",
            "de.example": "2.2.2.2",
            "unknown.example": "3.3.3.3",
        }
        countries = {"1.1.1.1": "RU", "2.2.2.2": "DE"}

        with patch("checker.resolve_hosts", return_value=host_ip), \
                patch("checker.lookup_ip_countries", return_value=countries), \
                patch("checker.check_tcp", return_value=20) as tcp:
            job = Job(cfg)
            job.run()

        self.assertEqual(len(job.results), 2)
        self.assertEqual({item["info"]["name"] for item in job.results}, {"RU", "Unknown"})
        self.assertEqual(tcp.call_count, 2)

    def test_unlimited_checks_processes_all_candidates(self):
        keys = "\n".join(
            f"vless://44444444-4444-4444-4444-{i:012d}@host{i}.example:443"
            f"?security=none&type=tcp#K{i}"
            for i in range(12)
        )
        cfg = self.cfg(keys, count=100, workers=4)
        cfg["max_checks"] = None

        with patch("checker.check_tcp", return_value=None) as tcp:
            job = Job(cfg)
            job.run()

        self.assertEqual(job.state, "completed")
        self.assertEqual(job.checked, 12)
        self.assertEqual(tcp.call_count, 12)

    def test_geo_cache_is_persistent(self):
        store.save_geo({"1.1.1.1": "AU", "8.8.8.8": "US"})
        self.assertEqual(
            store.get_geo(["8.8.8.8", "1.1.1.1"]),
            {"1.1.1.1": "AU", "8.8.8.8": "US"},
        )

    def test_working_recheck_removes_only_failed_snapshot_keys(self):
        good = (
            "vless://11111111-1111-1111-1111-111111111111@good.example:443"
            "?security=none&type=tcp#Good"
        )
        bad = (
            "vless://22222222-2222-2222-2222-222222222222@bad.example:443"
            "?security=none&type=tcp#Bad"
        )
        for raw in (good, bad):
            info = checker.parse_vless(raw)
            store.save_result({"info": info, "ping": 20, "speed": None, "score": 75})

        cfg = self.cfg(f"{good}\n{bad}", count=2, workers=2)
        cfg["max_checks"] = None
        cfg["prune_working"] = True
        cfg["working_snapshot"] = [good, bad]
        with patch("checker.check_tcp", side_effect=lambda host, port: 20 if host == "good.example" else None):
            job = Job(cfg)
            job.run()

        self.assertEqual(job.state, "completed")
        self.assertEqual(store.working_keys(), [good])
        self.assertIn("удалено 1", job.message)

    def test_stopped_working_recheck_does_not_delete_keys(self):
        raw = (
            "vless://33333333-3333-3333-3333-333333333333@one.example:443"
            "?security=none&type=tcp#One"
        )
        info = checker.parse_vless(raw)
        store.save_result({"info": info, "ping": 20, "speed": None, "score": 75})
        cfg = self.cfg(raw, count=1)
        cfg["prune_working"] = True
        cfg["working_snapshot"] = [raw]
        job = Job(cfg)
        job.stop()
        job.run()

        self.assertEqual(job.state, "stopped")
        self.assertEqual(store.working_keys(), [raw])


    def test_reality_skips_python_tls_probe(self):
        raw = (
            "vless://11111111-1111-1111-1111-111111111111@real.example:443"
            "?security=reality&type=tcp&sni=www.microsoft.com&pbk=pub&sid=ab#R"
        )
        with patch("checker.check_tcp", return_value=20),                 patch("checker.check_tls") as tls,                 patch("checker.check_xray", return_value=30):
            cfg = self.cfg(raw, count=1)
            cfg["enable_xray"] = True
            job = Job(cfg)
            job.run()
        tls.assert_not_called()
        self.assertEqual(len(job.results), 1)

    def test_private_address_is_dropped_before_tcp(self):
        raw = (
            "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443"
            "?security=none&type=tcp#local"
        )
        with patch("checker.check_tcp") as tcp:
            job = Job(self.cfg(raw, count=1))
            job.run()
        tcp.assert_not_called()
        self.assertEqual(job.results, [])

    def test_name_fragment_does_not_duplicate_checks(self):
        base = (
            "vless://11111111-1111-1111-1111-111111111111@dup.example:443"
            "?security=none&type=tcp#"
        )
        with patch("checker.check_tcp", return_value=20) as tcp:
            job = Job(self.cfg((base + "one") + chr(10) + (base + "two"), count=2))
            job.run()
        self.assertEqual(tcp.call_count, 1)
        self.assertEqual(len(job.results), 1)

    def test_event_ids_keep_growing_after_trim(self):
        job = Job(self.cfg("", count=1))
        for _ in range(10001):
            job.emit("progress", {"n": 1})
        ids = [event["id"] for event in job.events]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(ids[0], 1)
        last = ids[-1]
        job.emit("state", {"state": "completed"})
        self.assertEqual(job.events[-1]["id"], last + 1)
        replay = job.events_after(last - 1)
        self.assertEqual(replay[-1]["type"], "state")

    def test_finished_jobs_expire(self):
        from jobs import jobs as registry
        job = Job(self.cfg(
            "vless://11111111-1111-1111-1111-111111111111@gone.example:443"
            "?security=none&type=tcp#g", count=1))
        job.finished_at = time.time() - 10**7
        registry.items[job.id] = job
        self.assertIsNone(registry.get(job.id))

    def test_finished_state_and_its_event_are_seen_together(self):
        job = Job(self.cfg("", count=1))
        job.set_state("completed", "done")
        events, finished = job.poll(0)
        self.assertTrue(finished)
        self.assertEqual(events[-1]["type"], "state")
        self.assertEqual(events[-1]["data"]["state"], "completed")

if __name__ == "__main__":
    unittest.main()
