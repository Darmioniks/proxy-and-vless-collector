import os
import tempfile
import threading
import unittest
from unittest.mock import patch

import checker
import filter_vless


UUID = "11111111-1111-1111-1111-111111111111"


def key(query, host="good.example", port=443, name="name"):
    return "vless://%s@%s:%d?%s#%s" % (UUID, host, port, query, name)


class ProbeTest(unittest.TestCase):
    def info(self, query, host="good.example"):
        return checker.parse_vless(key(query, host=host))

    def test_private_host_is_dropped_before_tcp(self):
        with patch("filter_vless.checker.check_tcp") as tcp:
            result = filter_vless.probe(
                self.info("security=none&type=tcp", host="10.0.0.5"),
                checker.CheckCache(), checker.CheckCache(),
            )
        self.assertIsNone(result)
        tcp.assert_not_called()

    def test_reality_is_not_tls_probed(self):
        query = "security=reality&type=tcp&sni=a.com&pbk=pub"
        with patch("filter_vless.checker.check_tcp", return_value=5), \
                patch("filter_vless.checker.check_tls", return_value=None) as tls:
            result = filter_vless.probe(self.info(query), checker.CheckCache(), checker.CheckCache())
        self.assertIsNotNone(result)
        tls.assert_not_called()

    def test_tls_handshake_failure_drops_key(self):
        query = "security=tls&type=tcp&sni=a.com"
        with patch("filter_vless.checker.check_tcp", return_value=5), \
                patch("filter_vless.checker.check_tls", return_value=None):
            result = filter_vless.probe(self.info(query), checker.CheckCache(), checker.CheckCache())
        self.assertIsNone(result)


class DedupeTest(unittest.TestCase):
    def test_name_fragment_does_not_create_second_key(self):
        text = "\n".join([
            key("security=none&type=tcp", name="first"),
            key("security=none&type=tcp", name="second"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vless.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            infos = filter_vless.load_infos(path)
        self.assertEqual(len(infos), 1)


class PoolTest(unittest.TestCase):
    def test_run_pool_stops_at_limit(self):
        stop = threading.Event()
        kept = filter_vless.run_pool(
            list(range(10)), lambda item: item, workers=1, stop=stop, limit=2,
        )
        self.assertEqual(len(kept), 2)
        self.assertTrue(stop.is_set())

    def test_run_pool_keeps_only_non_none(self):
        stop = threading.Event()
        kept = filter_vless.run_pool(
            [1, 2, 3, 4], lambda item: item if item % 2 else None, workers=2, stop=stop,
        )
        self.assertEqual(sorted(kept), [1, 3])
        self.assertFalse(stop.is_set())


if __name__ == "__main__":
    unittest.main()
