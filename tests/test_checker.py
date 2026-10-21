import json
import threading
import time
import unittest
from unittest.mock import patch

import checker


UUID = "11111111-1111-1111-1111-111111111111"


def key(query, host="good.example", port=443):
    return "vless://%s@%s:%d?%s#name" % (UUID, host, port, query)


class ParseTest(unittest.TestCase):
    def test_reality_requires_pbk_and_sni(self):
        self.assertIsNone(checker.parse_vless(key("security=reality&type=tcp&sni=a.com")))
        info = checker.parse_vless(key("security=reality&type=tcp&sni=a.com&pbk=pub"))
        self.assertIsNotNone(info)

    def test_rejects_bad_uuid_port_and_transport(self):
        self.assertIsNone(checker.parse_vless(key("security=none&type=tcp").replace(UUID, "not-a-uuid")))
        self.assertIsNone(checker.parse_vless(key("security=none&type=tcp", port=70000)))
        self.assertIsNone(checker.parse_vless(key("security=none&type=tcp<br/>")))
        garbage = "vless://%s@host.example:443?type=tcp&security=none#<b>x</b>" % UUID
        # html in the fragment is fine, html in the transport is not
        self.assertIsNotNone(checker.parse_vless(garbage))

    def test_private_hosts_are_detected(self):
        for host in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
                     "169.254.1.1", "::1", "localhost"):
            self.assertTrue(checker.is_private_host(host), host)
        self.assertFalse(checker.is_private_host("1.1.1.1"))

    def test_xhttp_and_httpupgrade_reach_outbound(self):
        extra = json.dumps({"xPaddingBytes": "100-1000"})
        import urllib.parse
        xhttp = checker.parse_vless(key(
            "security=tls&type=xhttp&path=%2Fapi&host=cdn.example&mode=stream-one&extra="
            + urllib.parse.quote(extra)
        ))
        stream = checker.vless_to_outbound(xhttp)["streamSettings"]
        self.assertEqual(stream["xhttpSettings"]["path"], "/api")
        self.assertEqual(stream["xhttpSettings"]["host"], "cdn.example")
        self.assertEqual(stream["xhttpSettings"]["mode"], "stream-one")
        self.assertEqual(stream["xhttpSettings"]["xPaddingBytes"], "100-1000")

        upgrade = checker.parse_vless(key("security=none&type=httpupgrade&path=%2Fup&host=h.example"))
        settings = checker.vless_to_outbound(upgrade)["streamSettings"]["httpupgradeSettings"]
        self.assertEqual(settings, {"path": "/up", "host": "h.example"})

    def test_identity_ignores_name_fragment(self):
        a = checker.parse_vless(key("security=none&type=tcp") + "one")
        b = checker.parse_vless(key("security=none&type=tcp") + "two")
        self.assertEqual(checker.key_identity(a), checker.key_identity(b))

    def test_ipv6_and_idn_hosts(self):
        info = checker.parse_vless("vless://%s@[2001:db8::1]:8443?security=none&type=tcp" % UUID)
        self.assertEqual((info["host"], info["port"]), ("2001:db8::1", 8443))
        idn = checker.parse_vless(key("security=none&type=tcp", host="пример.рф"))
        self.assertTrue(idn["host"].startswith("xn--"))

    def test_responses_are_closed(self):
        closed = []

        class Resp:
            status_code = 204
            def close(self):
                closed.append(1)
            def iter_content(self, chunk_size):
                yield b"x" * 300000

        with patch.object(checker, "XRAY_BIN", "xray"),                 patch("checker._start_xray", return_value=(None, None, {})),                 patch("checker._stop_xray"),                 patch("checker.requests.get", return_value=Resp()):
            checker.check_xray({"params": {}}, min_bytes=1)
        self.assertGreaterEqual(len(closed), 1)

    def test_cancel_releases_slot_and_stops_process(self):
        event = threading.Event()
        event.set()
        killed = []

        class Proc:
            def poll(self):
                return None
            def terminate(self):
                killed.append("term")
            def wait(self, timeout=None):
                return 0
            def kill(self):
                killed.append("kill")

        with patch.object(checker, "XRAY_BIN", "xray"),                 patch("checker._start_xray", return_value=(Proc(), "cfg.json", {})),                 patch("checker._stop_xray", side_effect=lambda proc, path: proc.terminate()):
            result = checker.check_xray({}, stop_event=event, min_success=1, min_bytes=0)
        self.assertIsNone(result)
        self.assertTrue(checker.XRAY_SLOTS.acquire(timeout=1))
        checker.XRAY_SLOTS.release()


if __name__ == "__main__":
    unittest.main()
