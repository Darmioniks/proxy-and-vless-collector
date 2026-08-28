import unittest
from unittest.mock import Mock, patch

import mtproto


class MtprotoTest(unittest.TestCase):
    def test_parse_link_accepts_telegram_formats(self):
        first = mtproto.parse_link("tg://proxy?server=one.example&port=443&secret=abc")
        second = mtproto.parse_link("https://t.me/proxy?server=two.example&port=8443&secret=def")

        self.assertEqual((first["host"], first["port"]), ("one.example", 443))
        self.assertEqual((second["host"], second["port"]), ("two.example", 8443))
        self.assertTrue(second["url"].startswith("tg://proxy?"))

    def test_parse_link_rejects_missing_secret(self):
        self.assertIsNone(mtproto.parse_link("tg://proxy?server=one.example&port=443"))

    def test_scan_deduplicates_endpoint_and_sorts_working(self):
        responses = {
            url: Mock(
                text=(
                    "tg://proxy?server=one.example&port=443&secret=abc\n"
                    "https://t.me/proxy?server=two.example&port=8443&secret=def\n"
                ),
                raise_for_status=Mock(),
            )
            for url in mtproto.SOURCES
        }

        def get(url, **kwargs):
            return responses[url]

        def tcp(host, port):
            return {"one.example": 45, "two.example": 20}[host]

        with patch("mtproto.requests.get", side_effect=get), \
                patch("mtproto.checker.check_tcp", side_effect=tcp), \
                patch("mtproto.random.shuffle"):
            result = mtproto.scan(limit=10, workers=2)

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["tested"], 2)
        self.assertEqual([item["host"] for item in result["working"]], [
            "two.example", "one.example",
        ])


if __name__ == "__main__":
    unittest.main()
