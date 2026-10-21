import unittest
from unittest.mock import patch

import desktop


class DesktopTest(unittest.TestCase):
    def test_happ_link_keeps_subscription_protocol_visible(self):
        link = desktop.happ_link("https://example.com/keys.txt?x=1&y=2")
        self.assertEqual(
            link,
            "happ://add/https://example.com/keys.txt?x=1&y=2",
        )

    def test_open_happ_returns_fallback_when_client_missing(self):
        with patch("desktop.happ_command", return_value=None):
            result = desktop.DesktopApi().open_happ()

        self.assertFalse(result["ok"])
        self.assertEqual(result["subscriptionUrl"], desktop.HAPP_SUBSCRIPTION_URL)

    @unittest.skipUnless(hasattr(__import__("os"), "startfile"), "Windows only")
    def test_open_happ_uses_registered_protocol(self):
        with patch("desktop.happ_command", return_value='"Happ.exe" "%1"'), \
                patch("desktop.os.startfile") as startfile:
            result = desktop.DesktopApi().open_happ()

        self.assertTrue(result["ok"])
        startfile.assert_called_once_with(desktop.happ_link())

    @unittest.skipUnless(hasattr(__import__("os"), "startfile"), "Windows only")
    def test_open_happ_accepts_local_working_subscription(self):
        url = "http://127.0.0.1:43125/sub/abc123"
        with patch("desktop.happ_command", return_value='"Happ.exe" "%1"'), \
                patch("desktop.os.startfile") as startfile:
            result = desktop.DesktopApi().open_happ(url)

        self.assertTrue(result["ok"])
        startfile.assert_called_once_with(desktop.happ_link(url))

    def test_open_happ_rejects_untrusted_subscription(self):
        result = desktop.DesktopApi().open_happ("https://example.com/sub/abc")

        self.assertFalse(result["ok"])
        self.assertIn("Некорректная", result["error"])

    def test_telegram_proxy_rejects_other_links(self):
        result = desktop.DesktopApi().open_telegram_proxy("https://example.com")

        self.assertFalse(result["ok"])

    @unittest.skipUnless(hasattr(__import__("os"), "startfile"), "Windows only")
    def test_telegram_proxy_uses_registered_protocol(self):
        link = "tg://proxy?server=one.example&port=443&secret=abc"
        with patch("desktop.os.startfile") as startfile:
            result = desktop.DesktopApi().open_telegram_proxy(link)

        self.assertTrue(result["ok"])
        startfile.assert_called_once_with(link)


    def test_port_stays_stable_between_launches(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp,                 patch.dict(os.environ, {"PM_SUB_PORT": ""}):
            with patch("desktop.app_data_dir", return_value=tmp):
                first = desktop.choose_port()
                second = desktop.choose_port()
        self.assertEqual(first, second)
        self.assertGreater(first, 0)

if __name__ == "__main__":
    unittest.main()
