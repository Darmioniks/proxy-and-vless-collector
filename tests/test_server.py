import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

import server


class ServerTest(unittest.TestCase):
    def test_job_accepts_unlimited_checks_and_excluded_countries(self):
        req = server.JobRequest(
            count=10,
            source="remote",
            max_checks=None,
            enable_xray=False,
            filters={"excluded_countries": ["de"]},
        )
        with patch.object(
            server.jobs, "create",
            return_value=SimpleNamespace(id="job-id", state="queued"),
        ) as create:
            response = server.create_job(req)

        self.assertEqual(response, {"id": "job-id", "state": "queued"})
        cfg = create.call_args.args[0]
        self.assertIsNone(cfg["max_checks"])
        self.assertEqual(cfg["filters"]["excluded_countries"], ["DE"])

    def test_job_rejects_country_in_both_lists(self):
        req = server.JobRequest(
            source="remote",
            enable_xray=False,
            filters={"countries": ["DE"], "excluded_countries": ["de"]},
        )

        with self.assertRaises(HTTPException) as raised:
            server.create_job(req)

        self.assertEqual(raised.exception.status_code, 422)

    def test_telegram_scan_returns_scanner_result(self):
        expected = {"sources": {}, "total": 1, "tested": 1, "working": []}
        with patch("server.mtproto.scan", return_value=expected) as scan:
            response = server.scan_telegram(server.TelegramRequest(limit=25))

        self.assertEqual(response, expected)
        scan.assert_called_once_with(25)

    def test_working_recheck_uses_complete_database_snapshot(self):
        keys = ["vless://one", "vless://two"]
        with patch("server.store.working_keys", return_value=keys), \
                patch.object(server.checker, "XRAY_BIN", None), \
                patch.object(
                    server.jobs, "create",
                    return_value=SimpleNamespace(id="recheck-id", state="queued"),
                ) as create:
            response = server.recheck_working(
                server.WorkingRecheckRequest(workers=4, enable_xray=False)
            )

        self.assertEqual(response["total"], 2)
        cfg = create.call_args.args[0]
        self.assertTrue(cfg["prune_working"])
        self.assertEqual(cfg["working_snapshot"], keys)
        self.assertEqual(cfg["count"], 2)

    def test_working_download_contains_all_keys(self):
        with patch("server.store.working_keys", return_value=["vless://one", "vless://two"]):
            response = server.download_working()

        self.assertEqual(response.body.decode(), "vless://one\nvless://two")
        self.assertIn("working-vless.txt", response.headers["content-disposition"])


if __name__ == "__main__":
    unittest.main()
