"""
Unit tests for skills/scanner.py -- per-source processing and full-scan
report assembly (including the concurrency, progress, and cancel hooks).

Network I/O is mocked out (skills.scanner.fetch_page) so these tests are
fast, deterministic, and runnable offline.

Run the whole suite from the project root with:
    python3 -m unittest discover tests -v
"""

import threading
import unittest
from unittest.mock import patch

from skills.scanner import build_ioc_mapping, process_source, run_full_scan

PAGE_HTML = """
<html><head><script>var x = "deadbeef".repeat(8);</script></head><body>
<p>C2 at 203.0.113.45 and defanged 198[.]51[.]100[.]23.</p>
<p>Same host defanged: 203[.]0[.]113[.]45</p>
<p>hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08</p>
</body></html>
"""


class TestProcessSource(unittest.TestCase):
    @patch("skills.scanner.fetch_page", return_value=PAGE_HTML)
    def test_success_extracts_and_dedupes(self, _mock_fetch):
        url, result = process_source({"name": "Blog", "url": "https://example.com"})

        self.assertEqual(url, "https://example.com")
        self.assertEqual(result["status"], "success")
        # 203.0.113.45 appears both plain and defanged -- must be ONE entry.
        self.assertEqual(result["ipv4_addresses"], ["198.51.100.23", "203.0.113.45"])
        self.assertEqual(result["defanged_ips_refanged"], ["198.51.100.23", "203.0.113.45"])
        self.assertEqual(
            result["sha256_hashes"],
            ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
        )

    @patch("skills.scanner.fetch_page", return_value=None)
    def test_fetch_failure_marks_failed(self, _mock_fetch):
        url, result = process_source({"name": "Dead", "url": "https://dead.example"})
        self.assertEqual(result["status"], "failed")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["ipv4_addresses"], [])

    def test_missing_url_marks_failed(self):
        url, result = process_source({"name": "No URL"})
        self.assertEqual(url, "")
        self.assertEqual(result["status"], "failed")


class TestBuildIocMapping(unittest.TestCase):
    def test_reverse_index_skips_failed_sources(self):
        results = {
            "https://a.example": {
                "status": "success",
                "ipv4_addresses": ["1.1.1.1", "2.2.2.2"],
                "sha256_hashes": [],
            },
            "https://b.example": {
                "status": "success",
                "ipv4_addresses": ["1.1.1.1"],
                "sha256_hashes": ["a" * 64],
            },
            "https://c.example": {
                "status": "failed",
                "ipv4_addresses": [],
                "sha256_hashes": [],
            },
        }
        mapping = build_ioc_mapping(results)
        self.assertEqual(mapping["1.1.1.1"], ["https://a.example", "https://b.example"])
        self.assertEqual(mapping["2.2.2.2"], ["https://a.example"])
        self.assertEqual(mapping["a" * 64], ["https://b.example"])


class TestRunFullScan(unittest.TestCase):
    @patch("skills.scanner.fetch_page", return_value=PAGE_HTML)
    def test_report_shape_and_metadata(self, _mock_fetch):
        sources = [
            {"name": "A", "url": "https://a.example"},
            {"name": "B", "url": "https://b.example"},
        ]
        report = run_full_scan(sources, total_configured=3)

        meta = report["scan_metadata"]
        self.assertEqual(meta["total_sources_configured"], 3)
        self.assertEqual(meta["total_sources_scanned"], 2)
        self.assertEqual(meta["sources_succeeded"], 2)
        self.assertEqual(meta["sources_failed"], 0)
        self.assertEqual(meta["total_unique_iocs"], 3)
        self.assertEqual(meta["total_unique_ipv4"], 2)
        self.assertEqual(meta["total_unique_sha256"], 1)
        self.assertFalse(meta["cancelled"])
        # Both sources served identical HTML, so every IOC maps to both URLs.
        for urls in report["ioc_to_source_mapping"].values():
            self.assertEqual(sorted(urls), ["https://a.example", "https://b.example"])

    @patch("skills.scanner.fetch_page", return_value=PAGE_HTML)
    def test_result_order_matches_source_order(self, _mock_fetch):
        """Sources are scanned concurrently, but the report must still list
        them in configured order."""
        sources = [{"name": f"S{i}", "url": f"https://s{i}.example"} for i in range(8)]
        report = run_full_scan(sources, total_configured=8)
        self.assertEqual(
            list(report["results_by_source"].keys()),
            [f"https://s{i}.example" for i in range(8)],
        )

    @patch("skills.scanner.fetch_page", return_value=PAGE_HTML)
    def test_progress_callback_called_per_source(self, _mock_fetch):
        sources = [{"name": f"S{i}", "url": f"https://s{i}.example"} for i in range(4)]
        calls = []
        lock = threading.Lock()

        def on_progress(completed, total, url, result):
            with lock:
                calls.append((completed, total, url, result["status"]))

        run_full_scan(sources, total_configured=4, progress_callback=on_progress)

        self.assertEqual(len(calls), 4)
        self.assertEqual(sorted(c[0] for c in calls), [1, 2, 3, 4])
        self.assertTrue(all(c[1] == 4 for c in calls))

    @patch("skills.scanner.fetch_page", return_value=PAGE_HTML)
    def test_pre_set_cancel_skips_everything(self, _mock_fetch):
        cancel = threading.Event()
        cancel.set()
        report = run_full_scan(
            [{"name": "A", "url": "https://a.example"}], total_configured=1, cancel_event=cancel
        )
        self.assertEqual(report["scan_metadata"]["total_sources_scanned"], 0)
        self.assertTrue(report["scan_metadata"]["cancelled"])
        self.assertEqual(report["results_by_source"], {})


if __name__ == "__main__":
    unittest.main()
