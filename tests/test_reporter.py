"""
Tests for Reporter: TXT and JSON report generation with mock data.
Run from project root: python -m unittest discover -s tests -p "test_*.py"
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from modules.reporter import Reporter


class TestReporter(unittest.TestCase):
    def setUp(self):
        self.passive = {
            "whois": {"domain_name": "example.com", "registrar": "Test Registrar"},
            "dns": {"A": ["93.184.216.34"], "MX": ["mail.example.com (Priority: 10)"]},
            "subdomains": ["www.example.com", "mail.example.com"],
        }
        self.active = {
            "open_ports": [{"port": 80, "state": "open", "service": "HTTP"}],
            "banners": {},
            "technologies": ["Web Server: nginx"],
            "ip_address": "93.184.216.34",
        }
        self._report_dir_orig = config.REPORTS_FOLDER

    def tearDown(self):
        config.REPORTS_FOLDER = self._report_dir_orig

    def test_generate_txt_report(self):
        with tempfile.TemporaryDirectory() as d:
            config.REPORTS_FOLDER = d
            r = Reporter("example.com", self.passive, self.active)
            with redirect_stdout(io.StringIO()):
                path = r.generate_txt_report()
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("example.com", content)
            self.assertIn("RECONNAISSANCE REPORT", content)
            self.assertIn("www.example.com", content)

    def test_generate_json_report(self):
        with tempfile.TemporaryDirectory() as d:
            config.REPORTS_FOLDER = d
            r = Reporter("example.com", self.passive, self.active)
            with redirect_stdout(io.StringIO()):
                path = r.generate_json_report()
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "example.com")
            self.assertIn("passive_reconnaissance", data)
            self.assertIn("active_reconnaissance", data)
            self.assertEqual(len(data["passive_reconnaissance"]["subdomains"]), 2)

    def test_generate_reports_unknown_format(self):
        r = Reporter("example.com", {}, {})
        with redirect_stdout(io.StringIO()):
            self.assertIsNone(r.generate_reports(format_type="unknown"))

    def test_reporter_with_custom_dir(self):
        with tempfile.TemporaryDirectory() as d:
            config.REPORTS_FOLDER = d
            r = Reporter("test.com", {"whois": {}}, {})
            with redirect_stdout(io.StringIO()):
                path = r.generate_txt_report()
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(Path(path).parent, Path(d).resolve())


if __name__ == "__main__":
    unittest.main()
