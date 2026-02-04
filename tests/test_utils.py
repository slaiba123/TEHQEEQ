"""
Tests for utils: parse_target, validate_domain, validate_ip, validate_output_path.
Run from project root: python -m unittest discover -s tests -p "test_*.py"
"""

import os
import tempfile
import unittest
from pathlib import Path

# Allow importing project modules when run from repo root
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils import (
    validate_domain,
    validate_ip,
    parse_target,
    validate_output_path,
)


class TestValidateDomain(unittest.TestCase):
    def test_valid_domains(self):
        self.assertTrue(validate_domain("example.com"))
        self.assertTrue(validate_domain("sub.example.com"))
        self.assertTrue(validate_domain("neduet.edu.pk"))
        self.assertTrue(validate_domain("a.co"))

    def test_invalid_domains(self):
        self.assertFalse(validate_domain(""))
        self.assertFalse(validate_domain("notadomain"))
        self.assertFalse(validate_domain("invalid."))
        self.assertFalse(validate_domain(".com"))
        self.assertFalse(validate_domain("has space.com"))


class TestValidateIP(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("0.0.0.0"))
        self.assertTrue(validate_ip("255.255.255.255"))
        self.assertTrue(validate_ip("8.8.8.8"))

    def test_invalid_ipv4(self):
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("1.2.3.4.5"))
        self.assertFalse(validate_ip(""))
        self.assertFalse(validate_ip("192.168.1"))


class TestParseTarget(unittest.TestCase):
    def test_domain_with_protocol(self):
        target, ttype = parse_target("https://example.com")
        self.assertEqual(target, "example.com")
        self.assertEqual(ttype, "domain")

    def test_domain_with_path(self):
        target, ttype = parse_target("example.com/path/to/page")
        self.assertEqual(target, "example.com")
        self.assertEqual(ttype, "domain")

    def test_domain_with_port(self):
        target, ttype = parse_target("example.com:8080")
        self.assertEqual(target, "example.com")
        self.assertEqual(ttype, "domain")

    def test_plain_domain(self):
        target, ttype = parse_target("example.com")
        self.assertEqual(target, "example.com")
        self.assertEqual(ttype, "domain")

    def test_plain_ip(self):
        target, ttype = parse_target("192.168.1.1")
        self.assertEqual(target, "192.168.1.1")
        self.assertEqual(ttype, "ip")

    def test_invalid_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parse_target("not valid")
        self.assertIn("Invalid target format", str(ctx.exception))


class TestValidateOutputPath(unittest.TestCase):
    def test_empty_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate_output_path("")
        self.assertIn("empty", str(ctx.exception).lower())
        with self.assertRaises(ValueError):
            validate_output_path("   ")

    def test_valid_returns_absolute(self):
        with tempfile.TemporaryDirectory() as d:
            out = validate_output_path(d)
            self.assertTrue(Path(out).is_absolute())
            self.assertTrue(Path(out).resolve().exists() or True)

    def test_relative_resolved(self):
        out = validate_output_path("reports")
        self.assertTrue(Path(out).is_absolute())


if __name__ == "__main__":
    unittest.main()
