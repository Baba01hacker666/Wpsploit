import unittest
from unittest.mock import MagicMock
import sys


class TestHeadersCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = MagicMock()
        from core.headers_check import header_findings, _cookie_flags
        cls.header_findings = staticmethod(header_findings)
        cls.cookie_flags = staticmethod(_cookie_flags)

    @classmethod
    def tearDownClass(cls):
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_cookie_flags(self):
        f = self.cookie_flags("wordpress_test=1; path=/; HttpOnly; Secure; SameSite=Lax")
        self.assertTrue(f["httponly"])
        self.assertTrue(f["secure"])
        self.assertTrue(f["samesite"])

    def test_cookie_flags_missing(self):
        f = self.cookie_flags("wp-settings-1=1; path=/")
        self.assertFalse(f["httponly"])
        self.assertFalse(f["secure"])
        self.assertFalse(f["samesite"])

    def test_header_findings_missing_and_disclosure(self):
        report = {
            "missing": [
                {"header": "strict-transport-security", "severity": "high", "why": "no hsts"},
                {"header": "content-security-policy", "severity": "medium", "why": "no csp"},
            ],
            "disclosure": {"server": "Apache/2.4.29 (Ubuntu)"},
            "cookies": [{"name": "wp-settings-1", "missing_flags": ["HTTPONLY", "SECURE"]}],
        }
        findings = self.header_findings(report)
        titles = [f["title"] for f in findings]
        self.assertEqual(len(findings), 4)
        self.assertIn("Missing security header: strict-transport-security", titles)
        self.assertIn("Version disclosure via 'server' header", titles)
        cookie_f = [f for f in findings if "Cookie" in f["title"]][0]
        self.assertEqual(cookie_f["severity"], "medium")

    def test_header_findings_empty(self):
        self.assertEqual(self.header_findings({"missing": [], "disclosure": {}, "cookies": []}), [])


if __name__ == "__main__":
    unittest.main()
