import unittest
from unittest.mock import MagicMock
import sys


class TestMainHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = MagicMock()

        from main import build_parser, gather_findings, compute_risk, select_modules, MODULES

        cls.build_parser = staticmethod(build_parser)
        cls.gather_findings = staticmethod(gather_findings)
        cls.compute_risk = staticmethod(compute_risk)
        cls.select_modules = staticmethod(select_modules)
        cls.MODULES = MODULES

    @classmethod
    def tearDownClass(cls):
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def _args(self, argv):
        return self.build_parser().parse_args(argv)

    def test_default_is_smart_full_scan(self):
        args = self._args(["-u", "https://example.com"])
        selected = self.select_modules(args)
        for key, meta in self.MODULES.items():
            if meta["default"]:
                self.assertTrue(selected[key], f"{key} should be on by default")
        self.assertFalse(selected["crawl"], "crawl must stay opt-in")

    def test_all_includes_crawler(self):
        args = self._args(["-u", "https://example.com", "--all"])
        selected = self.select_modules(args)
        for key in self.MODULES:
            self.assertTrue(selected[key])

    def test_quick_only_scans(self):
        args = self._args(["-u", "https://example.com", "-Q"])
        selected = self.select_modules(args)
        self.assertTrue(selected["scan"])
        for key in ("brute", "extract", "recon", "headers", "backups", "admin", "hints", "crawl"):
            self.assertFalse(selected[key])

    def test_explicit_module_csv(self):
        args = self._args(["-u", "https://example.com", "--modules", "headers,hints"])
        selected = self.select_modules(args)
        self.assertTrue(selected["headers"])
        self.assertTrue(selected["hints"])
        self.assertFalse(selected["crawl"])
        self.assertFalse(selected["brute"])

    def test_unknown_module_exits(self):
        args = self._args(["-u", "https://example.com", "--modules", "nope"])
        with self.assertRaises(SystemExit) as ctx:
            self.select_modules(args)
        self.assertEqual(ctx.exception.code, 2)

    def test_output_flag_defaults_to_domain(self):
        args = self._args(["-u", "https://example.com", "-o"])
        self.assertEqual(args.output, "")
        args2 = self._args(["-u", "https://example.com", "-o", "custom_dir"])
        self.assertEqual(args2.output, "custom_dir")

    def test_url_autoscheme(self):
        args = self._args(["-u", "example.com"])
        self.assertEqual(args.url, "example.com")

    def test_gather_findings_git_critical(self):
        results = {
            "endpoint_scan": {
                "/.git/": {"status": "accessible", "status_code": 200, "info": "", "listing": False},
                "/wp-login.php": {"status": "accessible", "status_code": 200, "info": "", "listing": False},
            }
        }
        findings = self.gather_findings(results)
        titles = [f["title"] for f in findings]
        self.assertIn("/.git directory is exposed", titles)
        self.assertEqual(len(findings), 1)

    def test_gather_findings_users_and_dedupe(self):
        results = {
            "enumerated_users": ["admin", "editor"],
            "extracted_info": {"/wp-json/wp/v2/users": [{"slug": "admin"}]},
            "found_admin_panels": ["https://x/secret/wp-login.php"],
        }
        findings = self.gather_findings(results)
        self.assertGreaterEqual(len(findings), 3)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        idx = [order[f["severity"]] for f in findings]
        self.assertEqual(idx, sorted(idx))

    def test_compute_risk(self):
        score, grade, counts = self.compute_risk(
            [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "low"},
            ]
        )
        expected = 100 - 30 - 18 - 8 - 3
        self.assertEqual(score, max(0, expected))
        self.assertEqual(counts, {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0})

    def test_compute_risk_clean_site(self):
        score, grade, counts = self.compute_risk([])
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")


if __name__ == "__main__":
    unittest.main()
