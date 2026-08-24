import unittest
from unittest.mock import MagicMock
import sys


class TestVulnHints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = MagicMock()
        from core.vuln_hints import (
            is_version_below,
            version_tuple,
            hint_for_plugin,
            hint_for_theme,
            collect_hints,
            hints_for_wp_core,
            hint_findings,
        )
        cls.is_version_below = staticmethod(is_version_below)
        cls.version_tuple = staticmethod(version_tuple)
        cls.hint_for_plugin = staticmethod(hint_for_plugin)
        cls.hint_for_theme = staticmethod(hint_for_theme)
        cls.collect_hints = staticmethod(collect_hints)
        cls.hints_for_wp_core = staticmethod(hints_for_wp_core)
        cls.hint_findings = staticmethod(hint_findings)

    @classmethod
    def tearDownClass(cls):
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_version_tuple(self):
        self.assertEqual(self.version_tuple("6.4.2"), (6, 4, 2))
        self.assertEqual(self.version_tuple("5"), (5,))

    def test_is_version_below(self):
        self.assertTrue(self.is_version_below("5.9", "6.0"))
        self.assertTrue(self.is_version_below("6.4.2", "6.4.3"))
        self.assertFalse(self.is_version_below("6.4.3", "6.4.3"))
        self.assertFalse(self.is_version_below("7.0", "6.4.3"))
        self.assertTrue(self.is_version_below("4.9", "5.2.8"))

    def test_known_plugin_hint(self):
        h = self.hint_for_plugin("revslider")
        self.assertIsNotNone(h)
        self.assertEqual(h["severity"], "critical")

    def test_unknown_plugin_hint(self):
        self.assertIsNone(self.hint_for_plugin("totally-unknown-plugin"))

    def test_alias_normalization(self):
        h = self.hint_for_plugin("cf7")
        self.assertIsNotNone(h)
        self.assertEqual(h["severity"], "high")

    def test_legacy_theme_hint(self):
        h = self.hint_for_theme("twentyten")
        self.assertIsNotNone(h)
        self.assertEqual(h["severity"], "low")

    def test_core_hints_outdated(self):
        version_info = {"meta": ["WordPress 5.2"], "statuses": {"meta": "found"}}
        hints = self.hints_for_wp_core(version_info)
        self.assertEqual(len(hints), 1)
        self.assertLessEqual(hints[0]["severity"], "critical")
        self.assertIn("wordpress-core:5.2", hints[0]["target"])

    def test_core_hints_recent(self):
        version_info = {"meta": ["WordPress 6.8"], "statuses": {"meta": "found"}}
        hints = self.hints_for_wp_core(version_info)
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["severity"], "info")

    def test_collect_hints_dedupes_and_sorts(self):
        hints = self.collect_hints(
            plugins=["revslider", "contact-form-7"],
            themes=["twentyten"],
            version_info={"meta": ["WordPress 5.1"]},
        )
        targets = [h["target"] for h in hints]
        self.assertEqual(len(targets), len(set(targets)))
        severities = [h["severity"] for h in hints]
        order = ["critical", "high", "medium", "low", "info"]
        idx = [order.index(s) for s in severities]
        self.assertEqual(idx, sorted(idx))

    def test_hint_findings_shape(self):
        findings = self.hint_findings([{"target": "plugin:x", "severity": "medium", "note": "n"}])
        self.assertEqual(findings[0]["module"], "hints")
        self.assertEqual(findings[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
