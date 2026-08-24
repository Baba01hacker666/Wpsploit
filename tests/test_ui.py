import unittest
from unittest.mock import MagicMock
import sys


class TestUi(unittest.TestCase):
    def setUp(self):
        import core.ui as ui
        self.ui = ui

    def test_severity_order_complete(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertIn(sev, self.ui.SEVERITY_ORDER)

    def test_severity_text_plain_mode(self):
        self.ui.init(no_color=True)
        t = self.ui.severity_text("critical")
        plain = getattr(t, "plain", str(t))
        self.assertIn("CRIT", plain.upper())

    def test_init_no_color_fallback(self):
        self.ui.init(no_color=True)
        self.assertIsNone(self.ui._console)
        self.assertTrue(self.ui.NO_COLOR)

    def test_findings_table_runs_without_error(self):
        self.ui.init(no_color=True, quiet=True)
        findings = [
            {"severity": "critical", "module": "scan", "title": "t1", "detail": "d1"},
            {"severity": "low", "module": "headers", "title": "t2", "detail": "d2"},
        ]
        self.ui.findings_table(findings)

    def test_risk_summary_quiet(self):
        self.ui.init(quiet=True)
        self.ui.risk_summary(42, "D", {"high": 3})
