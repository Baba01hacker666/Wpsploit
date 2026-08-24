import unittest
from unittest.mock import MagicMock
import sys


class TestBackupFinder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = MagicMock()
        from core.backup_finder import classify_hit, backup_findings
        cls.classify_hit = staticmethod(classify_hit)
        cls.backup_findings = staticmethod(backup_findings)

    @classmethod
    def tearDownClass(cls):
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_debug_log_classified_high(self):
        sev, title, _ = self.classify_hit(
            "/wp-content/debug.log", 200, "PHP Notice: undefined index in /var/www/wp-includes/post.php"
        )
        self.assertEqual(sev, "high")

    def test_sql_dump_critical(self):
        sev, title, _ = self.classify_hit("/backup.sql", 200, "CREATE TABLE wp_users")
        self.assertEqual(sev, "critical")

    def test_git_critical(self):
        sev, title, _ = self.classify_hit("/.git/logs/HEAD", 200, "000000 111111 author")
        self.assertEqual(sev, "critical")
        self.assertIn("Git", title)

    def test_env_critical(self):
        sev, _, _ = self.classify_hit("/.env", 200, "DB_PASSWORD=hunter2")
        self.assertEqual(sev, "critical")

    def test_directory_listing(self):
        sev, title, _ = self.classify_hit(
            "/wp-content/uploads/", 200, "<html><head><title>Index of /uploads</title></head></html>"
        )
        self.assertEqual(sev, "high")
        self.assertIn("listing", title)

    def test_archive_high(self):
        sev, _, _ = self.classify_hit("/backup.zip", 200, "PK\x03\x04")
        self.assertEqual(sev, "high")

    def test_composer_low(self):
        sev, _, _ = self.classify_hit("/composer.json", 200, '{"require": {}}')
        self.assertEqual(sev, "low")

    def test_unknown_sensitive_defaults_medium(self):
        sev, _, _ = self.classify_hit("/some-file.txt", 200, "hello")
        self.assertEqual(sev, "medium")

    def test_backup_findings_shape(self):
        hits = [
            {"severity": "critical", "title": "t1", "detail": "d1"},
            {"severity": "low", "title": "t2", "detail": "d2"},
        ]
        findings = self.backup_findings(hits)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["module"], "backups")


if __name__ == "__main__":
    unittest.main()
