import unittest
from unittest.mock import MagicMock, patch
import sys

class TestCrawler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests and bs4 BEFORE importing core.crawler
        cls.mock_requests = MagicMock()
        cls.mock_bs4 = MagicMock()

        cls.original_modules = {
            "requests": sys.modules.get("requests"),
            "bs4": sys.modules.get("bs4")
        }

        sys.modules["requests"] = cls.mock_requests
        sys.modules["bs4"] = cls.mock_bs4

        # Now import the function under test
        global normalize_url
        from core.crawler import normalize_url

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        for module_name, original_module in cls.original_modules.items():
            if original_module is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = original_module

    def test_normalize_url_basic(self):
        # Test basic scheme and netloc lowercasing
        self.assertEqual(normalize_url("HTTP://EXAMPLE.COM"), "http://example.com/")
        self.assertEqual(normalize_url("https://Example.Com/Path"), "https://example.com/Path")

    def test_normalize_url_path(self):
        # Test path leading slash addition and trailing slash removal
        self.assertEqual(normalize_url("http://example.com"), "http://example.com/")
        self.assertEqual(normalize_url("http://example.com/path/"), "http://example.com/path")
        self.assertEqual(normalize_url("http://example.com/"), "http://example.com/")

    def test_normalize_url_query(self):
        # Test query parameter sorting and blank value retention
        self.assertEqual(normalize_url("http://example.com/?b=2&a=1"), "http://example.com/?a=1&b=2")
        self.assertEqual(normalize_url("http://example.com/?c=3&a=1&b=2"), "http://example.com/?a=1&b=2&c=3")
        self.assertEqual(normalize_url("http://example.com/?a=&b=2"), "http://example.com/?a=&b=2")
        # Test multi-value query params
        self.assertEqual(normalize_url("http://example.com/?a=2&a=1"), "http://example.com/?a=1&a=2")

    def test_normalize_url_fragment(self):
        # Test fragment removal
        self.assertEqual(normalize_url("http://example.com/#fragment"), "http://example.com/")
        self.assertEqual(normalize_url("http://example.com/path?query=1#frag"), "http://example.com/path?query=1")

if __name__ == "__main__":
    unittest.main()
