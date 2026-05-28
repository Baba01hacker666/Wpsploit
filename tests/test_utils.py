from unittest.mock import MagicMock
import unittest
import sys

class TestUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests BEFORE importing core.utils
        cls.mock_requests = MagicMock()

        # Save original requests if it exists
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = cls.mock_requests

        # Now import the module under test
        global sanitize_output
        from core.utils import sanitize_output

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_sanitize_output_normal_string(self):
        data = "hello world"
        result = sanitize_output(data)
        self.assertEqual(result, "hello world")

    def test_sanitize_output_ansi_codes(self):
        data = "\x1b[31mRed\x1b[0m"
        result = sanitize_output(data)
        # repr('\x1b[31mRed\x1b[0m') is "'\\x1b[31mRed\\x1b[0m'"
        # [1:-1] gives "\\x1b[31mRed\\x1b[0m"
        self.assertEqual(result, "\\x1b[31mRed\\x1b[0m")

    def test_sanitize_output_quotes(self):
        data = "It's 'quoted'"
        result = sanitize_output(data)
        # repr("It's 'quoted'") is '"It\'s \'quoted\'"' or similar depending on python version/logic
        # Actually: repr("It's 'quoted'") is '"It\'s \'quoted\'"'
        # Let's verify with what repr actually returns.
        expected = repr(data)[1:-1]
        self.assertEqual(result, expected)

    def test_sanitize_output_mixed_quotes(self):
        data = 'He said "Hello"'
        result = sanitize_output(data)
        expected = repr(data)[1:-1]
        self.assertEqual(result, expected)

    def test_sanitize_output_non_string_int(self):
        data = 123
        result = sanitize_output(data)
        self.assertEqual(result, "123")

    def test_sanitize_output_non_string_list(self):
        data = [1, 2, 3]
        result = sanitize_output(data)
        self.assertEqual(result, "[1, 2, 3]")

    def test_sanitize_output_empty_string(self):
        data = ""
        result = sanitize_output(data)
        self.assertEqual(result, "")

    def test_sanitize_output_none(self):
        data = None
        result = sanitize_output(data)
        self.assertEqual(result, "None")

if __name__ == "__main__":
    unittest.main()
