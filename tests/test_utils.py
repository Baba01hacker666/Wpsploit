import unittest
from unittest.mock import MagicMock
import sys

class TestUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests BEFORE importing core.utils
        cls.mock_requests = MagicMock()
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = cls.mock_requests

        # Import the functions under test
        global sanitize_output, sanitize_filename
        from core.utils import sanitize_output, sanitize_filename

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_sanitize_output_string(self):
        # Normal string
        self.assertEqual(sanitize_output("hello"), "hello")

        # String with ANSI escape codes
        # repr("\033") is "'\\x1b'"
        self.assertEqual(sanitize_output("\033[91mError\033[0m"), "\\x1b[91mError\\x1b[0m")

        # String with newlines and tabs
        self.assertEqual(sanitize_output("line1\nline2\ttab"), "line1\\nline2\\ttab")

        # String with quotes
        # repr("It's a trap") -> '"It\'s a trap"'
        # [1:-1] -> "It's a trap"
        self.assertEqual(sanitize_output("It's a trap"), "It's a trap")

        # repr('He said "hello"') -> "'He said \"hello\"'"
        # [1:-1] -> 'He said "hello"'
        self.assertEqual(sanitize_output('He said "hello"'), 'He said "hello"')

    def test_sanitize_output_non_string(self):
        # Integer
        self.assertEqual(sanitize_output(123), "123")

        # List
        self.assertEqual(sanitize_output([1, 2, 3]), "[1, 2, 3]")

        # None
        self.assertEqual(sanitize_output(None), "None")

    def test_sanitize_filename(self):
        # Basic alphanumeric
        self.assertEqual(sanitize_filename("valid_file.txt"), "valid_file.txt")

        # Non-alphanumeric character replacement
        self.assertEqual(sanitize_filename("file with spaces.txt"), "file_with_spaces.txt")
        self.assertEqual(sanitize_filename("file@#$%^&*().txt"), "file_________.txt")

        # Path traversal (..) handling
        # "../../etc/passwd" -> ".._.._etc_passwd" -> "._._etc_passwd" -> "_._etc_passwd" (after lstrip)
        self.assertEqual(sanitize_filename("../../etc/passwd"), "_._etc_passwd")

        # Leading dots and hyphens
        self.assertEqual(sanitize_filename(".hidden"), "hidden")
        self.assertEqual(sanitize_filename("-flag"), "flag")
        self.assertEqual(sanitize_filename("..."), "default")

        # Empty/None inputs
        self.assertEqual(sanitize_filename(""), "default")
        self.assertEqual(sanitize_filename(None), "default")

if __name__ == "__main__":
    unittest.main()
