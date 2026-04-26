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
        global sanitize_output, sanitize_filename, safe_get
        from core.utils import sanitize_output, sanitize_filename, safe_get

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

    def test_safe_get_invalid_initial_scheme(self):
        session = MagicMock()
        with self.assertRaises(ValueError) as cm:
            safe_get(session, "ftp://example.com")
        self.assertIn("Invalid URL scheme", str(cm.exception))

    def test_safe_get_success_no_redirect(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        session.get.return_value = mock_response

        url = "http://example.com/page"
        r = safe_get(session, url)

        session.get.assert_called_once_with(url, allow_redirects=False)
        self.assertEqual(r, mock_response)

    def test_safe_get_follow_valid_redirect(self):
        session = MagicMock()

        # First response is a redirect
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {'Location': '/new-path'}

        # Second response is success
        resp2 = MagicMock()
        resp2.status_code = 200

        session.get.side_effect = [resp1, resp2]

        url = "http://example.com/old"
        r = safe_get(session, url)

        self.assertEqual(session.get.call_count, 2)
        session.get.assert_any_call("http://example.com/old", allow_redirects=False)
        session.get.assert_any_call("http://example.com/new-path", allow_redirects=False)
        self.assertEqual(r, resp2)

    def test_safe_get_prevent_cross_domain_redirect(self):
        session = MagicMock()

        # First response is a redirect to another domain
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': 'http://attacker.com/malicious'}

        session.get.return_value = resp1

        url = "http://example.com/redirect"
        r = safe_get(session, url)

        # Should only call get once
        session.get.assert_called_once_with(url, allow_redirects=False)
        self.assertEqual(r, resp1)

    def test_safe_get_prevent_invalid_scheme_redirect(self):
        session = MagicMock()

        # First response is a redirect to non-http/https
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': 'gopher://example.com/something'}

        session.get.return_value = resp1

        url = "http://example.com/redirect"
        r = safe_get(session, url)

        # Should only call get once because scheme is invalid
        session.get.assert_called_once_with(url, allow_redirects=False)
        self.assertEqual(r, resp1)

    def test_safe_get_respect_max_redirects(self):
        session = MagicMock()

        # Create a loop of redirects
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {'Location': '/loop'}
        session.get.return_value = resp

        url = "http://example.com/start"
        max_redirs = 5
        r = safe_get(session, url, max_redirects=max_redirs)

        # Initial call + max_redirs
        self.assertEqual(session.get.call_count, max_redirs + 1)
        self.assertEqual(r, resp)

    def test_safe_get_respect_allow_redirects_false(self):
        session = MagicMock()

        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {'Location': '/somewhere'}
        session.get.return_value = resp1

        url = "http://example.com/redirect"
        r = safe_get(session, url, allow_redirects=False)

        # Should only call once even if it's a redirect
        session.get.assert_called_once_with(url, allow_redirects=False)
        self.assertEqual(r, resp1)

    def test_safe_get_missing_location_header(self):
        session = MagicMock()

        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {} # No Location
        session.get.return_value = resp1

        url = "http://example.com/redirect"
        r = safe_get(session, url)

        session.get.assert_called_once_with(url, allow_redirects=False)
        self.assertEqual(r, resp1)

if __name__ == "__main__":
    unittest.main()
