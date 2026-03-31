from unittest.mock import MagicMock
import unittest
import sys

class RequestException(Exception):
    pass

class TestAdminFinder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests BEFORE importing core.admin_finder
        cls.mock_requests = MagicMock()
        cls.mock_requests.exceptions.RequestException = RequestException

        # Save original requests if it exists
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = cls.mock_requests

        # Now import the module under test
        global check_admin_path
        from core.admin_finder import check_admin_path

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_check_admin_path_success(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Please Log In</body></html>"
        mock_response.url = "http://example.com/wp-login.php"
        session.get.return_value = mock_response

        result = check_admin_path(session, "http://example.com", "wp-login.php")
        self.assertEqual(result, "http://example.com/wp-login.php")

    def test_check_admin_path_404(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        session.get.return_value = mock_response

        result = check_admin_path(session, "http://example.com", "notfound")
        self.assertIsNone(result)

    def test_check_admin_path_no_login_text(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Welcome to my site</body></html>"
        session.get.return_value = mock_response

        result = check_admin_path(session, "http://example.com", "index.php")
        self.assertIsNone(result)

    def test_check_admin_path_request_exception(self):
        session = MagicMock()
        session.get.side_effect = RequestException

        result = check_admin_path(session, "http://example.com", "wp-admin")
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
