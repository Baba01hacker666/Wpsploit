from unittest.mock import MagicMock
import unittest
import sys

class RequestException(Exception):
    pass

class TestAuthorEnum(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests BEFORE importing core.author_enum
        cls.mock_requests = MagicMock()
        cls.mock_requests.exceptions.RequestException = RequestException

        # Save original requests if it exists
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = cls.mock_requests

        # Now import the module under test
        global check_author_id
        from core.author_enum import check_author_id

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_check_author_id_success(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {'Location': 'http://example.com/author/johndoe/'}
        session.get.return_value = mock_response

        result = check_author_id(session, "http://example.com", 1)
        self.assertEqual(result, "johndoe")

    def test_check_author_id_not_found(self):
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        session.get.return_value = mock_response

        result = check_author_id(session, "http://example.com", 999)
        self.assertIsNone(result)

    def test_check_author_id_request_exception(self):
        session = MagicMock()
        session.get.side_effect = RequestException

        result = check_author_id(session, "http://example.com", 2)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
