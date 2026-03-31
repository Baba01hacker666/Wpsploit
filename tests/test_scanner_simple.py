import unittest
from unittest.mock import MagicMock, patch
import sys

# Minimal mock requests
class MockRequests:
    class Session:
        def __init__(self):
            self.headers = {}
        def get(self, *args, **kwargs):
            return MagicMock()

class RequestException(Exception):
    pass

class TestScanner(unittest.TestCase):
    def test_endpoint_collection(self):
        # Mock requests before importing
        mock_requests = MagicMock()
        mock_requests.Session = MockRequests.Session
        mock_requests.exceptions.RequestException = RequestException

        with patch.dict(sys.modules, {"requests": mock_requests}):
            # Import inside test to use patched sys.modules
            from core.scanner import scan_all_endpoints

            with patch("core.scanner.load_endpoints") as mock_load:
                # Mock load_endpoints to return some data with duplicates
                mock_load.side_effect = [
                    ["/wp-login.php", "/admin"],
                    ["/wp-json/v2", "/wp-login.php"], # duplicate
                    ["/xmlrpc.php"]
                ]

                session = MockRequests.Session()

                # Mock executor to do nothing
                with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
                    mock_executor.return_value.__enter__.return_value.submit.side_effect = lambda f, *args, **kwargs: MagicMock()

                    # Instead of mocking as_completed, let's mock it at the module level if possible,
                    # but scan_all_endpoints imports concurrent.futures and uses it.
                    # Let's mock concurrent.futures.as_completed
                    with patch("concurrent.futures.as_completed") as mock_as_completed:
                        mock_as_completed.return_value = []

                        with patch("builtins.print"):
                            scan_all_endpoints(session, "http://example.com", 1)

                        self.assertEqual(mock_load.call_count, 3)

if __name__ == "__main__":
    unittest.main()
