import unittest
from unittest.mock import MagicMock, patch
import sys

# Define a mock RequestException for testing
class MockRequestException(Exception):
    pass

class TestExtraRecon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock requests BEFORE importing core.extra_recon
        cls.mock_requests = MagicMock()
        cls.mock_requests.RequestException = MockRequestException
        cls.original_requests = sys.modules.get("requests")
        sys.modules["requests"] = cls.mock_requests

        # Import the module under test
        global enumerate_plugins_and_themes
        from core.extra_recon import enumerate_plugins_and_themes

    @classmethod
    def tearDownClass(cls):
        # Restore sys.modules
        if cls.original_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = cls.original_requests

    def test_enumerate_plugins_and_themes_with_html(self):
        """Test enumeration with direct HTML content."""
        html = """
        <link rel='stylesheet' href='http://example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.1' />
        <script src='http://example.com/wp-content/plugins/woocommerce/assets/js/frontend/add-to-cart.min.js?ver=5.3.0'></script>
        <link rel='stylesheet' href='http://example.com/wp-content/themes/twentytwentyone/style.css?ver=1.3' />
        """
        plugins, themes = enumerate_plugins_and_themes(None, "http://example.com", html_content=html)
        self.assertEqual(plugins, ["contact-form-7", "woocommerce"])
        self.assertEqual(themes, ["twentytwentyone"])

    def test_enumerate_plugins_and_themes_duplicates(self):
        """Test that duplicates are removed and results are sorted."""
        html = """
        <link rel='stylesheet' href='wp-content/plugins/my-plugin/style.css' />
        <link rel='stylesheet' href='wp-content/plugins/my-plugin/other.css' />
        <link rel='stylesheet' href='wp-content/themes/my-theme/style.css' />
        <link rel='stylesheet' href='wp-content/themes/my-theme/mobile.css' />
        """
        plugins, themes = enumerate_plugins_and_themes(None, "http://example.com", html_content=html)
        self.assertEqual(plugins, ["my-plugin"])
        self.assertEqual(themes, ["my-theme"])

    def test_enumerate_plugins_and_themes_no_matches(self):
        """Test with HTML that has no matches."""
        html = "<html><body>Hello World</body></html>"
        plugins, themes = enumerate_plugins_and_themes(None, "http://example.com", html_content=html)
        self.assertEqual(plugins, [])
        self.assertEqual(themes, [])

    @patch("core.extra_recon.safe_get")
    def test_enumerate_plugins_and_themes_with_request(self, mock_safe_get):
        """Test enumeration when it needs to fetch HTML."""
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "<link rel='stylesheet' href='wp-content/plugins/akismet/style.css' />"
        mock_safe_get.return_value = mock_response

        plugins, themes = enumerate_plugins_and_themes(session, "http://example.com")

        mock_safe_get.assert_called_once_with(session, "http://example.com", timeout=10)
        self.assertEqual(plugins, ["akismet"])
        self.assertEqual(themes, [])

    @patch("core.extra_recon.safe_get")
    def test_enumerate_plugins_and_themes_request_exception(self, mock_safe_get):
        """Test handling of request exceptions during HTML fetch."""
        session = MagicMock()
        mock_safe_get.side_effect = MockRequestException("Network error")

        plugins, themes = enumerate_plugins_and_themes(session, "http://example.com")

        self.assertEqual(plugins, [])
        self.assertEqual(themes, [])

if __name__ == "__main__":
    unittest.main()
