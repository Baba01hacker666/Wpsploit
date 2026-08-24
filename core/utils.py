# core/utils.py
import random
import re
import threading
import time
from pathlib import Path
import requests

# ANSI Color Codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
USER_AGENTS = []

_default_timeout = 10.0
_request_delay = 0.0
_throttle_lock = threading.Lock()
_last_request_time = 0.0


def set_default_timeout(seconds):
    global _default_timeout
    try:
        _default_timeout = max(1.0, float(seconds))
    except (TypeError, ValueError):
        pass
    return _default_timeout


def get_default_timeout():
    return _default_timeout


def set_request_delay(seconds):
    global _request_delay
    try:
        _request_delay = max(0.0, float(seconds))
    except (TypeError, ValueError):
        pass
    return _request_delay


def _throttle():
    global _last_request_time
    if _request_delay <= 0:
        return
    with _throttle_lock:
        now = time.monotonic()
        wait = _request_delay - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.monotonic()


def resolve_data_path(rel_path):
    """Resolve data files relative to the repository root, with sensible fallbacks."""
    candidate = Path(rel_path)
    if candidate.is_absolute():
        return candidate

    repo_root = Path(__file__).resolve().parent.parent
    anchored_path = repo_root / candidate
    if anchored_path.exists():
        return anchored_path

    # Fallback for legacy callers relying on current working directory.
    return candidate

def setup_session(proxy=None, user_agent=None):
    """Sets up a requests.Session() with a random User-Agent and connection pooling."""
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent or get_random_user_agent()})
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session

def load_user_agents(path="user_agents.txt"):
    """Loads user agents from a file, with a fallback."""
    global USER_AGENTS
    resolved_path = resolve_data_path(path)
    try:
        with open(resolved_path, "r") as f:
            USER_AGENTS = [line.strip() for line in f if line.strip()]
        if not USER_AGENTS:
            USER_AGENTS = [DEFAULT_USER_AGENT]
    except FileNotFoundError:
        print(f"[!] Warning: '{resolved_path}' not found. Using default user agent.")
        USER_AGENTS = [DEFAULT_USER_AGENT]

def get_random_user_agent():
    """Returns a random user agent from the loaded list."""
    if not USER_AGENTS:
        load_user_agents()
    return random.choice(USER_AGENTS)

def load_endpoints(path):
    """Loads endpoints from a file."""
    resolved_path = resolve_data_path(path)
    try:
        with open(resolved_path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Warning: Endpoint file '{resolved_path}' not found. Skipping.")
        return []

def sanitize_output(data):
    """Escapes ANSI codes and other potentially harmful characters from untrusted data."""
    if isinstance(data, str):
        return repr(data)[1:-1]
    return repr(data)

_FILENAME_SAFE_RE = re.compile(r'[^a-zA-Z0-9.-]')

def sanitize_filename(filename):
    """
    Sanitizes a string for use as a filename or directory name.
    Replaces non-alphanumeric characters (except dots and hyphens) with underscores,
    iteratively removes '..' sequences, and strips leading dots.
    """
    if not filename:
        return "default"

    # Replace unsafe characters
    filename = _FILENAME_SAFE_RE.sub('_', filename)

    # Remove '..' sequences
    while '..' in filename:
        filename = filename.replace('..', '.')

    # Strip leading dots and hyphens (prevent hidden files and flag-like names)
    filename = filename.lstrip('.-')

    return filename or "default"

def safe_get(session, url, **kwargs):
    """
    Perform a session.get() with SSRF protections:
    - Only allow http and https schemes.
    - Manually follow redirects while verifying netloc.
    """
    from urllib.parse import urlparse, urljoin

    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

    # Capture the requested allow_redirects, default to True (requests default)
    follow_redirects = kwargs.pop('allow_redirects', True)
    max_redirects = kwargs.pop('max_redirects', 10)

    kwargs.setdefault('timeout', _default_timeout)
    _throttle()

    # We must explicitly set allow_redirects=False for the actual requests call
    r = session.get(url, allow_redirects=False, **kwargs)

    # Manual redirect handling if requested
    original_netloc = parsed.netloc
    redirect_count = 0

    while 300 <= r.status_code < 400 and follow_redirects and redirect_count < max_redirects:
        location = r.headers.get('Location')
        if not location:
            break

        next_url = urljoin(url, location)
        next_parsed = urlparse(next_url)

        # SSRF protection: Ensure same netloc
        if next_parsed.netloc != original_netloc:
            # We don't follow cross-domain redirects for security
            break

        if next_parsed.scheme not in ('http', 'https'):
            break

        _throttle()
        r = session.get(next_url, allow_redirects=False, **kwargs)
        url = next_url
        redirect_count += 1

    return r

# Initialize user agents on module load
load_user_agents()
