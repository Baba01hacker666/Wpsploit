# core/utils.py
import random
import re
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

def setup_session():
    """Sets up a requests.Session() with a random User-Agent and connection pooling."""
    session = requests.Session()
    session.headers.update({"User-Agent": get_random_user_agent()})
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

# Initialize user agents on module load
load_user_agents()
