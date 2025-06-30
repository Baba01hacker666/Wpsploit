# core/utils.py
import random

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
USER_AGENTS = []

def load_user_agents(path="user_agents.txt"):
    """Loads user agents from a file, with a fallback."""
    global USER_AGENTS
    try:
        with open(path, "r") as f:
            USER_AGENTS = [line.strip() for line in f if line.strip()]
        if not USER_AGENTS:
            USER_AGENTS = [DEFAULT_USER_AGENT]
    except FileNotFoundError:
        print(f"[!] Warning: '{path}' not found. Using default user agent.")
        USER_AGENTS = [DEFAULT_USER_AGENT]

def get_random_user_agent():
    """Returns a random user agent from the loaded list."""
    if not USER_AGENTS:
        load_user_agents()
    return random.choice(USER_AGENTS)

def load_endpoints(path):
    """Loads endpoints from a file."""
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Warning: Endpoint file '{path}' not found. Skipping.")
        return []

# Initialize user agents on module load
load_user_agents()