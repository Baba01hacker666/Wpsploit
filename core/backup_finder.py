# core/backup_finder.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, safe_get, get_default_timeout

LISTING_MARKERS = ("<title>Index of /", "Directory listing for", "Parent Directory")

DEBUG_LOG_MARKERS = ("PHP Notice", "PHP Warning", "PHP Deprecated", "PHP Fatal error", "WordPress database error")


def classify_hit(endpoint, status_code, body):
    """Classify an accessible sensitive file into (severity, title, detail)."""
    lowered = (body or "")[:4000].lower()

    if any(m.lower() in lowered for m in LISTING_MARKERS):
        return "high", f"Open directory listing at {endpoint}", "Server exposes a browsable index of files"

    if endpoint.rstrip("/").endswith((".sql", ".sql.gz")):
        return "critical", f"Database dump exposed: {endpoint}", "Potential full database disclosure"

    if "debug.log" in endpoint and any(m in (body or "")[:4000] for m in DEBUG_LOG_MARKERS):
        return "high", f"Debug log exposed: {endpoint}", "PHP errors leak file paths and internals"

    if "/.git" in endpoint:
        return "critical", f"Git repository exposed: {endpoint}", "Source code history may be downloadable"

    if "/.svn" in endpoint:
        return "critical", f"SVN repository exposed: {endpoint}", "Source metadata may be downloadable"

    if endpoint.endswith((".zip", ".tar", ".tar.gz", ".7z", ".rar")):
        return "high", f"Archive exposed: {endpoint}", "Backup archive reachable, verify contents"

    if ".env" in endpoint:
        return "critical", f"Environment file exposed: {endpoint}", "May contain credentials and secrets"

    if endpoint.endswith(("composer.json", "package.json")):
        return "low", f"Dependency manifest exposed: {endpoint}", "Discloses dependency versions"

    if endpoint.endswith(("error_log", "php_errorlog")):
        return "medium", f"Error log exposed: {endpoint}", "Error output leaks paths and queries"

    return "medium", f"Sensitive file accessible: {endpoint}", "Manual review recommended"


def check_path(session, base_url, path):
    url = urljoin(base_url, path)
    try:
        r = safe_get(session, url, timeout=get_default_timeout(), allow_redirects=False)
        if r.status_code == 200:
            severity, title, detail = classify_hit(path, r.status_code, r.text)
            return {
                "path": path,
                "url": url,
                "status_code": 200,
                "severity": severity,
                "title": title,
                "detail": detail,
                "snippet": (r.text or "")[:200],
            }
        return None
    except requests.exceptions.RequestException:
        return None


def find_backups(session, base_url, threads=10, extra_paths=None):
    """Scan for exposed backups, logs, dumps and directory listings."""
    paths = set(load_endpoints("endpoints/backups.txt"))
    if extra_paths:
        paths.update(extra_paths)
    paths = sorted(paths)

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {executor.submit(check_path, session, base_url, p): p for p in paths}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                hits.append(result)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: order.get(h["severity"], 9))
    return hits


def backup_findings(hits):
    findings = []
    for h in hits:
        findings.append(
            {
                "severity": h["severity"],
                "module": "backups",
                "title": h["title"],
                "detail": h["detail"],
            }
        )
    return findings
