# Wpsploit - WordPress Reconnaissance Tool

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

### Made by Doraemon Cyber Team

Wpsploit is a fast, smart command-line tool for reconnaissance and attack-surface mapping of WordPress sites.
One flag is enough: it figures out everything else by itself.

```sh
python3 main.py -u https://target.com
```

That single command runs a **smart full recon**: endpoint scanning, user enumeration, REST API extraction,
version/plugin/theme recon, security-headers audit, backup/log hunting, admin panel discovery, and known-issue
hints — then prints a severity-ranked findings table with a risk score, and tells you what to do next.

---

## Highlights

- **Smart defaults** — no flag soup. `-u` alone runs every fast module; only the slow crawler is opt-in.
- **Beautiful CLI** — rich terminal UI (tables, panels, spinners) with clean plain-text fallback when piped.
- **Findings, not noise** — results are deduplicated, ranked CRITICAL → INFO, and scored 0–100 with a grade.
- **Reports** — `results.json` + human-readable `report.md` saved to `./<domain>/` with `-o`.
- **Gentle by design** — SSRF-safe redirects, output sanitization, configurable rate limiting (`--delay`),
  proxy support, random or custom User-Agent.
- **Offline vuln hints** — detected WP core / plugin / theme versions are matched against a built-in
  known-issue database (no external API calls).

## Modules

| Key | Name | Default run | What it does |
| --- | --- | --- | --- |
| `scan` | Endpoint Scan | yes | Probes common/sensitive paths (`.git`, wp-config backups, xmlrpc, ...) |
| `brute` | User Enumeration | yes | Reveals usernames via `?author=1..N` |
| `extract` | REST API Extract | yes | Pulls public users/posts/pages/media/comments |
| `recon` | Extra Recon | yes | WP version, plugins/themes, XML-RPC capabilities, REST namespaces |
| `headers` | Headers Audit | yes | Security headers, server disclosure, cookie hardening |
| `backups` | Backup Hunt | yes | Exposed debug logs, SQL dumps, archives, directory listings |
| `admin` | Admin Finder | yes | Finds login panels moved off `/wp-admin` |
| `hints` | Vuln Hints | yes | Matches versions against built-in known-issue DB |
| `crawl` | Crawler | opt-in | Spiders internal/external links (slowest module) |

Inspect them any time:

```sh
python3 main.py --list-modules
```

---

## Setup & Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/Baba01hacker666/Wpsploit.git
    cd Wpsploit
    ```

2.  **Install dependencies:**
    ```sh
    pip3 install -r requirements.txt
    ```

    `requests` is the only hard requirement; `rich` adds the pretty UI and
    `beautifulsoup4` improves crawling — the tool still works without them.

Data files (endpoint wordlists, user agents) resolve from the project location, so the tool also
works when launched from anywhere via an absolute path.

---

## Usage

```sh
python3 main.py --help        # full help
python3 main.py               # interactive wizard (when run in a terminal)
```

### The only command you usually need

```sh
python3 main.py -u https://target.com          # smart full recon
python3 main.py -u target.com                  # scheme auto-added
python3 main.py -u https://target.com -o       # ...and save reports to ./target.com/
```

### Scan scope

| Flag | Meaning |
| --- | --- |
| *(none)* | Smart default: every fast module, no crawler |
| `-Q`, `--quick` | Endpoints only — fastest possible check |
| `-A`, `--all` | Everything including the site crawler |
| `--modules headers,hints` | Pick exactly which modules run |

### Useful extras

| Flag | Meaning |
| --- | --- |
| `-o [DIR]` | Save `results.json`, `report.md`, link lists |
| `--threads N` | Concurrency (default 10) |
| `--delay S` | Minimum seconds between requests — be gentle |
| `--proxy URL` | Route through Burp/other proxy |
| `--user-agent UA` | Override random UA rotation |
| `--timeout S` | Per-request timeout (default 10) |
| `--max-author-id N` | How far author enumeration probes |
| `--crawl-depth N` | Crawler depth when using `--all` |
| `--endpoints-file PATH` | Merge your own wordlist into the scan (repeatable) |
| `-v / -q / --no-color / --no-banner` | Output control for humans and scripts |

---

## Tests

```sh
python3 -m unittest discover tests
```

---

## Disclaimer

This tool is intended for educational purposes and for use in authorized security testing scenarios only.
The end user is solely responsible for their actions. The developers assume no liability for misuse.

**Always obtain explicit permission from the website owner before scanning a target.**
