# Wpsploit - WordPress Reconnaissance Tool

![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

### Made by Doraemon Cyber Team

Wpsploit is a powerful and fast command-line tool for performing comprehensive reconnaissance on WordPress websites. It helps security researchers and penetration testers gather essential information about a target WordPress installation quickly and efficiently.

---

## Features

-   **Endpoint Scanning:** Scans for common and sensitive WordPress files and directories (e.g., `/wp-admin/`, `/wp-config.php.save`, `/wp-json/`).
-   **User Enumeration:** Discovers valid usernames by brute-forcing author IDs (`/?author=1`, `/?author=2`, etc.).
-   **Site Crawler:** Crawls the website to discover internal links and map out the site structure.
-   **API Data Extraction:** Attempts to extract public data from accessible WordPress REST API endpoints, including users, posts, pages, and media.
-   **Concurrent Scanning:** Uses multithreading to perform scans quickly.
-   **Automatic JSON Output:** Saves all scan results to a folder named after the target's domain for organized record-keeping.

---

## Setup & Installation

Wpsploit is easy to set up. All you need is Python 3 and Git.

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/Baba01hacker666/Wpsploit.git
    ```

2.  **Navigate to the project directory:**
    ```sh
    cd Wpsploit
    ```

3.  **Install the required Python packages:**
    ```sh
    pip3 install requests beautifulsoup4
    ```
    *Note: Depending on your system, you may need to use `pip` instead of `pip3`.*

---

## How to Use

The tool is operated from the command line. You can view all available options by using the `-h` or `--help` flag.

```sh
python3 main.py -h
```

```
usage: main.py [-h] -u URL [--threads THREADS] [--output] [--brute] [--crawl] [--extract]

WordPress Info Gatherer CLI Tool

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  Target WordPress site URL
  --threads THREADS  Thread count
  --output           Save results to a folder named after the target domain
  --brute            Enable ?author= ID brute-forcing
  --crawl            Enable site crawling
  --extract          Enable API data extraction
```

### Arguments

| Argument        | Short | Description                                                   |
| --------------- | ----- | ------------------------------------------------------------- |
| `--url`         | `-u`  | **(Required)** The target WordPress site URL.                 |
| `--threads`     |       | The number of concurrent threads for scanning.                |
| `--output`      |       | A flag to save results in an automatically created directory. |
| `--brute`       |       | Enables the author username enumeration feature.              |
| `--crawl`       |       | Enables the internal link crawler.                            |
| `--extract`     |       | Enables data extraction from the WP REST API.                 |

---

## Example Commands

### 1. Basic Scan
Perform a simple scan for common endpoints on a target website.

```sh
python3 main.py -u https://target-wordpress-site.com
```

### 2. Comprehensive Scan
Run a full scan, including user enumeration, site crawling, and API data extraction.

```sh
python3 main.py -u https://target-wordpress-site.com --brute --crawl --extract
```

### 3. Full Scan with Output
Run a full scan and automatically save the findings. This command will create a folder named after the target's domain and save a `results.json` file inside it.

```sh
python3 main.py -u https://target-wordpress-site.com --brute --crawl --extract --output
```

### 4. Fast Scan
Increase the number of threads to speed up the endpoint scanning process (use with caution to avoid overwhelming the server).

```sh
python3 main.py -u https://target-wordpress-site.com --threads 50
```

---

## Disclaimer

This tool is intended for educational purposes and for use in authorized security testing scenarios only. The end user is solely responsible for their actions. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

**Always obtain explicit permission from the website owner before scanning a target.**
