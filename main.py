#!/usr/bin/env python3
# main.py
import argparse
import datetime
import json
import os
import sys
from urllib.parse import urlparse

from core import __version__
from core import ui
from core.utils import (
    setup_session,
    sanitize_output,
    sanitize_filename,
    set_default_timeout,
    set_request_delay,
)
from core.scanner import scan_all_endpoints
from core.author_enum import author_enum
from core.crawler import crawl_site
from core.extract_info import extract_info, summarize_api_info
from core.admin_finder import find_admin_panels

MODULES = {
    "scan": {
        "label": "Endpoint Scan",
        "description": "Probe common/sensitive WordPress paths (.git, wp-config backups, xmlrpc...)",
        "default": True,
    },
    "brute": {
        "label": "User Enumeration",
        "description": "Reveal usernames by probing ?author=1..N",
        "default": True,
    },
    "extract": {
        "label": "REST API Extract",
        "description": "Pull public data from the WP REST API (users, posts, pages...)",
        "default": True,
    },
    "recon": {
        "label": "Extra Recon",
        "description": "WP version, plugins/themes, XML-RPC capabilities, REST namespaces",
        "default": True,
    },
    "headers": {
        "label": "Headers Audit",
        "description": "Security headers, server disclosure and cookie hardening",
        "default": True,
    },
    "backups": {
        "label": "Backup Hunt",
        "description": "Exposed debug logs, SQL dumps, archives, directory listings",
        "default": True,
    },
    "admin": {
        "label": "Admin Finder",
        "description": "Locate login panels moved off /wp-admin",
        "default": True,
    },
    "hints": {
        "label": "Vuln Hints",
        "description": "Match detected versions against built-in known-issue database",
        "default": True,
    },
    "crawl": {
        "label": "Crawler",
        "description": "Spider internal/external links (slowest module)",
        "default": False,
    },
}

QUICK_MODULES = ("scan",)
SEVERITY_WEIGHTS = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wpsploit",
        description="Wpsploit v%s — WordPress reconnaissance & attack-surface mapper" % __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
how it works:
  one flag is enough. the default run already performs every fast
  module (endpoints, users, REST API, recon, headers, backups,
  admin finder, vuln hints) and skips only the slow site crawler.

examples:
  wpsploit -u https://target.com            smart full recon (this is all you need)
  wpsploit -u https://target.com -o         same, but save JSON + markdown report
  wpsploit -u https://target.com --all      also crawl every link (slow)
  wpsploit -u https://target.com -Q         quick check, endpoints only
  wpsploit -u https://target.com \\
      --modules headers,hints               pick exactly what you want
  wpsploit                                  no args -> interactive wizard

tip: pipe through less or use -q for quiet summary-only output.
""" % {"prog": "wpsploit"},
    )

    target = parser.add_argument_group("target")
    target.add_argument("-u", "--url", metavar="URL", help="Target WordPress site URL")

    scope = parser.add_argument_group("scan scope (defaults are smart — usually skip this)")
    scope.add_argument("-Q", "--quick", action="store_true",
                       help="Endpoints only, skip everything else")
    scope.add_argument("-A", "--all", action="store_true",
                       help="Everything, including the slow crawler")
    scope.add_argument("--modules", metavar="a,b,c", default=None,
                       help="Comma-separated module list. Available: %s"
                            % ",".join(MODULES))

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", nargs="?", const="", default=None, metavar="DIR",
                     help="Save results.json + report.md (default dir: ./<domain>/)")
    out.add_argument("-v", "--verbose", action="store_true", help="Show low-value lines too")
    out.add_argument("-q", "--quiet", action="store_true", help="Only show the final summary")
    out.add_argument("--no-color", action="store_true", help="Disable colors/markup")
    out.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    perf = parser.add_argument_group("performance & stealth")
    perf.add_argument("--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    perf.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    perf.add_argument("--delay", type=float, default=0.0, help="Minimum seconds between requests (be gentle)")
    perf.add_argument("--proxy", metavar="URL", help="Route traffic through e.g. http://127.0.0.1:8080")
    perf.add_argument("--user-agent", metavar="UA", help="Override the random User-Agent")

    tune = parser.add_argument_group("fine tuning")
    tune.add_argument("--max-author-id", type=int, default=15, help="Max author ID to probe (default: 15)")
    tune.add_argument("--crawl-depth", type=int, default=2, help="Max crawl depth (default: 2)")
    tune.add_argument("--endpoints-file", action="append", default=[], metavar="PATH",
                      help="Extra endpoint wordlist merged into the scan (repeatable)")

    misc = parser.add_argument_group("misc")
    misc.add_argument("-i", "--interactive", action="store_true", help="Launch the guided wizard")
    misc.add_argument("-L", "--list-modules", action="store_true", help="List modules and exit")
    misc.add_argument("-V", "--version", action="version", version=f"wpsploit {__version__}")

    return parser
    parser.add_argument("--no-color", action="store_true", help="Disable colors/markup")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch the interactive wizard")
    parser.add_argument("-L", "--list-modules", action="store_true", help="List available modules and exit")
    parser.add_argument("-V", "--version", action="version", version=f"wpsploit {__version__}")

    return parser


def print_module_list():
    rows = []
    for key, m in MODULES.items():
        rows.append([key, m["label"], "yes" if m["default"] else "opt-in", m["description"]])
    ui.table("Wpsploit modules (default run includes every 'yes' module)", ["Key", "Name", "Default", "Description"], rows)


def interactive_wizard(parser):
    ui.rule("interactive wizard")
    try:
        url = input("Target URL (e.g. https://example.com): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    if not url:
        ui.err("No target provided.")
        sys.exit(2)

    print()
    print("  [1] Quick     endpoint scan only")
    print("  [2] Smart     every fast module (recommended)")
    print("  [3] Full      everything + site crawler")
    try:
        choice = input("Preset [1-3, default 2]: ").strip() or "2"
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)

    argv = ["-u", url]
    if choice == "1":
        argv.append("--quick")
    elif choice == "3":
        argv.append("--all")
    return parser.parse_args(argv)


def select_modules(args):
    if args.quick:
        return {key: key in QUICK_MODULES for key in MODULES}

    if args.modules is not None:
        requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in requested if m not in MODULES]
        if unknown or not requested:
            ui.err(
                "Unknown module(s): "
                + ", ".join(unknown or ["<empty>"])
                + f". Available: {', '.join(MODULES)}"
            )
            raise SystemExit(2)
        return {key: key in requested for key in MODULES}

    if args.all:
        return {key: True for key in MODULES}

    return {key: bool(meta["default"]) for key, meta in MODULES.items()}


def gather_findings(results):
    findings = []
    seen = set()

    def add(severity, module, title, detail=""):
        key = (title,)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {"severity": severity, "module": module, "title": title, "detail": str(detail)}
        )

    scan = results.get("endpoint_scan", {})
    for ep, data in scan.items():
        status = data.get("status")
        listing = data.get("listing")
        blank = data.get("blank")

        if ep == "/.git/" and status == "accessible":
            add("critical", "scan", "/.git directory is exposed", "Source history may be downloadable")
        elif ep == "/wp-config.php.save" and status == "accessible" and not blank:
            add("critical", "scan", "/wp-config.php.save is exposed", "Database credentials likely inside")
        elif ep == "/wp-json/wp/v2/users" and status == "accessible":
            add("high", "scan", "User listing is publicly reachable", "/wp-json/wp/v2/users returned 200")
        elif ep == "/wp-login.php?action=register" and status == "accessible":
            add("medium", "scan", "Open user registration", "Anyone can register an account")
        elif ep == "/readme.html" and status == "accessible":
            add("low", "scan", "readme.html is exposed", "Discloses WordPress version")
        elif ep == "/xmlrpc.php" and status == "accessible":
            add("info", "scan", "XML-RPC interface active", "Enable the recon module to test its capabilities")

        if listing:
            add("high", "scan", f"Open directory listing at {ep}", "Server exposes browsable index")

    users_enum = results.get("enumerated_users") or []
    api_users = results.get("extracted_info", {}).get("/wp-json/wp/v2/users")
    api_users_real = (
        isinstance(api_users, list)
        and bool(api_users)
        and isinstance(api_users[0], dict)
    )

    if users_enum:
        s_users = ", ".join(sanitize_output(u) for u in users_enum)
        add(
            "high",
            "brute",
            f"{len(users_enum)} usernames enumerated via author IDs",
            s_users,
        )

    if api_users_real:
        slugs = [sanitize_output(u.get("slug")) for u in api_users if isinstance(u, dict)]
        slugs = [s for s in slugs if s]
        if slugs:
            add(
                "high",
                "extract",
                f"{len(slugs)} users exposed via REST API",
                ", ".join(slugs),
            )

    admin_panels = results.get("found_admin_panels") or []
    if admin_panels:
        add(
            "medium",
            "admin",
            f"{len(admin_panels)} admin panel location(s) discovered",
            "; ".join(admin_panels[:5]),
        )

    for hit in results.get("backup_hits") or []:
        add(hit["severity"], "backups", hit["title"], hit["detail"])

    for h in results.get("header_findings") or []:
        add(h["severity"], "headers", h["title"], h["detail"])

    for h in results.get("vuln_hints") or []:
        add(h["severity"], "hints", f"Known-issue hint: {h['target']}", h["note"])

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


def compute_risk(findings):
    score = 100
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        score -= SEVERITY_WEIGHTS.get(sev, 0)
    score = max(0, min(100, score))
    grade = "F"
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    return score, grade, counts


def _has_real_users(results):
    if results.get("enumerated_users"):
        return True
    api_users = results.get("extracted_info", {}).get("/wp-json/wp/v2/users")
    return (
        isinstance(api_users, list)
        and bool(api_users)
        and isinstance(api_users[0], dict)
    )


def next_step_suggestions(results, findings):
    tips = []
    severities = {f["severity"] for f in findings}
    if "critical" in severities or "high" in severities:
        tips.append("Triage CRITICAL/HIGH items first - they are usually quick wins for attackers")
    if _has_real_users(results):
        tips.append("Exposed usernames enable credential-stuffing: enforce strong passwords + 2FA")
    if any(f.get("listing") for f in (results.get("endpoint_scan") or {}).values()):
        tips.append("Disable directory indexing in the web server config")
    if (results.get("xmlrpc") or {}).get("status") == 200:
        tips.append("Block xmlrpc.php at the web server level if you do not need it")
    if results.get("wp_version_info"):
        tips.append("Keep WordPress core, plugins and themes updated; verify hinted versions manually")
    if results.get("crawled_internal_links"):
        n = len(results["crawled_internal_links"])
        tips.append(f"Review the {n} crawled internal links for staging/test content")
    if not tips:
        tips.append("No obvious quick wins; consider deeper manual testing")
    return tips[:4]


def build_markdown_report(base_url, results, findings, score, grade, counts, selected):
    today = datetime.date.today().isoformat()
    lines = [
        "# Wpsploit Report",
        "",
        f"- **Target:** {base_url}",
        f"- **Date:** {today}",
        f"- **Tool:** Wpsploit v{__version__}",
        f"- **Modules run:** {', '.join(k for k, v in selected.items() if v)}",
        f"- **Risk score:** {score}/100 ({grade})",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += ["| Severity | Module | Issue | Detail |", "| --- | --- | --- | --- |"]
        for f in findings:
            detail = f["detail"].replace("|", "\\|")
            title = f["title"].replace("|", "\\|")
            lines.append(
                f"| {f['severity'].upper()} | {f['module']} | {title} | {detail} |"
            )
    else:
        lines.append("_No findings._")

    lines += ["", "## Module details", ""]

    scan = results.get("endpoint_scan") or {}
    interesting = {ep: d for ep, d in scan.items() if d.get("status") in ("accessible", "protected")}
    if interesting:
        lines += ["### Endpoint scan", ""]
        for ep, d in sorted(interesting.items()):
            lines.append(f"- `{ep}` -> {d['status']} (HTTP {d.get('status_code')})")
        lines.append("")

    if results.get("enumerated_users"):
        lines += ["### Enumerated users", ""]
        lines += [f"- `{u}`" for u in results["enumerated_users"]]
        lines.append("")

    plugins = results.get("plugins") or []
    themes = results.get("themes") or []
    if plugins or themes or results.get("wp_version_info"):
        lines += ["### Extra recon", ""]
        vi = results.get("wp_version_info") or {}
        versions = vi.get("meta") or []
        lines.append(f"- WP version hints: {versions}")
        lines.append(f"- Plugins ({len(plugins)}): {', '.join(plugins) or 'n/a'}")
        lines.append(f"- Themes ({len(themes)}): {', '.join(themes) or 'n/a'}")
        ns = results.get("rest_namespaces")
        if ns:
            lines.append(f"- REST namespaces: {', '.join(ns)}")
        lines.append("")

    headers_report = results.get("headers_audit") or {}
    if headers_report:
        lines += ["### Headers audit", ""]
        for m in headers_report.get("missing", []):
            lines.append(f"- Missing `{m['header']}` ({m['severity']}): {m['why']}")
        for k, v in (headers_report.get("disclosure") or {}).items():
            lines.append(f"- `{k}: {v}`")
        lines.append("")

    if results.get("crawled_internal_links") is not None:
        internal = results.get("crawled_internal_links") or []
        external = results.get("crawled_external_links") or []
        lines += ["### Crawler", "", f"- Internal links: {len(internal)}", f"- External links: {len(external)}", ""]

    lines.append("---")
    lines.append("_Generated by Wpsploit. Use only against systems you are authorized to test._")
    return "\n".join(lines) + "\n"


def save_reports(output_dir, base_url, results, findings, score, grade, counts, selected):
    os.makedirs(output_dir, exist_ok=True)
    results_path = os.path.join(output_dir, "results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    report_path = os.path.join(output_dir, "report.md")
    with open(report_path, "w") as f:
        f.write(build_markdown_report(base_url, results, findings, score, grade, counts, selected))

    if results.get("crawled_internal_links") is not None:
        with open(os.path.join(output_dir, "internal_links.txt"), "w") as f:
            f.write("\n".join(results.get("crawled_internal_links") or []))
        with open(os.path.join(output_dir, "external_links.txt"), "w") as f:
            f.write("\n".join(results.get("crawled_external_links") or []))

    ui.ok(f"JSON results saved to {results_path}")
    ui.ok(f"Markdown report saved to {report_path}")


def run_pipeline(session, base_url, args, selected, results):
    extra_files = []
    for path in args.endpoints_file:
        try:
            with open(path) as f:
                extra_files += [l.strip() for l in f if l.strip()]
        except OSError as e:
            ui.err(f"Could not read endpoints file {path}: {e}")

    if selected.get("scan"):
        ui.rule("endpoint scan")
        with ui.status("Scanning common & sensitive endpoints..."):
            results["endpoint_scan"] = scan_all_endpoints(
                session, base_url, args.threads, extra_endpoints=extra_files
            )

    if selected.get("brute"):
        ui.rule("user enumeration")
        with ui.status(f"Probing ?author=1..{args.max_author_id}..."):
            users = author_enum(session, base_url, max_id=args.max_author_id, threads=args.threads)
        results["enumerated_users"] = users
        if users:
            for u in users:
                ui.ok(f"user via author probing: {sanitize_output(u)}")
        else:
            ui.info("No users found via author enumeration")

    if selected.get("admin_finder"):
        ui.rule("admin finder")
        with ui.status("Searching for admin panels..."):
            panels = find_admin_panels(session, base_url, args.threads)
        results["found_admin_panels"] = panels
        if panels:
            for p in panels:
                ui.ok(f"admin panel candidate: {sanitize_output(p)}")
        else:
            ui.info("No additional admin panels found")

    if selected.get("extract"):
        ui.rule("rest api extraction")
        with ui.status("Extracting REST API data..."):
            api_data = extract_info(session, base_url, threads=args.threads)
        results["extracted_info"] = api_data
        summary = summarize_api_info(api_data)
        for ep, meta in sorted(summary.items()):
            if meta["type"] == "list" and meta["count"]:
                ui.sub(f"{ep} -> {meta['count']} item(s)")

    if selected.get("recon"):
        ui.rule("extra recon")
        from core.extra_recon import (
            identify_wp_version,
            enumerate_plugins_and_themes,
            extract_versions_from_assets,
            fetch_user_info_json,
            enumerate_rest_namespaces,
            check_xmlrpc_available,
            VERSION_CHECK_FOUND,
            VERSION_CHECK_REQUEST_ERROR,
        )

        with ui.status("Running extra reconnaissance..."):
            try:
                r = session.get(base_url, timeout=args.timeout)
                html_content = r.text
            except Exception:
                html_content = ""

            version_info = identify_wp_version(session, base_url, html_content)
            plugins, themes = enumerate_plugins_and_themes(session, base_url, html_content)
            asset_versions = extract_versions_from_assets(session, base_url, html_content)
            user_json = fetch_user_info_json(session, base_url)
            namespaces, ns_error = enumerate_rest_namespaces(session, base_url)
            xmlrpc_status, xmlrpc_resp = check_xmlrpc_available(session, base_url)

        results["wp_version_info"] = version_info
        results["plugins"] = plugins
        results["themes"] = themes
        results["asset_versions"] = asset_versions
        results["user_json"] = user_json
        results["rest_namespaces"] = namespaces
        results["rest_namespaces_error"] = ns_error
        results["xmlrpc"] = {"status": xmlrpc_status, "response": xmlrpc_resp}

        versions_found = version_info.get("meta") or []
        for source, st in version_info.get("statuses", {}).items():
            if st == VERSION_CHECK_FOUND and source != "meta":
                ui.ok(f"WP version marker [{source}]: {sanitize_output(version_info.get(source))}")
            elif st == VERSION_CHECK_REQUEST_ERROR:
                e = (version_info.get("errors") or {}).get(source, "?")
                ui.warn(f"WP version check [{source}] failed ({sanitize_output(e)})")
        if versions_found:
            ui.ok(f"WP version (meta): {sanitize_output(versions_found[0])}")
        else:
            ui.info("No WP version marker found (good hygiene)")
        if plugins:
            ui.sub(f"plugins ({len(plugins)}): {', '.join(sanitize_output(p) for p in plugins[:10])}")
        else:
            ui.sub("plugins: none visible in HTML")
        if themes:
            ui.sub(f"themes ({len(themes)}): {', '.join(sanitize_output(t) for t in themes)}")
        else:
            ui.sub("themes: none visible in HTML")
        if namespaces:
            ui.sub(f"REST namespaces: {', '.join(namespaces[:10])}")
        if xmlrpc_status == 200:
            ui.warn(f"XML-RPC responds (HTTP 200): {sanitize_output((xmlrpc_resp or '')[:120])}")
        else:
            ui.info(f"XML-RPC status: {xmlrpc_status}")

    if selected.get("headers"):
        ui.rule("headers audit")
        from core.headers_check import analyze_headers, header_findings

        with ui.status("Auditing security headers & cookies..."):
            report = analyze_headers(session, base_url)
            hf = header_findings(report)
        results["headers_audit"] = report
        results["header_findings"] = hf
        if hf:
            for f in hf:
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "cyan"}
                c = sev_color.get(f["severity"], "white")
                ui.raw(f"  [{c}]{f['severity'].upper():<8}[/{c}] {f['title']}")
        else:
            ui.ok("All audited security headers present")

    if selected.get("backups"):
        ui.rule("backup hunt")
        from core.backup_finder import find_backups, backup_findings

        with ui.status("Hunting exposed backups/logs/dumps..."):
            hits = find_backups(session, base_url, threads=args.threads)
            bf = backup_findings(hits)
        results["backup_hits"] = hits
        results["backup_findings"] = bf
        if hits:
            for h in hits:
                ui.warn(f"[{h['severity'].upper()}] {h['url']} — {h['detail']}")
        else:
            ui.ok("No exposed backups or logs found")

    if selected.get("hints"):
        ui.rule("vulnerability hints")
        from core.vuln_hints import collect_hints, hint_findings

        with ui.status("Matching versions against known-issue database..."):
            hints = collect_hints(
                plugins=results.get("plugins"),
                themes=results.get("themes"),
                version_info=results.get("wp_version_info"),
                namespaces=results.get("rest_namespaces"),
            )
            vf = hint_findings(hints)
        results["vuln_hints"] = hints
        results["hint_findings"] = vf
        if hints:
            for h in hints:
                ui.warn(f"[{h['severity'].upper()}] {h['target']}: {h['note']}")
        else:
            ui.info("No known-issue matches for detected components")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    ui.init(no_color=args.no_color, quiet=args.quiet, verbose=args.verbose)

    if args.list_modules:
        print_module_list()
        return 0

    if args.interactive or (not args.url and sys.stdin.isatty()):
        print()
        ui.banner(__version__)
        args = interactive_wizard(parser)
        # re-init in case flags differ
        ui.init(no_color=args.no_color, quiet=args.quiet, verbose=args.verbose)

    if not args.url:
        parser.print_help()
        return 2

    url = args.url.strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        ui.err(f"Invalid URL: {args.url}")
        return 2
    base_url = url.rstrip("/")
    domain = sanitize_filename(parsed.netloc)

    set_default_timeout(args.timeout)
    set_request_delay(args.delay)

    selected = select_modules(args)

    if not args.no_banner and not args.quick:
        ui.banner(__version__)
    elif not args.no_banner and args.quick:
        ui.info(f"wpsploit v{__version__} — quick scan")
    ui.info(f"Target : {base_url}")
    ui.info(f"Threads: {args.threads}   Timeout: {args.timeout}s   Delay: {args.delay}s")
    if args.proxy:
        ui.info(f"Proxy  : {args.proxy}")
    ui.info("Modules: " + ", ".join(k for k, v in selected.items() if v))

    output_dir = None
    if args.output is not None:
        output_dir = args.output if isinstance(args.output, str) and args.output else domain
        ui.ok(f"Reports will be saved to '{output_dir}/'")

    session = setup_session(proxy=args.proxy, user_agent=args.user_agent)

    results = {}
    try:
        run_pipeline(session, base_url, args, selected, results)
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted — showing partial results")
    except SystemExit:
        raise

    ui.rule("findings summary")
    findings = gather_findings(results)
    if findings:
        ui.findings_table(findings)
    else:
        ui.ok("No issues automatically identified.")

    score, grade, counts = compute_risk(findings)
    ui.risk_summary(score, grade, counts)
    ui.next_steps(next_step_suggestions(results, findings))

    if output_dir:
        save_reports(output_dir, base_url, results, findings, score, grade, counts, selected)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
