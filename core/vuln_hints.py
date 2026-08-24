# core/vuln_hints.py
import re

KNOWN_PLUGIN_HINTS = {
    "revslider": ("critical", "Slider Revolution had critical LFI/RCE vulnerabilities widely exploited in the wild"),
    "contact-form-7": ("high", "Versions before 5.3.9/5.4.2 allowed unauthenticated arbitrary file upload (CVE-2020-35489)"),
    "wp-file-manager": ("critical", "Versions before 6.9 allowed unauthenticated RCE (CVE-2020-25213)"),
    "duplicator": ("critical", "Versions before 1.3.28 had unauthenticated directory traversal leading to site takeover (CVE-2020-11738 era issues)"),
    "updraftplus": ("high", "Versions before 1.16.7 allowed subscriber-level backup downloads (CVE-2020-11738)"),
    "advanced-custom-fields": ("medium", "Versions before 6.1.5 had reflected XSS (CVE-2023-30777); ACF < 5.x had multiple XSS issues"),
    "elementor": ("medium", "Elementor has had multiple high-profile XSS and privilege issues; verify installed version is current"),
    "woocommerce": ("medium", "WooCommerce periodically ships high-severity fixes; verify version is up to date"),
    "ninja-forms": ("medium", "Ninja Forms had unauthenticated SQL injection fixed in 3.6.3 (CVE-2022-33819)"),
    "w3-total-cache": ("high", "W3 Total Cache had SSRF/RCE chains historically; verify current version"),
    "wp-super-cache": ("medium", "WP Super Cache had RCE via comment spam chain (2013-era) and later auth issues"),
    "kingcomposer": ("high", "KingComposer before 2.9.6/2.9.7 allowed authenticated RCE and had XSS issues"),
    "sitepress-multilingual-cms": ("medium", "WPML had multiple information disclosure bugs; verify version"),
    "all-in-one-wp-migration": ("high", "Export files are often guessable/enumerable when plugin is active"),
    "really-simple-ssl": ("info", "Security plugin detected: review its hardening report manually"),
    "wordfence": ("info", "Wordfence detected: check scan results and blocking config"),
}

KNOWN_THEME_HINTS = {
    "twentyten": ("low", "Default theme from 2010, no longer supported by core updates"),
    "twentyeleven": ("low", "Legacy default theme, no longer maintained"),
    "twentytwelve": ("low", "Legacy default theme, no longer maintained"),
    "twentythirteen": ("low", "Legacy default theme, no longer maintained"),
    "twentyfourteen": ("low", "Legacy default theme, no longer maintained"),
    "twentyfifteen": ("low", "Legacy default theme, nearing end of maintenance"),
    "twentysixteen": ("low", "Legacy default theme"),
    "divi": ("medium", "Divi has had several vulnerable releases; verify the installed version"),
    "avada": ("medium", "Avada shipped security fixes for object injection and XSS; verify version"),
}

WP_CORE_HINTS = [
    {"below": "4.9.16", "severity": "critical", "note": "Very old WordPress branch with many public exploits (5.x+ RCE chains do not apply but dozens of CVEs do)"},
    {"below": "5.2.8", "severity": "critical", "note": "Multiple critical vulnerabilities fixed since 5.2.8"},
    {"below": "5.6.3", "severity": "high", "note": "Several high-severity vulns fixed between 5.6.3 and 5.8 (incl. PHP object injection)"},
    {"below": "6.0.4", "severity": "medium", "note": "Security releases after 6.0.4 include stored XSS and SSRF fixes"},
    {"below": "6.3.3", "severity": "medium", "note": "6.3.3+ fixed contributor-level stored XSS issues"},
    {"below": "6.4.3", "severity": "high", "note": "WordPress 6.4.3 (April 2024) fixed a remote code execution issue via POP chain"},
]

NAMESPACE_PLUGIN_MAP = {
    "contact-form-7": "contact-form-7",
    "wc/v1": None,
    "wc/v2": None,
    "wc/v3": None,
    "yoast": None,
    "acf/v3": "advanced-custom-fields",
    "jetpack": None,
    "litespeed": None,
    "redirection": None,
}


def version_tuple(version):
    nums = re.findall(r"\d+", str(version))[:4]
    return tuple(int(n) for n in nums)


def is_version_below(version, threshold):
    try:
        v = version_tuple(version)
        t = version_tuple(threshold)
        size = max(len(v), len(t))
        v = v + (0,) * (size - len(v))
        t = t + (0,) * (size - len(t))
        return v < t
    except (TypeError, ValueError):
        return False


def _normalize_plugin(name):
    n = name.lower().strip()
    aliases = {
        "cf7": "contact-form-7",
        "slider-revolution": "revslider",
        "rev-slider": "revslider",
        "acf": "advanced-custom-fields",
        "updraft": "updraftplus",
        "wp-filemanager": "wp-file-manager",
        "file-manager": "wp-file-manager",
        "woo": "woocommerce",
        "w3tc": "w3-total-cache",
        "wpml": "sitepress-multilingual-cms",
    }
    return aliases.get(n, n)


def hint_for_plugin(plugin_name):
    key = _normalize_plugin(plugin_name)
    if key in KNOWN_PLUGIN_HINTS:
        sev, note = KNOWN_PLUGIN_HINTS[key]
        return {
            "target": f"plugin:{plugin_name}",
            "severity": sev,
            "note": note,
        }
    return None


def hint_for_theme(theme_name):
    key = theme_name.lower().strip()
    if key in KNOWN_THEME_HINTS:
        sev, note = KNOWN_THEME_HINTS[key]
        return {
            "target": f"theme:{theme_name}",
            "severity": sev,
            "note": note,
        }
    return None


def hints_for_wp_core(version_info):
    """version_info is the dict returned by extra_recon.identify_wp_version."""
    hints = []
    versions = set()
    meta = version_info.get("meta") or []
    if isinstance(meta, list):
        for m in meta:
            match = re.search(r"(\d+\.\d+(?:\.\d+)*)", str(m))
            if match:
                versions.add(match.group(1))
    for ep in ("/readme.html", "/license.txt"):
        val = version_info.get(ep)
        if val:
            versions.add(str(val))

    for v in versions:
        for h in WP_CORE_HINTS:
            if is_version_below(v, h["below"]):
                hints.append(
                    {
                        "target": f"wordpress-core:{v}",
                        "severity": h["severity"],
                        "note": h["note"],
                    }
                )
                break
        else:
            hints.append(
                {
                    "target": f"wordpress-core:{v}",
                    "severity": "info",
                    "note": "Detected version appears recent; still verify against latest release",
                }
            )
        break

    return hints


def collect_hints(plugins=None, themes=None, version_info=None, namespaces=None):
    plugins = plugins or []
    themes = themes or []
    hints = []

    hints.extend(hints_for_wp_core(version_info or {}))

    seen = set()
    for p in plugins:
        h = hint_for_plugin(p)
        if h and h["target"] not in seen:
            seen.add(h["target"])
            hints.append(h)

    for t in themes:
        h = hint_for_theme(t)
        if h and h["target"] not in seen:
            seen.add(h["target"])
            hints.append(h)

    for ns in namespaces or []:
        for pattern, plugin in NAMESPACE_PLUGIN_MAP.items():
            if ns.startswith(pattern) and plugin and plugin not in [p.lower() for p in plugins]:
                h = hint_for_plugin(plugin)
                if h and h["target"] not in seen:
                    seen.add(h["target"])
                    h["note"] += " (detected via REST API namespace)"
                    hints.append(h)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    hints.sort(key=lambda x: order.get(x["severity"], 9))
    return hints


def hint_findings(hints):
    findings = []
    for h in hints:
        findings.append(
            {
                "severity": h["severity"],
                "module": "hints",
                "title": f"Known-issue hint for {h['target']}",
                "detail": h["note"] + " (verify installed version)",
            }
        )
    return findings
