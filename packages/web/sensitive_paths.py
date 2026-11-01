"""Shared sensitive-path catalog.

One source of truth for "this path is worth a closer look":
``SensitiveFileCheck`` probes the catalog directly, and external
discovery (ffuf) hits are classified against it — plus a few shape
heuristics — to become re-verification CANDIDATES for that same check.
External tools never mint findings; the check re-probes every
candidate with the in-Python client so findings always carry
first-party request/response evidence.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Exact-path catalog: path -> operator-facing label.
SENSITIVE_PATHS: dict[str, str] = {
    "/.git/HEAD": "Git repository exposed",
    "/.git/config": "Git config exposed",
    "/.svn/entries": "SVN metadata exposed",
    "/.hg/hgrc": "Mercurial config exposed",
    "/.env": ".env file exposed",
    "/.env.local": ".env file exposed",
    "/.env.production": ".env file exposed",
    "/phpinfo.php": "PHP info page exposed",
    "/info.php": "PHP info page exposed",
    "/test.php": "PHP test page exposed",
    "/server-status": "Apache mod_status exposed",
    "/server-info": "Apache mod_info exposed",
    "/nginx_status": "nginx stub_status exposed",
    "/actuator/env": "Spring Boot env actuator exposed",
    "/actuator/heapdump": "Spring Boot heap dump exposed",
    "/actuator/threaddump": "Spring Boot thread dump exposed",
    "/debug/vars": "Go debug vars exposed",
    "/debug/pprof": "Go pprof endpoint exposed",
    "/config.php": "Config file exposed",
    "/wp-config.php": "WordPress config exposed",
    "/database.yml": "Database credentials file exposed",
    "/secrets.json": "Secrets file exposed",
    "/id_rsa": "Private key exposed",
    "/.ssh/id_rsa": "Private key exposed",
    "/backup.sql": "Database dump exposed",
    "/dump.sql": "Database dump exposed",
    "/.DS_Store": "Directory metadata exposed",
    "/web.config": "IIS config exposed",
    "/composer.json": "Dependency manifest exposed",
    "/package.json": "Dependency manifest exposed",
}

# Shape heuristics for paths not in the exact catalog.
_SHAPE_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\.(?:bak|old|orig|save|swp|copy)$", re.IGNORECASE),
     "Backup file exposed"),
    (re.compile(r"\.(?:sql|sqlite3?|db)$", re.IGNORECASE),
     "Database file exposed"),
    (re.compile(r"\.(?:zip|tar|tar\.gz|tgz|7z|rar)$", re.IGNORECASE),
     "Archive exposed"),
    (re.compile(r"\.(?:pem|key|p12|pfx|jks)$", re.IGNORECASE),
     "Key material exposed"),
    (re.compile(r"\.(?:log|out)$", re.IGNORECASE), "Log file exposed"),
    (re.compile(r"^/\.(?!well-known)", re.IGNORECASE), "Dotfile exposed"),
    (re.compile(r"^/actuator(?:/|$)", re.IGNORECASE),
     "Spring Boot actuator exposed"),
    (re.compile(r"^/\.git(?:/|$)", re.IGNORECASE), "Git repository exposed"),
)

# What a catalog entry's body looks like when the file is really served.
# A status code alone cannot tell the file from a login wall, a custom
# error page or a soft-404 that differs from the calibration probe, so a
# finding needs the body to match. Files must also not be HTML.
_ENV = (re.compile(rb"^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=", re.M),
        "KEY=value lines")
_PHPINFO = (re.compile(rb"PHP Version \d|phpinfo\(\)</title>"),
            "the phpinfo() page")
_PHP_SOURCE = (re.compile(rb"<\?php"), "unexecuted PHP source")
_PRIVATE_KEY = (re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
                "a PEM private key")
_SQL_DUMP = (re.compile(rb"CREATE TABLE|INSERT INTO|-- (?:MySQL|MariaDB) dump"
                        rb"|PostgreSQL database dump", re.I),
             "SQL dump statements")

FILE_SIGNATURES: dict[str, tuple[re.Pattern[bytes], str]] = {
    "/.git/HEAD": (re.compile(rb"\A(?:ref: refs/|[0-9a-f]{40}\s*\Z)"),
                   "a git HEAD ref"),
    "/.git/config": (re.compile(rb"^\[core\]", re.M), "a git [core] section"),
    "/.svn/entries": (re.compile(rb"\A(?:\d+[ \t]*\r?\n|<\?xml[^>]*>\s*<wc-entries)"),
                      "an SVN entries header"),
    "/.hg/hgrc": (re.compile(rb"^\[(?:paths|ui|extensions|hooks|web)\]", re.M),
                  "a Mercurial hgrc section"),
    "/.env": _ENV,
    "/.env.local": _ENV,
    "/.env.production": _ENV,
    "/nginx_status": (re.compile(rb"\AActive connections: \d+"),
                      "nginx stub_status counters"),
    "/actuator/env": (re.compile(rb'"(?:propertySources|activeProfiles)"\s*:'),
                      "Spring environment JSON"),
    "/actuator/heapdump": (re.compile(rb"\A(?:JAVA PROFILE 1\.0|\x1f\x8b)"),
                           "an HPROF heap dump"),
    "/actuator/threaddump": (re.compile(rb'"thread(?:s"\s*:\s*\[|Name"\s*:)'),
                             "a JVM thread dump"),
    "/debug/vars": (re.compile(rb'"(?:cmdline|memstats)"\s*:'),
                    "Go expvar JSON"),
    "/config.php": _PHP_SOURCE,
    "/wp-config.php": _PHP_SOURCE,
    "/database.yml": (re.compile(rb"^\s*(?:adapter|database|username|password|host)\s*:",
                                 re.M),
                      "database settings in YAML"),
    "/secrets.json": (re.compile(rb'"[^"\n]*(?:secret|key|token|password|credential)'
                                 rb'[^"\n]*"\s*:', re.I),
                      "secret-named JSON keys"),
    "/id_rsa": _PRIVATE_KEY,
    "/.ssh/id_rsa": _PRIVATE_KEY,
    "/backup.sql": _SQL_DUMP,
    "/dump.sql": _SQL_DUMP,
    "/.DS_Store": (re.compile(rb"\A\x00\x00\x00\x01Bud1"), "a .DS_Store header"),
    "/web.config": (re.compile(rb"<configuration[\s>]"), "an IIS <configuration>"),
    "/composer.json": (re.compile(rb'"(?:require|autoload)"\s*:'),
                       "a Composer manifest"),
    "/package.json": (re.compile(rb'"(?:dependencies|devDependencies|scripts)"\s*:'),
                      "an npm manifest"),
}

# Status pages are HTML by nature, so only their own markers count.
PAGE_SIGNATURES: dict[str, tuple[re.Pattern[bytes], str]] = {
    "/phpinfo.php": _PHPINFO,
    "/info.php": _PHPINFO,
    "/server-status": (re.compile(rb"Apache Server Status|Total Accesses: \d"),
                       "Apache mod_status counters"),
    "/server-info": (re.compile(rb"Apache Server Information"),
                     "the Apache mod_info page"),
    "/debug/pprof": (re.compile(rb"Types of profiles available|/debug/pprof/goroutine"),
                     "the Go pprof index"),
}

_HTML = re.compile(rb"\A(?:\xef\xbb\xbf)?\s*<(?:!doctype\s+html|html|head|body)\b", re.I)
# Signatures sit near the top of every file they describe.
_SNIFF_BYTES = 64 * 1024


def served_content(path: str, body: bytes) -> str | None:
    """What in ``body`` shows the file at ``path`` is really served, or None.

    A path with no signature (a shape-rule or external candidate, or a
    catalog entry like ``/test.php``) must at least be a non-empty,
    non-HTML body: soft-404s, login walls and SPA shells are HTML.
    """
    head = (body or b"")[:_SNIFF_BYTES]
    key = path if path in FILE_SIGNATURES or path in PAGE_SIGNATURES else path.rstrip("/")
    if key in PAGE_SIGNATURES:
        pattern, description = PAGE_SIGNATURES[key]
        return description if pattern.search(head) else None
    if not head.strip() or _HTML.search(head):
        return None
    if key in FILE_SIGNATURES:
        pattern, description = FILE_SIGNATURES[key]
        return description if pattern.search(head) else None
    return "a non-HTML body"


def classify_path(path_or_url: str) -> str | None:
    """The sensitivity label for a path (or URL), or None."""
    path = urlparse(path_or_url).path or "/"
    label = SENSITIVE_PATHS.get(path) or SENSITIVE_PATHS.get(path.rstrip("/"))
    if label:
        return label
    for pattern, shape_label in _SHAPE_RULES:
        if pattern.search(path):
            return shape_label
    return None


def sensitive_candidates(urls: list[str], *, cap: int = 50) -> list[tuple[str, str]]:
    """(path, label) candidates from externally-discovered URLs."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url in urls:
        path = urlparse(url).path or "/"
        if path in seen:
            continue
        seen.add(path)
        label = classify_path(path)
        if label:
            out.append((path, label))
            if len(out) >= cap:
                break
    return out
