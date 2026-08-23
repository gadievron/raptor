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
