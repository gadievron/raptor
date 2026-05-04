"""Common path discovery -- probes a built-in wordlist for sensitive endpoints.

Covers admin panels, config files, debug endpoints, backup files,
API docs, framework-specific paths, and version control exposure.
Returns URLs that respond with 200, 301, 302, or 403 (forbidden
is itself a signal that something exists there).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, List
from urllib.parse import urlparse

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 403, 405}

_WORDLIST = [
    # Admin / management interfaces
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/admin/login", "/admin/dashboard", "/admin/config",
    "/panel", "/cpanel", "/webadmin", "/manage", "/manager",
    "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
    "/jenkins", "/jenkins/", "/gitlab", "/gitea",
    "/grafana", "/grafana/", "/kibana", "/kibana/",
    "/portainer", "/rancher",

    # API and documentation
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/api/v3", "/rest", "/rest/", "/graphql", "/graphql/",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/",
    "/redoc", "/docs", "/docs/",
    "/v1", "/v2", "/v3",

    # Health, status, and debug
    "/health", "/healthz", "/health/", "/ready", "/readyz",
    "/status", "/status/", "/ping", "/metrics",
    "/actuator", "/actuator/", "/actuator/health", "/actuator/env",
    "/actuator/metrics", "/actuator/beans", "/actuator/mappings",
    "/actuator/loggers", "/actuator/httptrace", "/actuator/info",
    "/debug", "/debug/", "/debug/vars", "/debug/pprof",
    "/console", "/h2-console", "/rails/info",
    "/_cat", "/_cat/indices", "/_nodes",  # Elasticsearch

    # Version control exposure
    "/.git", "/.git/HEAD", "/.git/config",
    "/.svn", "/.svn/entries", "/.hg", "/.hg/hgrc",
    "/.bzr", "/.bzr/README",
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/.env.backup",

    # Config and secret files
    "/config", "/config.php", "/config.json", "/config.yaml",
    "/config.yml", "/config.xml", "/settings.py", "/settings.php",
    "/configuration.php", "/wp-config.php", "/wp-config.php.bak",
    "/database.yml", "/database.json",
    "/secrets.json", "/credentials.json", "/credentials.yml",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/app.config",
    "/composer.json", "/package.json", "/requirements.txt",
    "/Gemfile", "/Makefile", "/Dockerfile",
    "/docker-compose.yml", "/docker-compose.yaml",

    # Backup and temp files
    "/backup", "/backup/", "/backups/",
    "/db.sql", "/database.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz",
    "/site.zip", "/www.zip",

    # Framework-specific
    "/info.php", "/phpinfo.php", "/test.php",
    "/server-status", "/server-info",   # Apache mod_status
    "/nginx_status",                     # nginx stub_status
    "/wp-json", "/wp-json/",            # WordPress REST
    "/xmlrpc.php",                       # WordPress XML-RPC
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/oauth/token", "/auth/token", "/token",
    "/login", "/logout", "/signup", "/register",
    "/forgot-password", "/reset-password",
    "/robots.txt", "/sitemap.xml",

    # Spring Boot / Java
    "/trace", "/heapdump", "/threaddump",

    # Node / Express
    "/__webpack_hmr",

    # Monitoring
    "/prometheus", "/jaeger",

    # Misc interesting
    "/cgi-bin/", "/cgi-bin/env.pl",
    "/shell", "/cmd", "/exec",
    "/upload", "/uploads/", "/files/", "/static/",
    "/.DS_Store",
]


def probe_common_paths(
    client: "WebClient",
    base_url: str,
    *,
    workers: int = 10,
) -> List[str]:
    """Probe the wordlist and return URLs that gave an interesting response."""
    found: List[str] = []
    base = base_url.rstrip("/")

    def _probe(path: str) -> str | None:
        try:
            resp = client.get(path)
            if resp.status_code in _INTERESTING_STATUS:
                return base + path
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, path): path for path in _WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                logger.debug("Common path found: %s", result)

    logger.info("Common path probe: %d/%d paths returned interesting responses",
                len(found), len(_WORDLIST))
    return sorted(found)
