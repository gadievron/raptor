"""Tech stack fingerprinting from HTTP headers, cookies, and HTML meta tags."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = logging.getLogger(__name__)

_SERVER_NORMALISE = re.compile(r"[/\s].*$")

_COOKIE_SIGNALS: Dict[str, str] = {
    "jsessionid": "Java/Servlet (Tomcat/JBoss/Jetty)",
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "PHP/Laravel",
    "ci_session": "PHP/CodeIgniter",
    "django_session": "Python/Django",
    "rack.session": "Ruby/Rack",
    "connect.sid": "Node.js/Express",
    "_session_id": "Ruby on Rails",
    "cfid": "ColdFusion",
    "cftoken": "ColdFusion",
}

_HEADER_SIGNALS: Dict[str, Dict[str, str]] = {
    "x-powered-by": {},   # value is the signal itself
    "x-generator": {},
    "x-drupal-cache": {"": "PHP/Drupal"},
    "x-wordpress-oembed": {"": "WordPress"},
}

_HTML_SIGNALS = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I), "generator"),
    (re.compile(r'wp-content/(?:plugins|themes)/', re.I), "WordPress"),
    (re.compile(r'/drupal\.js|drupal\.settings', re.I), "PHP/Drupal"),
    (re.compile(r'django-csrftoken|__django', re.I), "Python/Django"),
    (re.compile(r'rails-ujs|csrf-token', re.I), "Ruby on Rails"),
    (re.compile(r'laravel_token', re.I), "PHP/Laravel"),
    (re.compile(r'ng-version=|angular\.min\.js', re.I), "Angular"),
    (re.compile(r'react(?:\.development|\.production)\.min\.js|__react', re.I), "React"),
    (re.compile(r'vue(?:\.runtime)?\.(?:min\.)?js|data-v-', re.I), "Vue.js"),
    (re.compile(r'next/dist|__next', re.I), "Next.js"),
    (re.compile(r'__nuxt|_nuxt/', re.I), "Nuxt.js"),
]


def fingerprint_target(client: "WebClient", base_url: str) -> Dict[str, str]:
    """Return a dict of detected technologies and their evidence."""
    tech: Dict[str, str] = {}

    try:
        resp = client.get("/")
    except Exception as e:
        logger.debug("Fingerprint fetch failed: %s", e)
        return tech

    try:
        headers = resp.headers
    except Exception:
        return tech

    # Server header
    server = str(headers.get("Server") or "").strip()
    if server:
        tech["server"] = server
        short = _SERVER_NORMALISE.sub("", server).strip()
        if short:
            tech["server_product"] = short

    # X-Powered-By and similar
    powered = str(headers.get("X-Powered-By") or "").strip()
    if powered:
        tech["x_powered_by"] = powered

    gen = str(headers.get("X-Generator") or "").strip()
    if gen:
        tech["generator"] = gen

    # Framework signals from specific headers
    for header_name, mapping in _HEADER_SIGNALS.items():
        value = headers.get(header_name)
        if value is not None:
            tech[header_name.lower().replace("-", "_")] = value or "present"

    # Cookie-based signals
    cookies = client.get_cookies()
    for cookie_name, cookie_val in cookies.items():
        sig = _COOKIE_SIGNALS.get(cookie_name.lower())
        if sig:
            tech["framework"] = sig
            break

    # HTML meta / JS pattern signals
    try:
        html = resp.text
        for pattern, label in _HTML_SIGNALS:
            m = pattern.search(html)
            if m:
                value = m.group(1) if m.lastindex else label
                tech.setdefault("detected_tech", value)
                break
    except Exception:
        pass

    # Content-Security-Policy presence (useful context for header checks)
    if "Content-Security-Policy" in headers:
        tech["has_csp"] = "yes"

    # HTTPS detection
    from urllib.parse import urlparse
    if urlparse(base_url).scheme == "https":
        tech["transport"] = "https"
    else:
        tech["transport"] = "http"

    logger.info("Fingerprint: %s", tech)
    return tech
