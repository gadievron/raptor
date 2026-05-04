"""ASVS V2 -- Authentication checks (passive and low-impact active probes)."""

from __future__ import annotations

import time
from typing import List, TYPE_CHECKING

from packages.web.checks.base import Check, CheckCategory, CheckResult, registry

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession

_KNOWN_USERNAMES = ["admin", "administrator", "user", "test", "guest"]


@registry.register(CheckCategory.AUTHN, "V2.2.1", "Account enumeration via login response differences")
class AccountEnumerationCheck(Check):
    """Check if the login endpoint leaks whether a username exists.

    Makes at most 2 login attempts with obviously invalid credentials.
    Compares response length, status code, and body text.
    """

    def run(self, client, target_url, session=None, discovery=None):
        login_path = _find_login_path(client, discovery)
        if not login_path:
            return []

        try:
            # Probe with a likely-nonexistent user vs a common username
            r1 = client.post(
                login_path,
                data={
                    "username": "raptor_nonexistent_user_xyzzy_9291",
                    "password": "SomeWrongPassword!1",
                },
            )
            r2 = client.post(
                login_path,
                data={"username": "admin", "password": "SomeWrongPassword!1"},
            )
        except Exception:
            return []

        # Status code difference
        if r1.status_code != r2.status_code:
            return [self._result(
                passed=False, url=target_url.rstrip("/") + login_path,
                evidence=(
                    f"Nonexistent user: HTTP {r1.status_code} ({len(r1.content)} bytes); "
                    f"'admin': HTTP {r2.status_code} ({len(r2.content)} bytes)"
                ),
                detail=(
                    "The login endpoint returns different HTTP status codes for valid vs invalid "
                    "usernames. An attacker can enumerate valid accounts by comparing responses."
                ),
                recommendation=(
                    "Return an identical generic error for all failed login attempts regardless of "
                    "whether the username exists: 'Invalid username or password.'"
                ),
                severity="medium", asvs_ref="ASVS 5.0 V2.2.1",
            )]

        # Response body length difference (>50 bytes variance is suspicious)
        len_diff = abs(len(r1.content) - len(r2.content))
        if len_diff > 50:
            return [self._result(
                passed=False, url=target_url.rstrip("/") + login_path,
                evidence=(
                    f"Nonexistent user: {len(r1.content)} bytes; "
                    f"'admin': {len(r2.content)} bytes (difference: {len_diff} bytes)"
                ),
                detail=(
                    "The login endpoint returns significantly different response sizes for valid vs "
                    "invalid usernames. Even with a generic error message, response size differences "
                    "allow username enumeration."
                ),
                recommendation=(
                    "Pad responses or use a constant-time response path to ensure identical response "
                    "sizes regardless of username validity."
                ),
                severity="low", asvs_ref="ASVS 5.0 V2.2.1",
            )]

        return []


@registry.register(CheckCategory.AUTHN, "V2.2.2", "Brute-force protection absent")
class BruteForceProtectionCheck(Check):
    """Check if the login endpoint rate-limits repeated failures.

    Makes at most 5 login attempts. Does NOT perform an actual dictionary attack.
    """

    def run(self, client, target_url, session=None, discovery=None):
        login_path = _find_login_path(client, discovery)
        if not login_path:
            return []

        responses = []
        for i in range(5):
            try:
                resp = client.post(
                    login_path,
                    data={
                        "username": "admin",
                        "password": f"raptor_probe_password_{i}",
                    },
                )
                responses.append(resp.status_code)
            except Exception:
                break

        if len(responses) < 3:
            return []

        # If all responses are 200 or the same non-lockout code, no rate limit detected
        lockout_codes = {401, 403, 429, 423}
        has_lockout = any(code in lockout_codes for code in responses[2:])

        # Also check for captcha/lockout text in last response
        try:
            last = client.post(
                login_path,
                data={"username": "admin", "password": "raptor_final_probe"},
            )
            lockout_text = any(
                kw in last.text.lower()
                for kw in ("locked", "captcha", "too many", "rate limit", "blocked")
            )
        except Exception:
            lockout_text = False

        if not has_lockout and not lockout_text:
            return [self._result(
                passed=False, url=target_url.rstrip("/") + login_path,
                evidence=(
                    f"5 consecutive failed logins returned: {responses}. "
                    "No lockout, CAPTCHA, or rate-limit response detected."
                ),
                detail=(
                    "The login endpoint does not appear to implement brute-force protection. "
                    "An attacker can attempt unlimited password guesses without triggering "
                    "any lockout or rate-limiting mechanism."
                ),
                recommendation=(
                    "Implement account lockout after N consecutive failures (with unlock mechanism), "
                    "or CAPTCHA after N failures, or exponential back-off delays. "
                    "Also consider IP-based rate limiting as a complementary control."
                ),
                severity="high", asvs_ref="ASVS 5.0 V2.2.2",
            )]
        return []


@registry.register(CheckCategory.AUTHN, "V2.1.1", "Weak default credentials accepted")
class DefaultCredentialsCheck(Check):
    """Try a small set of well-known default credentials.

    Deliberately conservative -- at most 3 attempts against common combos.
    """

    _DEFAULTS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
    ]

    def run(self, client, target_url, session=None, discovery=None):
        login_path = _find_login_path(client, discovery)
        if not login_path:
            return []

        for username, password in self._DEFAULTS:
            try:
                resp = client.post(
                    login_path,
                    data={"username": username, "password": password},
                )
                # Successful login: redirected away from login page or no password field
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.content, "html.parser")
                still_on_login = bool(soup.find("input", {"type": "password"}))

                if not still_on_login and resp.status_code in (200, 302):
                    return [self._result(
                        passed=False, url=target_url.rstrip("/") + login_path,
                        evidence=f"Login succeeded with username='{username}' password='{password}'",
                        detail=(
                            f"Default credentials '{username}'/'{password}' were accepted. "
                            "This allows immediate, unauthenticated access to the application."
                        ),
                        recommendation=(
                            "Remove or change all default credentials before deploying to production. "
                            "Force a password change on first login for any default accounts."
                        ),
                        severity="critical", asvs_ref="ASVS 5.0 V2.1.1",
                    )]
            except Exception:
                continue
        return []


def _find_login_path(client, discovery: dict | None) -> str | None:
    """Return a likely login path from discovery data or by probing common paths."""
    if discovery:
        for form in discovery.get("forms", []):
            action = form.get("action", "")
            if any(kw in action.lower() for kw in ("login", "signin", "auth", "session")):
                from urllib.parse import urlparse
                return urlparse(action).path or "/"
        for url in discovery.get("urls", []):
            from urllib.parse import urlparse
            path = urlparse(url).path
            if any(kw in path.lower() for kw in ("/login", "/signin", "/auth")):
                return path

    candidates = ["/login", "/signin", "/auth/login", "/user/login",
                  "/account/login", "/api/login", "/api/auth/login"]
    for path in candidates:
        try:
            resp = client.get(path)
            if resp.status_code in (200, 302):
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.content, "html.parser")
                if soup.find("input", {"type": "password"}):
                    return path
        except Exception:
            continue
    return None
