"""Negative control: "open redirect" keyword family (Python).

Redirect targets come from a server-side allowlist keyed by name — no
request-derived value ever reaches the redirect call. The unsafe-shape
pattern must not match any line of this fixture.
"""

from flask import abort, redirect

SAFE_DESTINATIONS = {
    "home": "/",
    "profile": "/account/profile",
}


def go(name):
    if name not in SAFE_DESTINATIONS:
        abort(404)
    location = SAFE_DESTINATIONS[name]
    return redirect(location)
