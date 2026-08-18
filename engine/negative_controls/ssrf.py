"""Negative control: "ssrf" keyword family (Python).

Outbound requests use fixed literal URLs or an allowlist lookup whose
result is a bare identifier. No f-string URL, no concatenation, no
request-derived URL argument — the unsafe-shape pattern must not match.
"""

import requests

ALLOWED_ENDPOINTS = {
    "status": "https://api.example.com/status",
    "health": "https://api.example.com/health",
}


def fetch_status():
    return requests.get("https://api.example.com/status", timeout=5)


def fetch_named(name):
    if name not in ALLOWED_ENDPOINTS:
        raise ValueError("unknown endpoint")
    endpoint = ALLOWED_ENDPOINTS[name]
    return requests.get(endpoint, timeout=5)
