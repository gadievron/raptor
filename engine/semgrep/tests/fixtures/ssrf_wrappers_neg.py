import requests


def health():
    parts = ["http://", "internal.invalid", "/health"]
    url = "".join(parts)
    return requests.get(url)
