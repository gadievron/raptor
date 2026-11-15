"""Proxy grants reuse transport keys without relaxing URL admission."""

import pytest

from core.llm import egress
from core.sandbox import proxy


@pytest.mark.parametrize("url,expected", [
    ("https://faß.de/path", "xn--fa-hia.de"),
    ("https://XN--FA-HIA.DE./", "xn--fa-hia.de"),
    ("https://Example.COM。/", "example.com"),
    ("http://[::1]:8080/", "::1"),
    ("http://svc_name.internal/", "svc_name.internal"),
])
def test_transport_host_key_reaches_proxy(monkeypatch, url, expected):
    admitted = []
    monkeypatch.setattr(egress, "_enabled", True)
    monkeypatch.setattr(proxy, "get_proxy", lambda hosts: admitted.extend(hosts))
    egress.register_web_target(url)
    assert admitted == [expected]


@pytest.mark.parametrize("url", [
    "https://*.example/", "https://example*/", "ftp://example/",
    "https://\u200d.example/", "https://。/",
])
def test_invalid_target_refused_before_proxy(monkeypatch, url):
    def unexpected_proxy(hosts):
        pytest.fail("invalid target reached proxy admission")

    monkeypatch.setattr(egress, "_enabled", True)
    monkeypatch.setattr(proxy, "get_proxy", unexpected_proxy)
    with pytest.raises(ValueError):
        egress.register_web_target(url)


def test_inactive_egress_does_not_create_proxy(monkeypatch):
    def unexpected_proxy(hosts):
        pytest.fail("inactive egress created a proxy")

    monkeypatch.setattr(egress, "_enabled", False)
    monkeypatch.setattr(proxy, "get_proxy", unexpected_proxy)
    egress.register_web_target("https://faß.de/")
