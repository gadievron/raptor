"""One transport hostname fold shared by DNS pins and proxy admission."""

from urllib.parse import urlsplit

import pytest
import requests

from core.http.hosts import canonical_transport_host
from packages.web.client import _canonical_pin_host


@pytest.mark.parametrize("host,expected", [
    (None, ""), ("", ""), ("EXAMPLE.COM.", "example.com"),
    ("example.com。．｡", "example.com"), (b"EXAMPLE.COM", "example.com"),
    (bytearray(b"EXAMPLE.COM."), "example.com"), (b"\xff", ""),
    ("faß.de", "xn--fa-hia.de"), ("BÜCHER.example", "xn--bcher-kva.example"),
    ("XN--FA-HIA.DE.", "xn--fa-hia.de"), ("☃.example", ""),
    ("\ud800.example", ""), ("127.0.0.1", "127.0.0.1"),
    ("::1", "::1"), ("svc_name.internal", "svc_name.internal"),
])
def test_transport_keys_and_existing_web_pins_agree(host, expected):
    assert canonical_transport_host(host) == expected
    assert _canonical_pin_host(host) == expected


@pytest.mark.parametrize("host", ["faß.de", "bücher.example", "FAß.DE"])
def test_unicode_key_matches_the_prepared_http_transport(host):
    prepared = requests.Request("GET", f"https://{host}/").prepare()
    assert canonical_transport_host(host) == urlsplit(prepared.url).hostname


def test_normalization_does_not_replace_admission_validation():
    # Existing ASCII internal-host semantics are preserved; the caller must
    # reject wildcard grants rather than treating this fold as validation.
    assert canonical_transport_host("*.EXAMPLE") == "*.example"


def test_idna2003_substitution_would_name_a_different_host():
    assert "faß.de".encode("idna").decode("ascii") == "fass.de"
    assert canonical_transport_host("faß.de") == "xn--fa-hia.de"
