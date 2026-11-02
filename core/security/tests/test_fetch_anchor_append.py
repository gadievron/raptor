"""Extra-host additions must obey the WebFetch matcher's validation."""

import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "libexec" / "raptor-fetch-anchor"


@pytest.fixture
def append_host(tmp_path, monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    main = runpy.run_path(str(_SCRIPT))["main"]
    anchor = tmp_path / "fetch.anchor"
    anchor.write_text("https://victim.github.io/report\n", encoding="utf-8")
    monkeypatch.setitem(main.__globals__, "_anchor_path", lambda: anchor)

    def append(host):
        monkeypatch.setattr(sys, "argv", [str(_SCRIPT), "append", host])
        return main()

    return append, anchor


@pytest.mark.parametrize("host", [
    "bad_label.com", "bad..com", "a" * 64 + ".com", "bad-.com",
    "example.com..", "https://example.com", "example.com/path",
    "example.com:443", "example.com\nattacker.com", "",
])
def test_invalid_host_does_not_modify_anchor(append_host, host):
    append, anchor = append_host
    before = anchor.read_bytes()
    assert append(host) == 1
    assert anchor.read_bytes() == before


@pytest.mark.parametrize(("host", "normalized"), [
    ("CDN.Example.COM.", "cdn.example.com"),
    ("faß.de", "xn--fa-hia.de"),
    ("cdn.internal.invalid", "cdn.internal.invalid"),
    ("192.0.2.1", "192.0.2.1"),
])
def test_valid_host_is_normalized_and_appended(append_host, host, normalized):
    append, anchor = append_host
    before = anchor.read_text(encoding="utf-8")
    assert append(host) == 0
    assert anchor.read_text(encoding="utf-8") == before + normalized + "\n"


@pytest.mark.parametrize("error", [OSError("missing PSL"), ValueError("corrupt PSL")])
def test_psl_failure_does_not_modify_anchor(append_host, error):
    append, anchor = append_host
    before = anchor.read_bytes()
    with patch("core.domains.public_suffix.load_suffix_rules", side_effect=error):
        assert append("cdn.example.com") == 1
    assert anchor.read_bytes() == before
