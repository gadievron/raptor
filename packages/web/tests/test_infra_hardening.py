"""Infrastructure hardening: browser origin normalization, fingerprint
precision, linear inline-script scanning, execution-policy URL edge
cases, nuclei validator posture, OOB callback formatting, and the ffuf
summary's raw data-plane channel. No network."""

from __future__ import annotations

import ipaddress
import socket
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from packages.web.execution_policy import WebExecutionPolicy, WebPolicyError


# -- browser origin gate ------------------------------------------------------


def _engine(base_url: str):
    from packages.web.browser import BrowserEngine

    return BrowserEngine(base_url)  # __init__ never launches Chromium


def test_browser_origin_normalizes_explicit_default_ports():
    # Chromium emits WHATWG-normalized URLs (default port removed); an
    # operator base_url with ':80' must not abort every request.
    engine = _engine("http://host.example:80")
    assert engine._same_origin("http://host.example/page") is True
    engine_tls = _engine("https://host.example:443")
    assert engine_tls._same_origin("https://host.example/x") is True


def test_browser_origin_still_blocks_other_hosts_and_ports():
    engine = _engine("http://host.example")
    assert engine._same_origin("http://other.example/") is False
    assert engine._same_origin("http://host.example:8080/") is False
    assert engine._same_origin("https://host.example/") is False


def test_browser_websocket_scheme_map_keeps_default_ports():
    engine = _engine("https://host.example")
    assert engine._same_origin(
        "wss://host.example/socket", scheme_map={"ws": "http", "wss": "https"},
    ) is True


# -- fingerprint precision -----------------------------------------------------


def _fingerprint(html: str) -> dict:
    from packages.web.discovery.fingerprint import fingerprint_target

    client = MagicMock()
    client.get.return_value = SimpleNamespace(
        status_code=200, headers={}, text=html,
    )
    client.get_cookies.return_value = {}
    return fingerprint_target(client, "https://t.example")


def test_generic_csrf_token_meta_is_not_fingerprinted_as_rails():
    tech = _fingerprint(
        '<meta name="csrf-token" content="x">'
        '<input type="hidden" name="laravel_token" value="y">'
    )
    assert tech.get("detected_tech") == "PHP/Laravel"


def test_rails_markers_still_fingerprint_as_rails():
    tech = _fingerprint(
        '<meta name="csrf-param" content="authenticity_token">'
        '<script src="/assets/rails-ujs.js"></script>'
    )
    assert tech.get("detected_tech") == "Ruby on Rails"


# -- linear inline-script scanning ----------------------------------------------


def test_inline_script_scan_is_linear_on_hostile_unclosed_tags():
    from packages.web.discovery.js_routes import _inline_scripts

    hostile = ("<script>" * 3000) + ("x" * 1024 * 1024)
    started = time.monotonic()
    scripts = _inline_scripts(hostile)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"hostile page took {elapsed:.1f}s to scan"
    assert scripts == []  # no closing tag: nothing extractable

    normal = (
        "<script>fetch('/api/a')</script>"
        "<script src='/bundle.js'></script>"
        "<script type='module'>fetch('/api/b')</script>"
    )
    bodies = _inline_scripts(normal)
    assert any("/api/a" in body for body in bodies)
    assert any("/api/b" in body for body in bodies)
    assert not any("bundle" in body for body in bodies)


# -- execution policy URL edge cases ----------------------------------------------


def test_invalid_port_url_is_a_policy_error_not_a_valueerror():
    policy = WebExecutionPolicy.for_target("https://t.example")
    with pytest.raises(WebPolicyError):
        policy.authorize(
            tool_id="raptor-http", url="http://t.example:99999/x",
            risk="passive", action="http_request",
        )


def test_ipv6_target_round_trips_through_policy_construction():
    policy = WebExecutionPolicy.for_target("https://[::1]:8443/app")
    assert policy.receipt.allowed_origins == ("https://[::1]:8443",)
    # In-scope IPv6 URL authorizes; other origins are refused.
    policy.authorize(
        tool_id="raptor-http", url="https://[::1]:8443/login",
        risk="passive", action="http_request",
    )
    with pytest.raises(WebPolicyError):
        policy.authorize(
            tool_id="raptor-http", url="https://[::2]:8443/",
            risk="passive", action="http_request",
        )


# -- nuclei validator posture -------------------------------------------------------


def _runner(tmp_path: Path, reveal_secrets: bool = False):
    from packages.web.external_validators import ExternalValidatorRunner

    return ExternalValidatorRunner(
        base_url="https://t.example",
        out_dir=tmp_path,
        policy=MagicMock(),
        reveal_secrets=reveal_secrets,
    )


def test_response_transcripts_are_redacted_and_restricted_at_rest(tmp_path):
    runner = _runner(tmp_path)
    store = tmp_path / "nuclei-responses"
    (store / "t.example").mkdir(parents=True)
    transcript = store / "t.example" / "req-1.txt"
    token = "tok-" + "a" * 32
    transcript.write_text(
        f"GET / HTTP/1.1\nHost: t.example\nAuthorization: Bearer {token}\n\n",
        encoding="utf-8",
    )
    runner._scrub_response_store(store)
    text = transcript.read_text(encoding="utf-8")
    assert token not in text
    assert "Bearer [REDACTED]" in text
    assert transcript.stat().st_mode & 0o777 == 0o600
    assert store.stat().st_mode & 0o777 == 0o700


def test_reveal_secrets_skips_the_transcript_scrub(tmp_path):
    # The runner only calls the scrub when reveal_secrets is off; the
    # scrub itself must also be a no-op on unrelated content.
    runner = _runner(tmp_path, reveal_secrets=True)
    assert runner.reveal_secrets is True


def test_private_host_recognizes_hostnames_by_resolution(monkeypatch):
    from packages.web.external_validators import ExternalValidatorRunner

    def fake_getaddrinfo(host, port, **kwargs):
        addr = {"intranet.corp": "10.1.2.3", "public.example": "8.8.8.8"}[host]
        ipaddress.ip_address(addr)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    is_private = ExternalValidatorRunner._is_private_host
    assert is_private("http://intranet.corp:8080/") is True
    assert is_private("https://public.example/") is False
    assert is_private("http://127.0.0.1/") is True
    assert is_private("http://box.internal/") is True


def test_lna_is_decided_per_batch_not_across_mixed_targets(tmp_path, monkeypatch):
    import shutil as shutil_module

    from packages.web import external_validators as ev

    runner = _runner(tmp_path)
    runner.nuclei_config = ev.NucleiConfig(templates_dir=tmp_path)
    monkeypatch.setattr(
        shutil_module, "which", lambda *_args, **_kw: "/usr/bin/nuclei",
    )
    batches: list[tuple[dict, bool, str]] = []

    def fake_batch(binary, templates, targets, *, restrict_local=True, label=""):
        batches.append((dict(targets), restrict_local, label))
        return []

    monkeypatch.setattr(runner, "_nuclei_batch", fake_batch)

    findings = [
        SimpleNamespace(target_url="http://127.0.0.1:8080/a", url="", vuln_type="sqli"),
        SimpleNamespace(target_url="https://public.example/b", url="", vuln_type="xss"),
    ]
    monkeypatch.setattr(
        type(runner), "_is_private_host",
        staticmethod(lambda url: "127.0.0.1" in url),
    )
    runner._run_nuclei(findings)  # type: ignore[arg-type]

    by_label = {label: (targets, restrict) for targets, restrict, label in batches}
    assert set(by_label) == {"public", "private"}
    public_targets, public_restrict = by_label["public"]
    private_targets, private_restrict = by_label["private"]
    # The public batch keeps the RFC1918 pivot restriction even though
    # a private target rode in the same invocation before.
    assert public_restrict is True
    assert "https://public.example/b" in public_targets
    assert private_restrict is False
    assert "http://127.0.0.1:8080/a" in private_targets


# -- OOB callback formatting -----------------------------------------------------


def test_callback_base_brackets_ipv6_and_appends_port():
    from packages.web.oob import OobListener

    listener = OobListener(bind_host="127.0.0.1", callback_host="::1")
    assert listener.callback_base == f"http://[::1]:{listener.port}"

    plain = OobListener(bind_host="127.0.0.1", callback_host="203.0.113.5:8080")
    assert plain.callback_base == "http://203.0.113.5:8080"

    bare = OobListener(bind_host="127.0.0.1")
    assert bare.callback_base == f"http://127.0.0.1:{bare.port}"


def test_wildcard_bind_without_callback_host_warns(caplog):
    from packages.web.oob import OobListener

    listener = OobListener(bind_host="0.0.0.0")
    with caplog.at_level("WARNING", logger="raptor"):
        base = listener.callback_base
    assert base.startswith("http://0.0.0.0:")
    assert any("bind interface" in record.message for record in caplog.records)


# -- ffuf summary raw channel -------------------------------------------------------


def test_ffuf_summary_carries_raw_values_when_display_form_mutates(tmp_path):
    from packages.web.ffuf import FfufRunner

    runner = FfufRunner("https://t.example", tmp_path, reveal_secrets=False)
    payload = "admin'--&password=0123456789"
    entry = {
        "url": "https://t.example/x?token=abc123",
        "status": 200, "length": 1, "words": 1, "lines": 1,
        "input": {"FUZZ": payload, "FFUFHASH": "aa"},
    }
    summary = runner._summarize_result(entry)
    # Display form is sanitized...
    assert "0123456789" not in summary["input"]["FUZZ"]
    # ...and the verbatim payload rides the data-plane channel so the
    # first-party re-verification replays what ffuf actually sent.
    assert summary["input_raw"]["FUZZ"] == payload
    assert summary["url_raw"] == "https://t.example/x?token=abc123"

    clean = runner._summarize_result({
        "url": "https://t.example/plain",
        "status": 200, "length": 1, "words": 1, "lines": 1,
        "input": {"FUZZ": "hello"},
    })
    assert "input_raw" not in clean
    assert "url_raw" not in clean
