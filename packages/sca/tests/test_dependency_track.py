"""Tests for ``packages.sca.dependency_track`` — Dependency-Track
push integration."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from packages.sca import dependency_track
from packages.sca.dependency_track import (
    _redact_url,
    push_bom,
)


# ---------------------------------------------------------------------------
# Stub HttpClient
# ---------------------------------------------------------------------------


class _StubHttp:
    """Minimal HttpClient stub; records POST calls + returns canned
    responses driven by ``response`` / ``raises``."""

    def __init__(self, *, response: Dict[str, Any] = None,
                 raises: Exception = None):
        self.response = response if response is not None else {"token": "t-123"}
        self.raises = raises
        self.posts: List[Dict[str, Any]] = []

    def post_json(self, url: str, body: Dict[str, Any], **kwargs):
        self.posts.append({"url": url, "body": body, "kwargs": kwargs})
        if self.raises is not None:
            raise self.raises
        return self.response


def _make_bom(tmp_path: Path, content: Dict[str, Any] = None) -> Path:
    """Write a tiny CycloneDX-shaped JSON file. Schema-shape matters
    less than "is well-formed JSON"."""
    if content is None:
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [],
        }
    bom = tmp_path / "sbom.cdx.json"
    bom.write_text(json.dumps(content), encoding="utf-8")
    return bom


# ---------------------------------------------------------------------------
# push_bom — happy path
# ---------------------------------------------------------------------------


def test_push_bom_uploads_and_returns_token(tmp_path: Path):
    bom = _make_bom(tmp_path)
    http = _StubHttp(response={"token": "abc-123"})
    result = push_bom(
        url="https://dt.example.com",
        api_key="secret",
        bom_path=bom,
        project_name="myapp",
        project_version="1.0",
        http=http,
    )
    assert result == {"status": "uploaded", "token": "abc-123",
                       "error": None}


def test_push_bom_calls_combined_endpoint_with_correct_body(
    tmp_path: Path,
):
    bom_content = {"bomFormat": "CycloneDX", "specVersion": "1.5"}
    bom = _make_bom(tmp_path, bom_content)
    http = _StubHttp()
    push_bom(
        url="https://dt.example.com",
        api_key="secret",
        bom_path=bom,
        project_name="myapp", project_version="1.0",
        http=http,
    )
    assert len(http.posts) == 1
    call = http.posts[0]
    # Endpoint: base + /api/v1/bom (combined endpoint)
    assert call["url"] == "https://dt.example.com/api/v1/bom"
    body = call["body"]
    assert body["projectName"] == "myapp"
    assert body["projectVersion"] == "1.0"
    assert body["autoCreate"] is True
    # BOM is base64-encoded; decoding should round-trip.
    decoded = base64.b64decode(body["bom"]).decode("utf-8")
    assert json.loads(decoded) == bom_content


def test_push_bom_threads_api_key_via_header(tmp_path: Path):
    bom = _make_bom(tmp_path)
    http = _StubHttp()
    push_bom(
        url="https://dt.example.com",
        api_key="secret-key-xyz",
        bom_path=bom,
        project_name="x", project_version="1",
        http=http,
    )
    headers = http.posts[0]["kwargs"]["headers"]
    assert headers["X-Api-Key"] == "secret-key-xyz"
    assert headers["Content-Type"] == "application/json"


def test_push_bom_strips_trailing_slash_from_url(tmp_path: Path):
    """Base URL with trailing slash shouldn't produce a doubled
    slash in the endpoint."""
    bom = _make_bom(tmp_path)
    http = _StubHttp()
    push_bom(
        url="https://dt.example.com/",
        api_key="k",
        bom_path=bom,
        project_name="x", project_version="1",
        http=http,
    )
    assert http.posts[0]["url"] == "https://dt.example.com/api/v1/bom"


def test_push_bom_auto_create_false_propagates(tmp_path: Path):
    bom = _make_bom(tmp_path)
    http = _StubHttp()
    push_bom(
        url="https://dt.example.com",
        api_key="k",
        bom_path=bom,
        project_name="x", project_version="1",
        auto_create=False,
        http=http,
    )
    assert http.posts[0]["body"]["autoCreate"] is False


# ---------------------------------------------------------------------------
# push_bom — pre-flight failures
# ---------------------------------------------------------------------------


def test_push_bom_missing_file_returns_error(tmp_path: Path):
    """Bom path doesn't exist → status=error, no HTTP call made."""
    http = _StubHttp()
    result = push_bom(
        url="https://dt.example.com",
        api_key="k",
        bom_path=tmp_path / "nope.json",
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"
    assert "not found" in result["error"]
    assert http.posts == []


def test_push_bom_invalid_json_returns_error(tmp_path: Path):
    """A file that isn't valid JSON (e.g. operator passed report.md
    by mistake) → status=error, fail-fast before network."""
    bad = tmp_path / "not-json.txt"
    bad.write_text("# Some markdown\nthis isn't json")
    http = _StubHttp()
    result = push_bom(
        url="https://dt.example.com",
        api_key="k",
        bom_path=bad,
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"
    assert "isn't valid JSON" in result["error"]
    assert http.posts == []


def test_push_bom_oversized_file_rejected(tmp_path: Path, monkeypatch):
    """File over the 50MB cap is rejected pre-flight."""
    monkeypatch.setattr(
        dependency_track, "_MAX_BOM_BYTES", 1024,
    )
    big = tmp_path / "huge.cdx.json"
    big.write_bytes(b"{" + b"a" * 2048 + b"}")
    http = _StubHttp()
    result = push_bom(
        url="https://dt.example.com",
        api_key="k", bom_path=big,
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"
    assert "refusing to upload" in result["error"]


# ---------------------------------------------------------------------------
# push_bom — server-side failures
# ---------------------------------------------------------------------------


def test_push_bom_http_exception_returns_error(tmp_path: Path):
    bom = _make_bom(tmp_path)
    http = _StubHttp(raises=ConnectionError("dt unreachable"))
    result = push_bom(
        url="https://dt.example.com",
        api_key="k",
        bom_path=bom,
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"
    assert "DT upload failed" in result["error"]
    assert "dt unreachable" in result["error"]


def test_push_bom_response_missing_token_is_error(tmp_path: Path):
    """DT returned 200 but no ``token`` field — likely an auth
    mismatch (different DT major version, or a non-DT endpoint
    accepting our POST). Fail loudly."""
    bom = _make_bom(tmp_path)
    http = _StubHttp(response={"unexpected": "shape"})
    result = push_bom(
        url="https://dt.example.com",
        api_key="k", bom_path=bom,
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"
    assert "missing 'token'" in result["error"]


def test_push_bom_non_dict_response_handled(tmp_path: Path):
    """A response shape that isn't a dict (e.g. plain string from
    a mis-routed proxy) doesn't crash the helper."""
    bom = _make_bom(tmp_path)
    http = _StubHttp(response="not-a-dict")    # type: ignore[arg-type]
    result = push_bom(
        url="https://dt.example.com",
        api_key="k", bom_path=bom,
        project_name="x", project_version="1",
        http=http,
    )
    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# _redact_url
# ---------------------------------------------------------------------------


def test_redact_url_strips_query_and_fragment():
    """Operators occasionally embed auth in query strings (legacy
    DT setups); _redact_url logs without them."""
    assert _redact_url(
        "https://dt.example.com/path?apikey=secret#x"
    ) == "https://dt.example.com/path"


def test_redact_url_handles_trailing_slash():
    assert _redact_url(
        "https://dt.example.com/"
    ) == "https://dt.example.com"


# ---------------------------------------------------------------------------
# _build_egress_client — URL validation
# ---------------------------------------------------------------------------


def test_build_egress_client_rejects_non_http():
    """``file://`` / ``ftp://`` / unparseable URLs must be
    rejected so a misconfigured ``--url`` can't leak the SBOM
    locally or somewhere unexpected."""
    from packages.sca.dependency_track import _build_egress_client
    with pytest.raises(ValueError):
        _build_egress_client("file:///etc/passwd")
    with pytest.raises(ValueError):
        _build_egress_client("ftp://dt.example.com")
    with pytest.raises(ValueError):
        _build_egress_client("not-a-url")


def test_build_egress_client_accepts_http_and_https():
    from packages.sca.dependency_track import _build_egress_client
    # No exception → success. We don't actually USE the client in
    # this test (would require a sandboxed proxy for the host
    # check); just verify URL parsing accepts the shape.
    _build_egress_client("https://dt.example.com")
    _build_egress_client("http://dt.localhost:8080")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_dispatch_routes_dt_push(tmp_path: Path, monkeypatch,
                                       capsys):
    """The dt-push subcommand routes through cli._dispatch and
    invokes dependency_track.main."""
    bom = _make_bom(tmp_path)

    captured: Dict[str, Any] = {}

    def fake_push_bom(**kwargs):
        captured.update(kwargs)
        return {"status": "uploaded", "token": "tok", "error": None}

    monkeypatch.setattr(
        "packages.sca.dependency_track.push_bom", fake_push_bom,
    )

    from packages.sca.cli import main as cli_main
    rc = cli_main([
        "dt-push",
        "--url", "https://dt.example.com",
        "--api-key", "k",
        "--bom", str(bom),
        "--project", "myapp",
        "--version", "1.0",
    ])
    assert rc == 0
    assert captured["url"] == "https://dt.example.com"
    assert captured["api_key"] == "k"
    assert captured["bom_path"] == bom
    assert captured["project_name"] == "myapp"
    assert captured["project_version"] == "1.0"
    out = capsys.readouterr().out
    assert "uploaded" in out
    assert "token=tok" in out


def test_cli_api_key_falls_back_to_env(tmp_path: Path, monkeypatch):
    """Operator can set $DT_API_KEY instead of passing --api-key
    on the command line (avoids leaking the key into ps / shell
    history)."""
    bom = _make_bom(tmp_path)
    captured: Dict[str, Any] = {}

    def fake_push_bom(**kwargs):
        captured.update(kwargs)
        return {"status": "uploaded", "token": "t", "error": None}

    monkeypatch.setattr(
        "packages.sca.dependency_track.push_bom", fake_push_bom,
    )
    monkeypatch.setenv("DT_API_KEY", "env-key-xyz")

    from packages.sca.cli import main as cli_main
    rc = cli_main([
        "dt-push",
        "--url", "https://dt.example.com",
        "--bom", str(bom),
        "--project", "x", "--version", "1",
    ])
    assert rc == 0
    assert captured["api_key"] == "env-key-xyz"


def test_cli_missing_api_key_returns_2(
    tmp_path: Path, monkeypatch, capsys,
):
    """Without --api-key AND without DT_API_KEY, exit 2 with a
    clear message."""
    bom = _make_bom(tmp_path)
    monkeypatch.delenv("DT_API_KEY", raising=False)

    from packages.sca.cli import main as cli_main
    rc = cli_main([
        "dt-push",
        "--url", "https://dt.example.com",
        "--bom", str(bom),
        "--project", "x", "--version", "1",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "DT_API_KEY" in err


def test_cli_no_auto_create_threads_through(
    tmp_path: Path, monkeypatch,
):
    bom = _make_bom(tmp_path)
    captured: Dict[str, Any] = {}

    def fake_push_bom(**kwargs):
        captured.update(kwargs)
        return {"status": "uploaded", "token": "t", "error": None}

    monkeypatch.setattr(
        "packages.sca.dependency_track.push_bom", fake_push_bom,
    )

    from packages.sca.cli import main as cli_main
    cli_main([
        "dt-push",
        "--url", "https://dt.example.com",
        "--api-key", "k",
        "--bom", str(bom),
        "--project", "x", "--version", "1",
        "--no-auto-create",
    ])
    assert captured["auto_create"] is False


def test_cli_upload_failure_exits_1(
    tmp_path: Path, monkeypatch, capsys,
):
    bom = _make_bom(tmp_path)
    monkeypatch.setattr(
        "packages.sca.dependency_track.push_bom",
        lambda **kwargs: {
            "status": "error", "token": None,
            "error": "DT unreachable",
        },
    )
    from packages.sca.cli import main as cli_main
    rc = cli_main([
        "dt-push",
        "--url", "https://dt.example.com",
        "--api-key", "k",
        "--bom", str(bom),
        "--project", "x", "--version", "1",
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "DT unreachable" in err
