"""Tests for packages/studio/security.py — CSRF + cross-origin rejection."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.datastructures import Headers  # noqa: E402

from packages.studio import security  # noqa: E402
from packages.studio.app import app  # noqa: E402
from packages.studio.services import jobs  # noqa: E402

# Host validation expects a loopback Host header, so pin the base URL
# instead of relying on TestClient's default "testserver".
BASE = "http://127.0.0.1:8765"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Keep the cancel route's SQLite lookups inside the test tmp dir.
    monkeypatch.setattr(jobs, "STUDIO_DATA_DIR", tmp_path)
    # No context manager: skips lifespan, so the worker thread never starts.
    return TestClient(app, base_url=BASE)


def _token() -> str:
    return security.csrf_token()


# --- synchronizer token -----------------------------------------------------

def test_post_with_valid_token_reaches_handler(client):
    # 404 (job unknown) proves the request passed CSRF validation.
    r = client.post("/jobs/nonexistent/cancel", data={"csrf_token": _token()})
    assert r.status_code == 404


def test_post_without_token_rejected(client):
    r = client.post("/jobs/nonexistent/cancel", data={})
    assert r.status_code == 403


def test_post_with_wrong_token_rejected(client):
    r = client.post("/jobs/nonexistent/cancel", data={"csrf_token": "guess"})
    assert r.status_code == 403


def test_all_state_changing_routes_require_token(client):
    for url in (
        "/projects/new",
        "/projects/x/settings",
        "/projects/x/scan/new",
        "/jobs/x/cancel",
        "/settings",
    ):
        r = client.post(url, data={})
        assert r.status_code == 403, url


def test_forms_embed_token(client):
    r = client.get("/settings")
    assert r.status_code == 200
    assert f'name="csrf_token" value="{_token()}"' in r.text


# --- cross-origin middleware ------------------------------------------------

def test_cross_origin_post_rejected_by_origin(client):
    r = client.post(
        "/jobs/nonexistent/cancel",
        data={"csrf_token": _token()},
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403


def test_cross_origin_post_rejected_by_fetch_metadata(client):
    r = client.post(
        "/jobs/nonexistent/cancel",
        data={"csrf_token": _token()},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert r.status_code == 403


def test_null_origin_rejected(client):
    # Sandboxed iframes / data: URLs send the literal "null" origin.
    r = client.post(
        "/jobs/nonexistent/cancel",
        data={"csrf_token": _token()},
        headers={"Origin": "null"},
    )
    assert r.status_code == 403


def test_same_origin_post_allowed(client):
    r = client.post(
        "/jobs/nonexistent/cancel",
        data={"csrf_token": _token()},
        headers={"Origin": BASE, "Sec-Fetch-Site": "same-origin"},
    )
    assert r.status_code == 404


def test_get_ignores_cross_origin_headers(client):
    # Cross-origin reads are the browser's problem (SOP); we only gate writes.
    r = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert r.status_code == 200


# --- unit: header logic -----------------------------------------------------

def _reason(headers: dict) -> str | None:
    return security.cross_origin_reason(Headers(headers))


def test_reason_no_headers_falls_through_to_token():
    assert _reason({}) is None


def test_reason_matching_origin():
    assert _reason({"origin": "http://127.0.0.1:8765", "host": "127.0.0.1:8765"}) is None
    assert _reason({"origin": "http://LocalHost:8765", "host": "localhost:8765"}) is None


def test_reason_same_host_different_port_rejected():
    # A page on another local port is a different origin.
    assert _reason({"origin": "http://localhost:9000", "host": "localhost:8765"})


def test_reason_mismatched_origin():
    assert _reason({"origin": "http://attacker.test", "host": "127.0.0.1:8765"})


def test_reason_origin_without_host_header():
    assert _reason({"origin": "http://attacker.test"})


def test_reason_fetch_site_values():
    assert _reason({"sec-fetch-site": "cross-site"})
    assert _reason({"sec-fetch-site": "same-site"})
    assert _reason({"sec-fetch-site": "same-origin"}) is None
    assert _reason({"sec-fetch-site": "none"}) is None  # address-bar navigation


def test_host_without_port_variants():
    f = security._host_without_port
    assert f("127.0.0.1:8765") == "127.0.0.1"
    assert f("LocalHost") == "localhost"
    assert f("[::1]:8765") == "[::1]"
    assert f("[::1]") == "[::1]"
