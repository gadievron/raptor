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


@pytest.fixture(autouse=True)
def _clean_remote_env(monkeypatch):
    # Start every test from the default posture: loopback bind, no token.
    monkeypatch.delenv("STUDIO_ALLOW_REMOTE", raising=False)
    monkeypatch.delenv("STUDIO_AUTH_TOKEN", raising=False)


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


# --- remote access: host validation ----------------------------------------

def test_foreign_host_header_rejected(client, monkeypatch):
    # DNS rebinding: browser connects to 127.0.0.1 but sends the
    # attacker's hostname. Must not be served.
    monkeypatch.delenv("STUDIO_ALLOW_REMOTE", raising=False)
    r = client.get("/api/health", headers={"Host": "attacker.test:8765"})
    assert r.status_code == 400


def test_loopback_host_headers_accepted(client, monkeypatch):
    monkeypatch.delenv("STUDIO_ALLOW_REMOTE", raising=False)
    for host in ("127.0.0.1:8765", "localhost:8765", "[::1]:8765", "127.0.0.1"):
        r = client.get("/api/health", headers={"Host": host})
        assert r.status_code == 200, host


def test_foreign_host_allowed_when_remote_enabled(client, monkeypatch):
    monkeypatch.setenv("STUDIO_ALLOW_REMOTE", "1")
    monkeypatch.delenv("STUDIO_AUTH_TOKEN", raising=False)
    r = client.get("/api/health", headers={"Host": "studio.internal:8765"})
    assert r.status_code == 200


# --- remote access: token auth ----------------------------------------------
# When STUDIO_AUTH_TOKEN is set, every client must authenticate —
# loopback included (see RemoteAccessProtection docstring).

@pytest.fixture()
def remote(monkeypatch):
    monkeypatch.setenv("STUDIO_ALLOW_REMOTE", "1")
    monkeypatch.setenv("STUDIO_AUTH_TOKEN", "sekrit-token")


def test_remote_client_without_token_unauthorized(client, remote):
    r = client.get("/api/health")
    assert r.status_code == 401


def test_remote_client_with_bearer_token(client, remote):
    r = client.get("/api/health", headers={"Authorization": "Bearer sekrit-token"})
    assert r.status_code == 200


def test_remote_client_with_wrong_token_unauthorized(client, remote):
    r = client.get("/api/health", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_query_token_exchanged_for_cookie(client, remote):
    r = client.get("/api/health?token=sekrit-token", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/api/health"
    assert "studio_auth=sekrit-token" in r.headers.get("set-cookie", "")
    # The cookie then authenticates follow-up requests.
    r2 = client.get("/api/health", cookies={"studio_auth": "sekrit-token"})
    assert r2.status_code == 200


def test_wrong_query_token_unauthorized(client, remote):
    r = client.get("/api/health?token=wrong", follow_redirects=False)
    assert r.status_code == 401


def test_no_auth_required_when_token_unset(client, monkeypatch):
    monkeypatch.delenv("STUDIO_AUTH_TOKEN", raising=False)
    r = client.get("/api/health")
    assert r.status_code == 200


def test_loopback_client_also_needs_token_in_remote_mode(remote):
    # Regression for the DNS-rebinding chain in --allow-remote mode: a
    # rebound page in a browser ON the studio host connects from
    # loopback, with its own hostname as Host and a matching Origin.
    # Host validation is off in remote mode, so the token must gate it —
    # the rebound hostname's cookie jar can never hold studio_auth.
    rebound = TestClient(
        app, base_url="http://attacker.test:8765", client=("127.0.0.1", 5555)
    )
    r = rebound.get("/api/fs/list?path=/")
    assert r.status_code == 401
    r = rebound.get("/api/health")
    assert r.status_code == 401
    # With the token it works, proving 401 came from auth, not routing.
    r = rebound.get("/api/health", headers={"Authorization": "Bearer sekrit-token"})
    assert r.status_code == 200


def test_query_token_redirect_never_leaves_site(client, remote):
    # A protocol-relative path must not become an off-site redirect.
    r = client.get("//evil.example/?token=sekrit-token", follow_redirects=False)
    if r.status_code == 303:
        assert not r.headers["location"].startswith("//")


def test_auth_cookie_samesite_strict(client, remote):
    r = client.get("/api/health?token=sekrit-token", follow_redirects=False)
    cookie_hdr = r.headers.get("set-cookie", "")
    assert "samesite=strict" in cookie_hdr.lower()


# --- security headers -------------------------------------------------------

def test_csp_header_present_on_pages(client):
    r = client.get("/api/health")
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


def test_x_frame_options_header_present(client):
    r = client.get("/api/health")
    assert r.headers.get("x-frame-options") == "DENY"


# --- run artifact serving ----------------------------------------------------

def test_run_files_served_with_noscript_csp(client, tmp_path, monkeypatch):
    # A malicious SVG in a run dir must not execute same-origin script
    # when navigated to. CSP sandbox makes it scriptless + origin-less.
    run_dir = tmp_path / "proj" / "scan_x"
    run_dir.mkdir(parents=True)
    (run_dir / "evil.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    )

    class _Run:
        name = "scan_x"
        directory = run_dir

    class _Proj:
        name = "proj"

        def runs(self):
            return [_Run()]

    monkeypatch.setattr(
        "packages.studio.app.get_project",
        lambda name: _Proj() if name == "proj" else None,
    )
    r = client.get("/projects/proj/runs/scan_x/files/evil.svg")
    assert r.status_code == 200
    assert r.headers["content-security-policy"] == "sandbox"
    assert r.headers["x-content-type-options"] == "nosniff"
