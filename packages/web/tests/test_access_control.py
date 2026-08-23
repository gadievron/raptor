"""Principal-differential access-control testing (no network)."""

from __future__ import annotations

from types import SimpleNamespace

from packages.web.access_control import (
    Principal,
    object_scoped_urls,
    run_access_differential,
)
from packages.web.execution_policy import WebExecutionPolicy


def _resp(status: int, text: str = "ok"):
    return SimpleNamespace(status_code=status, text=text, content=text.encode())


class _StubClient:
    """Server double keyed by (principal marker, url)."""

    def __init__(self, routes):
        self.routes = routes

    def get(self, url: str, headers=None, **_kwargs):
        key = (url, tuple(sorted((headers or {}).items())))
        if key in self.routes:
            return self.routes[key]
        return self.routes.get(url, _resp(404, "nope"))


def _policy():
    return WebExecutionPolicy.for_target("https://example.test")


def test_object_scoped_urls_selects_ids_and_numeric_segments():
    urls = [
        "https://example.test/orders?order_id=5",
        "https://example.test/users/1234/profile",
        "https://example.test/docs/9f8b2c1a-1234-4abc-9def-0123456789ab",
        "https://example.test/about",
        "https://example.test/search?q=x",
    ]

    selected = object_scoped_urls(urls, ["order_id", "q"])

    assert "https://example.test/orders?order_id=5" in selected
    assert "https://example.test/users/1234/profile" in selected
    assert any("9f8b2c1a" in u for u in selected)
    assert "https://example.test/about" not in selected
    assert "https://example.test/search?q=x" not in selected


def test_idor_candidate_when_other_principal_sees_same_object():
    url = "https://example.test/orders?order_id=5"
    owner_body = "order 5: 2x widgets, ship to Alice"
    a = Principal("session_a", _StubClient({url: _resp(200, owner_body)}), True)
    b = Principal("session_b", _StubClient({url: _resp(200, owner_body)}), True)

    result = run_access_differential(
        principals=[a, b], urls=[url], parameters=["order_id"],
        policy=_policy(),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["kind"] == "idor_candidate"
    assert finding["other"] == "session_b"
    assert finding["evidence"]["session_a"]["status"] == 200


def test_properly_scoped_object_yields_no_finding():
    url = "https://example.test/orders?order_id=5"
    a = Principal("session_a", _StubClient({url: _resp(200, "order 5 details")}), True)
    b = Principal(
        "session_b", _StubClient({url: _resp(403, "forbidden")}), True,
    )

    result = run_access_differential(
        principals=[a, b], urls=[url], parameters=["order_id"],
        policy=_policy(),
    )

    assert result.findings == []
    assert result.targets_tested == 1


def test_forbidden_bypass_via_path_primitive():
    url = "https://example.test/admin/users/42"
    anon_routes = {
        url: _resp(403, "forbidden"),
        url + "/": _resp(200, "user 42 admin view"),
    }
    a = Principal("session_a", _StubClient({url: _resp(200, "user 42 admin view")}), True)
    anon = Principal("anonymous", _StubClient(anon_routes), False)

    result = run_access_differential(
        principals=[a, anon], urls=[url], parameters=[],
        policy=_policy(),
    )

    kinds = {f["kind"] for f in result.findings}
    assert "forbidden_bypass" in kinds
    bypass = next(f for f in result.findings if f["kind"] == "forbidden_bypass")
    assert bypass["primitive"] == "trailing_slash"


def test_out_of_scope_targets_are_policy_denied_silently():
    url = "https://evil.test/orders?order_id=5"
    a = Principal("session_a", _StubClient({url: _resp(200, "x")}), True)
    anon = Principal("anonymous", _StubClient({}), False)

    result = run_access_differential(
        principals=[a, anon], urls=[url], parameters=["order_id"],
        policy=_policy(),
    )

    assert result.targets_tested == 0
    assert result.findings == []


def test_requires_an_authenticated_primary():
    anon = Principal("anonymous", _StubClient({}), False)

    result = run_access_differential(
        principals=[anon], urls=["https://example.test/users/1"],
        parameters=[], policy=_policy(),
    )

    assert result.findings == []
    assert result.requests_used == 0


def test_scanner_phase_converts_hits_to_findings(tmp_path):
    """Phase 5b wiring: differential hits become needs_review V4 findings
    and the artifact is written."""
    import json
    from unittest.mock import MagicMock, patch

    from packages.web.access_control import AccessControlResult
    from packages.web.scanner import WebScanner

    with patch("packages.web.scanner.WebClient"), patch(
        "packages.web.scanner.WebCrawler"
    ):
        scanner = WebScanner(
            "http://example.com", None, tmp_path, access_control=True,
        )
        scanner.fuzzer = MagicMock()
        scanner.fuzzer.fuzz_parameter.return_value = []
        scanner.session = MagicMock(authenticated=True)
        scanner.auth_manager = None
        scanner.crawler.crawl.return_value = {
            "stats": {"total_pages": 1, "total_parameters": 1},
            "discovered_parameters": ["order_id"],
            "discovered_urls": ["http://example.com/orders?order_id=5"],
            "pages": [],
        }
        hits = AccessControlResult(
            findings=[{
                "kind": "idor_candidate",
                "url": "http://example.com/orders?order_id=5",
                "primary": "session_a",
                "other": "anonymous",
                "evidence": {"session_a": {"status": 200}},
            }],
            targets_tested=1,
            requests_used=2,
        )
        with patch(
            "packages.web.access_control.run_access_differential",
            return_value=hits,
        ):
            result = scanner.scan()

    assert "access_control" in result["phases_completed"]
    ac = [f for f in result["findings"] if f["vuln_type"] == "access_control"]
    assert len(ac) == 1
    assert ac[0]["status"] == "needs_review"
    assert ac[0]["cwe_id"] == "CWE-639"
    artifact = json.loads(
        (tmp_path / "access-control-differential.json").read_text(encoding="utf-8")
    )
    assert artifact["targets_tested"] == 1
