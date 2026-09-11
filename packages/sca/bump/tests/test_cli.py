"""Tests for the ``raptor-sca bump`` CLI wiring (``bump.cli``).

Covers two contracts:

  * ``--no-cache`` keeps the OSV new-CVE gate ALIVE: the CLI never
    hands ``cache=None`` to OsvClient/KevClient/EpssClient (which
    dereference their cache unconditionally — the resulting crash
    was swallowed as an empty vuln delta, so every ``--no-cache``
    run silently lost the gate and ``--apply`` could land KEV CVEs
    as Clean). Instead a real cache with zeroed TTLs is used,
    mirroring the scan pipeline, so lookups run AND aren't served
    from stale entries.
  * ``--json`` emits snake_case verdict values (``clean`` /
    ``review`` / ``block``); Title-Case labels stay in the
    human-readable renderings.
"""

from __future__ import annotations

import json
import time as _time
from pathlib import Path
from typing import Any

import pytest

from core.http import HttpError
from packages.sca.bump import cli as bump_cli


class _StubHttp:
    """Serves the GitHub-release, PyPI-metadata, and OSV endpoints
    the bump pipeline touches; counts OSV querybatch POSTs."""

    def __init__(self) -> None:
        self.osv_batch_posts: int = 0

    def get_json(self, url: str, **kw: Any) -> Any:
        if url.endswith("/repos/semgrep/semgrep/releases/latest"):
            return {"tag_name": "v1.119.0"}
        if url == "https://pypi.org/pypi/semgrep/json":
            return {"releases": {
                "1.119.0":
                    [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
            }}
        if url.endswith("/vulns/GHSA-target-only"):
            return {
                "id": "GHSA-target-only",
                "aliases": ["CVE-2099-0001"],
                "summary": "introduced by the target version",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "semgrep"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "1.100.0"}]}],
                }],
                "severity": [{
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }],
            }
        raise HttpError(f"stub 404: {url}", status=404)

    def post_json(self, url: str, body: Any, **kw: Any) -> Any:
        if url.endswith("/querybatch"):
            self.osv_batch_posts += 1
            results = []
            for q in body.get("queries", []):
                if q.get("version") == "1.119.0":
                    results.append({"vulns": [{"id": "GHSA-target-only"}]})
                else:
                    results.append({"vulns": []})
            return {"results": results}
        raise HttpError(f"stub 404: {url}", status=404)


@pytest.fixture
def bump_target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "Dockerfile").write_text("ARG SEMGREP_VERSION=1.50.0\n")
    return target


def _run_cli(
    monkeypatch, capsys, target: Path, cache_root: Path,
    *args: str, http: _StubHttp | None = None,
) -> tuple[int, str, _StubHttp]:
    import packages.sca as sca_pkg
    http = http or _StubHttp()
    monkeypatch.setattr(
        sca_pkg, "default_client", lambda **kw: http,
    )
    rc = bump_cli.main([
        str(target), "--cache-root", str(cache_root), *args,
    ])
    out = capsys.readouterr().out
    return rc, out, http


def test_no_cache_still_queries_osv_and_gates(
    monkeypatch, capsys, bump_target: Path, tmp_path: Path,
) -> None:
    """``--no-cache`` run: the OSV delta actually executes and the
    newly-introduced CVE escalates the verdict — the gate is live,
    not silently disabled."""
    rc, out, http = _run_cli(
        monkeypatch, capsys, bump_target, tmp_path / "cache",
        "--no-cache", "--json",
    )
    assert rc == 0
    assert http.osv_batch_posts >= 1, (
        "--no-cache must still query OSV (gate silently disabled)"
    )
    payload = json.loads(out)
    # The fixture yields the ARG candidate (plus the inline-install
    # walker's view of the same pin); the ARG one carries the delta.
    arg_results = [r for r in payload["results"] if r["kind"] == "arg"]
    assert arg_results, f"expected an arg result: {payload['results']}"
    assert arg_results[0]["verdict"] != "clean", (
        "new-CVE-introducing bump must not be Clean"
    )


def test_no_cache_does_not_serve_stale_entries(
    monkeypatch, capsys, bump_target: Path, tmp_path: Path,
) -> None:
    """Two directions of the cache semantics:

    * a cached-mode run after seeding serves OSV from the cache
      (no new querybatch POST) — the seed is real;
    * a ``--no-cache`` run against the same seeded cache re-queries
      (zeroed TTLs treat the seeded entries as stale)."""
    cache_root = tmp_path / "cache"

    # Seed with entries written "60s ago" so TTL-0 reads see them as
    # stale while 24h reads see them as fresh.
    import core.json.cache as cache_mod
    real_time = _time.time
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cache_mod.time, "time", lambda: real_time() - 60)
        rc, _, http_seed = _run_cli(
            monkeypatch, capsys, bump_target, cache_root,
        )
        assert rc == 0
        assert http_seed.osv_batch_posts >= 1

    # Cached-mode control: served from the seeded entries.
    rc, _, http_cached = _run_cli(
        monkeypatch, capsys, bump_target, cache_root,
    )
    assert rc == 0
    assert http_cached.osv_batch_posts == 0, (
        "cached-mode run must serve OSV from the seeded cache"
    )

    # --no-cache: same seeded cache, but zero TTL → refetch.
    rc, _, http_nocache = _run_cli(
        monkeypatch, capsys, bump_target, cache_root, "--no-cache",
    )
    assert rc == 0
    assert http_nocache.osv_batch_posts >= 1, (
        "--no-cache must not serve OSV from cached entries"
    )


def test_json_verdict_snake_case_human_title_case(
    monkeypatch, capsys, bump_target: Path, tmp_path: Path,
) -> None:
    """JSON status values are snake_case; the human table keeps the
    Title-Case labels."""
    rc, out, _ = _run_cli(
        monkeypatch, capsys, bump_target, tmp_path / "cache", "--json",
    )
    assert rc == 0
    payload = json.loads(out)
    verdicts = {r["verdict"] for r in payload["results"]}
    assert verdicts <= {"clean", "review", "block"}, (
        f"JSON verdicts must be snake_case, got {verdicts}"
    )

    rc, out, _ = _run_cli(
        monkeypatch, capsys, bump_target, tmp_path / "cache2",
    )
    assert rc == 0
    assert any(label in out for label in ("Clean", "Review", "Block"))


def test_report_to_dict_lowercases_all_verdict_labels() -> None:
    """Unit shape check on the JSON serializer itself."""
    from packages.sca.bump.orchestrator import (
        BumpCandidate,
        BumpReport,
        BumpResult,
    )
    results = [
        BumpResult(
            candidate=BumpCandidate(
                kind="arg", locator="X_VERSION",
                file=Path("/tmp/Dockerfile"),
                current_version="1", target_version="2",
            ),
            verdict=i, verdict_label=label,
            bump_supply_chain_findings=[],
        )
        for i, label in enumerate(("Clean", "Review", "Block"))
    ]
    report = BumpReport(
        target=Path("/tmp"), candidates=[], results=results,
    )
    d = bump_cli._report_to_dict(report)
    assert [r["verdict"] for r in d["results"]] == [
        "clean", "review", "block",
    ]
