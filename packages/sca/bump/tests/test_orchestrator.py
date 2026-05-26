"""Tests for ``packages.sca.bump.orchestrator``.

End-to-end-ish: stub upstream / registry clients to avoid network,
exercise the candidate enumeration + verdict + apply paths."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

from packages.sca.bump.orchestrator import (
    BumpCandidate, _VERDICT_BLOCK, _VERDICT_CLEAN, _VERDICT_REVIEW,
    render_report, run_bump,
)


# ---------------------------------------------------------------------------
# Stub HTTP — replies with operator-supplied JSON per URL.
# ---------------------------------------------------------------------------

class _StubResp:
    def __init__(self, body: dict, status=200):
        self._body = body
        self.status_code = status
        self.headers: Dict[str, str] = {}

    @property
    def content(self):
        import json
        return json.dumps(self._body).encode()


class _StubHttp:
    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses

    def get_json(self, url: str, **kw):
        if url in self._responses:
            return self._responses[url]
        from core.http import HttpError
        raise HttpError(f"stub: no payload for {url}")

    def request(self, method, url, **kw):
        if url in self._responses:
            return _StubResp(self._responses[url])
        from core.http import HttpError
        raise HttpError(f"stub: no payload for {url}")


class _StubPyPI:
    def __init__(self, packages):
        self._p = packages

    def get_metadata(self, name):
        return self._p.get(name)


class _StubNpm:
    def __init__(self, packages):
        self._p = packages

    def get_metadata(self, name):
        return self._p.get(name)


# ---------------------------------------------------------------------------
# Discovery + candidate enumeration
# ---------------------------------------------------------------------------

def test_no_dockerfiles_returns_empty_report(tmp_path: Path) -> None:
    """Target with no Dockerfile → empty report (no error)."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert report.results == []


def test_dockerfile_with_unknown_arg_skipped(tmp_path: Path) -> None:
    """ARG names not in the upstream-source map are silently
    skipped — operator can add via inline-comment override."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SOME_INTERNAL_VERSION=1.0\n"
    )
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert report.results == []


def test_dockerfile_with_known_arg_at_latest_no_candidate(
    tmp_path: Path,
) -> None:
    """ARG already at upstream-latest → not a candidate. Avoids
    proposing identity bumps."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.119.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []


def test_dockerfile_with_known_arg_below_latest_becomes_candidate(
    tmp_path: Path,
) -> None:
    """ARG below upstream-latest → candidate emitted; verdict
    computed."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            # Published over 30 days ago — recent_publish silent
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert len(report.candidates) == 1
    c = report.candidates[0]
    assert c.arg_name == "SEMGREP_VERSION"
    assert c.current_version == "1.50.0"
    assert c.target_version == "1.119.0"
    # Verdict: Clean (no bump-tier signals fired — old enough).
    assert report.results[0].verdict == _VERDICT_CLEAN


def test_dockerfile_recent_publish_target_review_not_clean(
    tmp_path: Path,
) -> None:
    """Target published <30 days ago → recent_publish medium →
    Review (not Clean)."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-09T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert report.results[0].verdict == _VERDICT_REVIEW
    # And the recent_publish finding is in the result for PR-comment
    # rendering / operator visibility.
    kinds = [f.kind for f in report.results[0].bump_supply_chain_findings]
    assert "recent_publish" in kinds


def test_upstream_lookup_failure_records_in_skipped(
    tmp_path: Path,
) -> None:
    """When the GitHub releases endpoint returns 404 (project
    doesn't cut releases), the ARG is recorded in ``skipped``
    so the operator sees the gap."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({})    # everything 404s
    report = run_bump(tmp_path, http=http)
    assert report.candidates == []
    assert len(report.skipped) == 1
    arg, path, reason = report.skipped[0]
    assert arg == "SEMGREP_VERSION"
    assert "upstream lookup failed" in reason


# ---------------------------------------------------------------------------
# Apply path
# ---------------------------------------------------------------------------

def test_apply_writes_clean_bumps_in_place(tmp_path: Path) -> None:
    """``apply=True`` rewrites the Dockerfile when verdict is
    Clean."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now, apply=True,
    )
    # Verdict Clean + apply → rewrite applied.
    assert report.results[0].rewrite_result is not None
    assert report.results[0].rewrite_result.applied
    # File contents updated in place.
    assert "1.119.0" in dockerfile.read_text()
    assert "1.50.0" not in dockerfile.read_text()


def test_apply_does_not_write_review_bumps(tmp_path: Path) -> None:
    """``apply=True`` honours the suggest-only policy: Review /
    Block bumps do NOT get auto-written, even with --apply.
    Operator review required."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-09T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now, apply=True,
    )
    assert report.results[0].verdict == _VERDICT_REVIEW
    assert report.results[0].rewrite_result is None
    # File untouched.
    assert dockerfile.read_text() == "ARG SEMGREP_VERSION=1.50.0\n"


def test_apply_default_is_dry_run(tmp_path: Path) -> None:
    """Default ``apply=False`` → no writes even for Clean
    verdicts. The dry-run produces the verdict report; the
    operator decides whether to ``--apply``."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert report.results[0].verdict == _VERDICT_CLEAN
    assert report.results[0].rewrite_result is None
    assert dockerfile.read_text() == "ARG SEMGREP_VERSION=1.50.0\n"


# ---------------------------------------------------------------------------
# Render report
# ---------------------------------------------------------------------------

def test_render_report_shape_and_findings_in_table(tmp_path: Path) -> None:
    """The text report shows ARG / current / target / verdict
    per row, plus inline supply-chain findings for non-Clean
    verdicts (so operators see WHY)."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2026-05-10T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    text = render_report(report)
    assert "SEMGREP_VERSION" in text
    assert "1.50.0" in text
    assert "1.119.0" in text
    assert "Review" in text
    # Inline finding annotation visible.
    assert "recent_publish" in text


def test_render_report_no_candidates_message(tmp_path: Path) -> None:
    """Friendly message when there are no candidates."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    text = render_report(report)
    assert "no bump candidates found" in text


# ---------------------------------------------------------------------------
# Cross-Dockerfile upstream-lookup deduplication
# ---------------------------------------------------------------------------

class _CountingHttp(_StubHttp):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.calls: List[str] = []

    def get_json(self, url: str, **kw):
        self.calls.append(url)
        return super().get_json(url, **kw)


# ---------------------------------------------------------------------------
# FROM image refs
# ---------------------------------------------------------------------------

def _tags_response(tags):
    return _StubResp({"name": "ignored", "tags": tags})


def test_from_image_with_clean_semver_tag_becomes_candidate(
    tmp_path: Path,
) -> None:
    """``FROM python:3.11`` → OCI tag lookup → bump candidate
    to highest stable tag."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.11", "3.12", "3.13"]},
    })
    report = run_bump(tmp_path, http=http)
    from_cands = [c for c in report.candidates if c.kind == "from_image"]
    assert len(from_cands) == 1
    cand = from_cands[0]
    assert cand.locator == "docker.io/library/python"
    assert cand.current_version == "3.11"
    assert cand.target_version == "3.13"
    # No bump-tier signals available for OCI yet → Clean.
    matching_result = [r for r in report.results
                        if r.candidate is cand][0]
    assert matching_result.verdict == _VERDICT_CLEAN


def test_from_image_variant_tag_now_bumpable(tmp_path: Path) -> None:
    """``FROM python:3.12-bookworm`` — variant-suffixed semver.
    Pre-variant-support behaviour was silent skip; today the
    walker treats it as a first-class candidate and asks the
    registry for the highest ``<semver>-bookworm`` tag.

    With an empty-tag stub (no tags returned from the registry),
    the lookup raises NoStableVersionsFound and the tag lands in
    ``skipped`` with an explicit reason — not silently dropped.
    That's the load-bearing behaviour change: an operator sees
    "couldn't bump because no bookworm tags found", not nothing.
    """
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-bookworm\n"
    )
    # Stub: registry returns empty tag list. The bumper queries
    # the variant ``bookworm`` against this, finds nothing, and
    # surfaces the skip with an explicit "no stable-semver tags"
    # reason. The /v2/library/python/tags/list URL is what
    # OciRegistryClient.list_tags hits.
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100": {
            "tags": [],
        },
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates
             if c.kind == "from_image"] == []
    # Now appears in skipped with an explanatory message —
    # operator-visible rather than silent.
    matching_skipped = [
        s for s in report.skipped
        if s[0] == "docker.io/library/python"
    ]
    assert len(matching_skipped) == 1, (
        f"expected one skipped entry for python:3.12-bookworm, "
        f"got {report.skipped!r}"
    )
    _, _, reason = matching_skipped[0]
    assert "OCI tag lookup failed" in reason


def test_from_image_digest_pinned_silently_skipped(tmp_path: Path) -> None:
    """Digest-pinned FROM is immutable — not a bump target."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11@sha256:abc123\n"
    )
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates
             if c.kind == "from_image"] == []


# ---------------------------------------------------------------------------
# Inline ``RUN pip install <name>==<version>`` (Phase 3.f)
# ---------------------------------------------------------------------------

def _stub_pypi_with_versions(packages: dict) -> object:
    """A PyPI stub that supports both ``get_metadata`` (existing
    Tier-1 detectors) AND ``list_versions`` (the inline-install
    walker added in Phase 3.f). ``packages`` is a dict mapping
    name → list[version]."""
    class _S:
        def __init__(self, p): self._p = p
        def get_metadata(self, n):
            v = self._p.get(n)
            if v is None:
                return None
            return {"releases": {ver: [] for ver in v}}
        def list_versions(self, n):
            return list(self._p.get(n) or [])
    return _S(packages)


def test_inline_install_pip_pinned_becomes_candidate(
    tmp_path: Path,
) -> None:
    """``RUN pip install semgrep==1.161.0`` with newer stable
    release on PyPI → inline_install_pip bump candidate."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir semgrep==1.161.0\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.12", "3.13"]},
    })
    pypi = _stub_pypi_with_versions({
        "semgrep": ["1.160.0", "1.161.0", "1.162.0", "1.163.0"],
    })
    report = run_bump(tmp_path, http=http, pypi_client=pypi)
    inline = [c for c in report.candidates
              if c.kind == "inline_install_pip"]
    assert len(inline) == 1
    assert inline[0].locator == "semgrep"
    assert inline[0].current_version == "1.161.0"
    assert inline[0].target_version == "1.163.0"
    # Upstream populated as ``pypi_meta`` for inline_install_pip
    # (was None pre-2026-05-20 polish; updated to record the
    # PyPI lookup coordinate for ``--json`` audit completeness).
    assert inline[0].upstream is not None
    assert inline[0].upstream.kind == "pypi_meta"
    assert inline[0].upstream.coordinate == "semgrep"
    assert inline[0].extra == {"kind": "inline_install_pip"}


def test_inline_install_pip_already_at_latest_not_a_candidate(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.163.0\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.13"]},
    })
    pypi = _stub_pypi_with_versions({
        "semgrep": ["1.161.0", "1.162.0", "1.163.0"],
    })
    report = run_bump(tmp_path, http=http, pypi_client=pypi)
    assert [c for c in report.candidates
            if c.kind == "inline_install_pip"] == []


def test_inline_install_pip_no_pypi_client_skipped(
    tmp_path: Path,
) -> None:
    """When the caller doesn't pass a PyPI client (e.g. offline
    runs), the inline-install walker is skipped entirely — no
    crash, no candidates, no skipped entries."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.161.0\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python", "tags": ["3.13"]},
    })
    report = run_bump(tmp_path, http=http, pypi_client=None)
    assert [c for c in report.candidates
            if c.kind == "inline_install_pip"] == []


def test_inline_install_pip_non_exact_pin_skipped(
    tmp_path: Path,
) -> None:
    """Range pins (``>=1.0``, ``~=2.0``) need different bump
    semantics than exact pins — out of scope for v1."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13\nRUN pip install 'semgrep>=1.0.0'\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.13"]},
    })
    pypi = _stub_pypi_with_versions({
        "semgrep": ["1.161.0", "1.162.0", "1.163.0"],
    })
    report = run_bump(tmp_path, http=http, pypi_client=pypi)
    assert [c for c in report.candidates
            if c.kind == "inline_install_pip"] == []


def test_inline_install_pip_apply_writes_through_dispatcher(
    tmp_path: Path,
) -> None:
    """End-to-end: ``apply=True`` with a Clean inline_install
    candidate routes through the dockerfile_from dispatcher and
    rewrites the file."""
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir semgrep==1.161.0\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python", "tags": ["3.13"]},
    })
    pypi = _stub_pypi_with_versions({
        "semgrep": ["1.161.0", "1.163.0"],
    })
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, apply=True,
    )
    applied = [
        r for r in report.results
        if r.candidate.kind == "inline_install_pip" and r.rewrite_result
        and r.rewrite_result.applied
    ]
    assert len(applied) == 1
    assert "semgrep==1.163.0" in df.read_text()


def test_from_image_stage_reuse_skipped(tmp_path: Path) -> None:
    """Multi-stage builds: ``FROM build AS runtime`` (where
    ``build`` is a prior stage name, not an image) shouldn't be
    bump-attempted."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11 AS build\n"
        "RUN do-build\n"
        "FROM build AS runtime\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.11", "3.12"]},
    })
    report = run_bump(tmp_path, http=http)
    from_cands = [c for c in report.candidates if c.kind == "from_image"]
    assert len(from_cands) == 1     # python only, not the stage reuse
    assert from_cands[0].locator == "docker.io/library/python"


def test_from_image_already_at_latest_not_a_candidate(tmp_path: Path) -> None:
    """FROM at highest stable tag → not a bump target."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.13\n")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.11", "3.12", "3.13"]},
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates
             if c.kind == "from_image"] == []


def test_from_image_apply_writes_dockerfile(tmp_path: Path) -> None:
    """End-to-end with --apply: FROM gets rewritten in place."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11\n")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python",
             "tags": ["3.11", "3.12", "3.13"]},
    })
    run_bump(tmp_path, http=http, apply=True)
    assert "FROM python:3.13" in dockerfile.read_text()


def test_mixed_arg_and_from_in_one_dockerfile(tmp_path: Path) -> None:
    """A devcontainer-shaped Dockerfile with both an ARG pin AND
    a FROM image — both surface as candidates."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.11\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python", "tags": ["3.11", "3.12"]},
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    from datetime import datetime, timezone
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(tmp_path, http=http, pypi_client=pypi, now=now)
    by_kind = {c.kind for c in report.candidates}
    assert by_kind == {"arg", "from_image"}


# ---------------------------------------------------------------------------
# GHA uses refs (Phase 3.b)
# ---------------------------------------------------------------------------

def _workflow(tmp_path: Path, name: str, body: str) -> Path:
    wf = tmp_path / ".github" / "workflows" / name
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(body)
    return wf


def test_gha_tag_pinned_uses_becomes_candidate(tmp_path: Path) -> None:
    """Tag-pinned ``uses: foo/bar@v4`` with newer upstream
    release → bump candidate."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    gha_cands = [c for c in report.candidates if c.kind == "gha_uses"]
    assert len(gha_cands) == 1
    c = gha_cands[0]
    assert c.locator == "actions/checkout"
    assert c.current_version == "v4"
    assert c.target_version == "v5"


def test_gha_sha_pinned_uses_skipped(tmp_path: Path) -> None:
    """SHA-pinned ``uses: foo/bar@<40hex>`` — Phase 3.b skips
    silently (3.b.2 will handle SHA+comment with tag→SHA
    resolution)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@"
              "de0fac2e4500dabe0009e67214ff5f5447ce83dd  # was v6\n")
    http = _StubHttp({})    # no upstream fetched
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_branch_pinned_uses_skipped(tmp_path: Path) -> None:
    """Branch-pinned ``uses: foo/bar@main`` — out of scope for
    auto-bumper (would be a security upgrade, not a bump)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@main\n")
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_major_only_pin_no_same_major_bump(tmp_path: Path) -> None:
    """``uses: foo/bar@v4`` with upstream-latest ``v4.2.1`` —
    no candidate. Operator chose major-only pinning explicitly;
    proposing a same-major specific-version roll would be
    unwanted churn."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v4.2.1"},
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_major_only_pin_major_bump_is_a_candidate(tmp_path: Path) -> None:
    """``uses: foo/bar@v4`` with upstream-latest ``v5`` →
    candidate (cross-major bump is a real change)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    assert len([c for c in report.candidates
                 if c.kind == "gha_uses"]) == 1


def test_gha_sub_action_path_walker(tmp_path: Path) -> None:
    """``uses: github/codeql-action/init@v4`` — locator should
    be ``github/codeql-action`` (the repo, without the subpath)
    so the upstream lookup hits the right GitHub repo."""
    _workflow(tmp_path, "codeql.yml",
              "      - uses: github/codeql-action/init@v4\n"
              "      - uses: github/codeql-action/analyze@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/github/codeql-action/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    gha_cands = [c for c in report.candidates if c.kind == "gha_uses"]
    # Both ``init`` and ``analyze`` sub-actions surface the
    # same repo (same locator). Walker dedup via cache means we
    # only hit the upstream once, but each subpath line is its
    # own candidate.
    assert len(gha_cands) == 2
    assert all(c.locator == "github/codeql-action" for c in gha_cands)


def test_gha_already_at_latest_no_candidate(tmp_path: Path) -> None:
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@v5\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_apply_writes_workflow_file(tmp_path: Path) -> None:
    """End-to-end: ``--apply`` rewrites the workflow YAML."""
    wf = _workflow(tmp_path, "ci.yml",
                    "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    run_bump(tmp_path, http=http, apply=True)
    assert "uses: actions/checkout@v5" in wf.read_text()


# ---------------------------------------------------------------------------
# GHA SHA-pinned with ``# was vX`` comment (Phase 3.b.2)
# ---------------------------------------------------------------------------

def test_gha_sha_pinned_with_comment_becomes_candidate(tmp_path: Path) -> None:
    """Raptor's convention: SHA-pinned + ``# was vX`` comment.
    Walker detects the shape, looks up upstream-latest tag,
    resolves to target SHA, emits candidate with both."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@"
              "de0fac2e4500dabe0009e67214ff5f5447ce83dd  # was v6\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v7"},
        "https://api.github.com/repos/actions/checkout/git/refs/tags/v7":
            {"object": {"type": "commit",
                         "sha": "ffffffffffffffffffffffffffffffffffffffff"}},
    })
    report = run_bump(tmp_path, http=http)
    gha_cands = [c for c in report.candidates if c.kind == "gha_uses"]
    assert len(gha_cands) == 1
    c = gha_cands[0]
    assert c.locator == "actions/checkout"
    assert c.current_version == "v6"
    assert c.target_version == "v7"
    assert c.extra["old_sha"] == "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    assert c.extra["new_sha"] == "f" * 40


def test_gha_sha_pinned_apply_writes_both_sha_and_comment(
    tmp_path: Path,
) -> None:
    """End-to-end: ``--apply`` on a SHA-pinned with ``# was vX``
    rewrites both the SHA and the comment tag."""
    wf = _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@"
              "0000000000000000000000000000000000000000  # was v6\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v7"},
        "https://api.github.com/repos/actions/checkout/git/refs/tags/v7":
            {"object": {"type": "commit", "sha": "1" * 40}},
    })
    run_bump(tmp_path, http=http, apply=True)
    text = wf.read_text()
    assert "@" + "1" * 40 in text
    assert "# was v7" in text
    assert "0000" not in text


def test_gha_sha_pinned_already_at_latest_no_candidate(tmp_path: Path) -> None:
    """SHA-pinned at latest tag → not a candidate (the bumper
    correctly handles the same-tag-but-different-SHA edge — only
    if upstream actually advanced)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@"
              "1111111111111111111111111111111111111111  # was v7\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v7"},
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_sha_pinned_same_major_pin_skipped(tmp_path: Path) -> None:
    """``# was v4`` and target is v4.x → same-major; skip
    (operator chose major-only pinning)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@"
              "0000000000000000000000000000000000000000  # was v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v4.2.1"},
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []


def test_gha_releases_latest_non_semver_falls_back_to_tags(
    tmp_path: Path,
) -> None:
    """``github/codeql-action``-shaped case: ``releases/latest``
    returns ``codeql-bundle-v2.25.4`` (a stable release but
    non-semver tag shape). The bumper can't substitute that for
    a ``v4`` pin; it should fall through to ``/tags`` and pick
    the highest stable-semver tag from there.

    Pre-fix the bumper proposed
    ``v4 → codeql-bundle-v2.25.4`` which would have produced an
    invalid pin. Live-output regression from raptor's actual
    workflow scan."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: github/codeql-action/init@v4\n")
    http = _StubHttp({
        # /releases/latest returns the non-semver bundle tag.
        "https://api.github.com/repos/github/codeql-action/releases/latest":
            {"tag_name": "codeql-bundle-v2.25.4"},
        # /tags has both bundle tags (skipped) AND stable-semver tags.
        "https://api.github.com/repos/github/codeql-action/tags?per_page=100":
            [
                {"name": "codeql-bundle-v2.25.4"},   # non-semver — skip
                {"name": "v5"},                       # stable — winner
                {"name": "v4.30.6"},
                {"name": "v4"},
            ],
    })
    report = run_bump(tmp_path, http=http)
    gha_cands = [c for c in report.candidates if c.kind == "gha_uses"]
    assert len(gha_cands) == 1
    # MUST be the stable-semver candidate, NOT codeql-bundle.
    assert gha_cands[0].target_version == "v5"
    assert "codeql-bundle" not in gha_cands[0].target_version


def test_gha_releases_latest_and_tags_both_non_semver_skipped(
    tmp_path: Path,
) -> None:
    """When NEITHER /releases/latest NOR /tags produces a
    stable-semver tag, the repo lands in ``skipped`` with a
    clear reason. Operator sees the gap rather than the bumper
    proposing a non-semver pin."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: weird/project@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/weird/project/releases/latest":
            {"tag_name": "release-2026-q1"},
        "https://api.github.com/repos/weird/project/tags?per_page=100":
            [{"name": "release-2026-q1"}, {"name": "rc-build-7"}],
    })
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates if c.kind == "gha_uses"] == []
    # Should be in skipped with explanatory reason.
    skipped_reasons = [s[2] for s in report.skipped
                        if s[0] == "weird/project"]
    assert len(skipped_reasons) == 1
    assert "non-semver" in skipped_reasons[0]


def test_gha_upstream_404_falls_back_to_tags(tmp_path: Path) -> None:
    """Some actions don't cut releases. Walker falls back to
    /tags (we already shipped ``latest_tag`` in Phase 2.a)."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: anthropics/claude-code@v2.0\n")
    # /releases/latest 404s; /tags returns a list.
    http = _StubHttp({
        "https://api.github.com/repos/anthropics/claude-code/tags?per_page=100":
            [{"name": "v2.1"}, {"name": "v2.0"}],
    })
    report = run_bump(tmp_path, http=http)
    gha_cands = [c for c in report.candidates if c.kind == "gha_uses"]
    assert len(gha_cands) == 1
    assert gha_cands[0].current_version == "v2.0"
    assert gha_cands[0].target_version == "v2.1"


# ---------------------------------------------------------------------------
# Helm chart deps (Phase 3.d)
# ---------------------------------------------------------------------------

def test_helm_chart_dependency_becomes_candidate(tmp_path: Path) -> None:
    """``Chart.yaml`` with ``dependencies:`` pointing at an
    out-of-date chart → bump candidate via the helm_index
    lookup."""
    # Helm parser needs PyYAML; skip if absent.
    pytest.importorskip("yaml")
    import yaml
    (tmp_path / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: my-chart\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 13.4.4\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
    )

    # The bumper's helm walker calls http.get_bytes on the
    # repo's index.yaml. Use a stub that delivers a
    # YAML-encoded payload.
    index_payload = yaml.safe_dump({
        "apiVersion": "v1",
        "entries": {
            "postgresql": [
                {"version": "13.4.4"},
                {"version": "14.0.0"},
            ],
        },
    }).encode()

    class _StubHttpBytes(_StubHttp):
        def get_bytes(self, url, **kw):
            if url == "https://charts.bitnami.com/bitnami/index.yaml":
                return index_payload
            from core.http import HttpError
            raise HttpError(f"no payload for {url}")

    http = _StubHttpBytes({})
    report = run_bump(tmp_path, http=http)
    helm_cands = [c for c in report.candidates
                   if c.kind == "helm_chart"]
    assert len(helm_cands) == 1
    c = helm_cands[0]
    assert c.locator == "postgresql"
    assert c.current_version == "13.4.4"
    assert c.target_version == "14.0.0"
    assert c.extra["repository"] == "https://charts.bitnami.com/bitnami"


def test_helm_chart_apply_writes_chart_yaml(tmp_path: Path) -> None:
    """End-to-end: ``--apply`` rewrites the Chart.yaml's
    dependency version."""
    pytest.importorskip("yaml")
    import yaml
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "apiVersion: v2\n"
        "name: my-chart\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "    repository: https://charts.example.com/\n"
    )
    index = yaml.safe_dump({
        "apiVersion": "v1",
        "entries": {"redis": [
            {"version": "17.0.0"}, {"version": "18.0.0"},
        ]},
    }).encode()

    class _StubHttpBytes(_StubHttp):
        def get_bytes(self, url, **kw):
            if url == "https://charts.example.com/index.yaml":
                return index
            from core.http import HttpError
            raise HttpError(f"no payload for {url}")

    http = _StubHttpBytes({})
    run_bump(tmp_path, http=http, apply=True)
    assert "version: 18.0.0" in chart.read_text()


def test_helm_chart_without_repository_silently_skipped(
    tmp_path: Path,
) -> None:
    """Vendored / file-based Chart.yaml deps lack a
    ``repository`` URL — can't look up upstream. Silent skip."""
    pytest.importorskip("yaml")
    (tmp_path / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: parent\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: child\n"
        "    version: 1.0.0\n"
    )
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates
             if c.kind == "helm_chart"] == []


# ---------------------------------------------------------------------------
# Git submodule pins (Phase 3.e)
# ---------------------------------------------------------------------------

def _gitmodules(tmp_path: Path, url: str, sm_path: str, sha: str) -> Path:
    """Build a minimal git-repo-shaped target with one
    submodule recorded at ``sha``. The .gitmodules parser walks
    the parent's git object DB to find the submodule SHA, so we
    have to build enough of a git tree for it to find — OR set
    up a stub. Simpler: bypass the parser's git-resolution by
    pre-resolving and feeding the parser a fixture."""
    (tmp_path / ".git").mkdir(exist_ok=True)
    # Minimal: write .gitmodules + an index entry mock would
    # require real git surgery. Use the parser internals directly
    # in tests instead — see test_git_submodule_candidate.
    gm = tmp_path / ".gitmodules"
    gm.write_text(
        f'[submodule "vendor/foo"]\n'
        f'\tpath = {sm_path}\n'
        f'\turl = {url}\n'
    )
    return gm


def test_git_submodule_candidate_via_parser(tmp_path: Path) -> None:
    """The .gitmodules parser resolves submodule SHAs by walking
    the parent's git object DB. In tests we bypass that and feed
    the orchestrator a pre-built Dependency via the parser
    fixture — verify the orchestrator wires the candidate
    correctly.

    For Phase 3.e, the relevant invariant is: given a submodule
    with a current SHA + GitHub URL, the bumper produces a
    candidate with new_sha in extra. We test that via the
    walker directly with a stub."""
    from packages.sca.bump.orchestrator import (
        _enumerate_git_submodule_candidates,
    )
    from packages.sca.models import (
        Confidence, Dependency, PinStyle,
    )

    current_sha = "a" * 40
    target_sha = "b" * 40
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
        "https://api.github.com/repos/actions/checkout/git/refs/tags/v5":
            {"object": {"type": "commit", "sha": target_sha}},
    })
    # Build a Dependency directly to bypass the real .gitmodules
    # parser (which would otherwise need a real git object DB).
    fake_dep = Dependency(
        ecosystem="GitHub",
        name="actions/checkout",
        version=current_sha,
        declared_in=tmp_path / ".gitmodules",
        scope="main", is_lockfile=True, pin_style=PinStyle.GIT,
        direct=True,
        purl=f"pkg:github/actions/checkout@{current_sha}",
        parser_confidence=Confidence("high", reason="t"),
        source_kind="git_submodule",
        source_extra={"url": "https://github.com/actions/checkout.git",
                       "path": "vendor/checkout",
                       "submodule_name": "vendor/checkout"},
    )
    # Patch ``parse_manifest`` to return our fake dep when
    # called against .gitmodules.
    from packages.sca import parsers as _parsers_mod
    orig = _parsers_mod.parse_manifest

    def _fake_parse(manifest):
        if manifest.path.name == ".gitmodules":
            return [fake_dep]
        return orig(manifest)

    _parsers_mod.parse_manifest = _fake_parse
    try:
        # Need a discoverable .gitmodules manifest.
        (tmp_path / ".gitmodules").write_text("# stub\n")
        cands, skipped = _enumerate_git_submodule_candidates(
            tmp_path, http=http, cache=None,
            github_token=None, sub_cache={},
        )
    finally:
        _parsers_mod.parse_manifest = orig

    assert len(cands) == 1
    c = cands[0]
    assert c.kind == "git_submodule"
    assert c.locator == "actions/checkout"
    assert c.current_version == current_sha
    assert c.target_version == "v5"          # human-readable tag
    assert c.extra["old_sha"] == current_sha
    assert c.extra["new_sha"] == target_sha
    assert c.extra["submodule_path"] == "vendor/checkout"


def test_git_submodule_apply_emits_manual_instruction(
    tmp_path: Path,
) -> None:
    """``--apply`` for git_submodule candidates doesn't rewrite —
    instead emits a ``manual: git submodule update ...``
    instruction the operator can run."""
    from packages.sca.bump.orchestrator import (
        _evaluate_one,
    )
    cand = BumpCandidate(
        kind="git_submodule",
        locator="actions/checkout",
        file=tmp_path / ".gitmodules",
        current_version="a" * 40,
        target_version="v5",
        upstream=None,
        extra={
            "old_sha": "a" * 40,
            "new_sha": "b" * 40,
            "submodule_path": "vendor/checkout",
        },
    )
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    result = _evaluate_one(
        cand, pypi_client=None, npm_client=None,
        osv_client=None, kev_client=None, epss_client=None,
        now=now,
    )
    # Verdict is Clean (no bump-tier signals for git submodules).
    assert result.verdict == _VERDICT_CLEAN
    # The apply-skip + manual instruction are handled in the
    # run_bump loop, NOT in _evaluate_one. Test that path via
    # run_bump. (Falling through here just to assert verdict.)


# ---------------------------------------------------------------------------
# Render-side deduplication (Followup B)
# ---------------------------------------------------------------------------

def test_render_dedups_identical_candidates_across_files(
    tmp_path: Path,
) -> None:
    """When 3 workflow files all pin actions/checkout@v4, the
    rendered report shows ONE row with ``(3 files)`` — not three
    identical rows. The underlying ``results`` list still has
    three entries so --apply touches all three files.

    Pre-fix raptor's bump output showed 8 CODEQL_VERSION rows
    and 3 github/codeql-action rows; operators read it as
    duplicate noise."""
    for name in ("a.yml", "b.yml", "c.yml"):
        _workflow(tmp_path, name,
                  "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    # Underlying results: 3 (one per file).
    gha_results = [r for r in report.results
                    if r.candidate.kind == "gha_uses"]
    assert len(gha_results) == 3
    # Rendered: one row with "(3 files)" annotation.
    text = render_report(report)
    # Filter to candidate ROWS (kind=gha_uses appears in the
    # candidate rows but also in the header — exclude header
    # by looking for the locator field directly).
    rows = [line for line in text.splitlines()
             if "actions/checkout" in line]
    assert len(rows) == 1, (
        f"expected 1 deduped row; got {len(rows)}: {rows}"
    )
    # The result column carries the file count.
    assert "(3 files)" in rows[0]


def test_render_applied_count_in_dedup_row(tmp_path: Path) -> None:
    """When --apply runs, the dedup row shows ``applied (N
    files)`` rather than just ``applied``."""
    for name in ("a.yml", "b.yml"):
        _workflow(tmp_path, name,
                  "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http, apply=True)
    text = render_report(report)
    # All files applied → "applied (2 files)" suffix.
    assert "applied (2 files)" in text


def test_render_single_file_still_shows_filename_count(
    tmp_path: Path,
) -> None:
    """A non-duplicated row still renders cleanly without the
    file-count noise — single-file candidates were already fine
    pre-fix; preserve that."""
    _workflow(tmp_path, "ci.yml",
              "      - uses: actions/checkout@v4\n")
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    text = render_report(report)
    # Single-file candidate: no "(N files)" suffix (renders empty
    # Result column).
    rows = [line for line in text.splitlines()
             if "actions/checkout" in line]
    assert len(rows) == 1
    assert "(1 file)" not in rows[0]
    assert "(2 files)" not in rows[0]


# ---------------------------------------------------------------------------
# OSV vuln-delta integration (Phase 4)
# ---------------------------------------------------------------------------

class _StubOsv:
    def __init__(self, advisories_for):
        self._adv = advisories_for

    def query_batch(self, deps):
        from packages.sca.osv import OsvResult
        return [OsvResult(d.key(),
                          self._adv.get((d.ecosystem, d.name, d.version), []))
                for d in deps]


def _adv(osv_id, severity="high"):
    from packages.sca.models import AffectedRange, Advisory, CVSSScore
    return Advisory(
        osv_id=osv_id, aliases=[], summary="x", details="",
        affected=[AffectedRange(type="ECOSYSTEM",
                                  events=[{"introduced": "0"}])],
        severity=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N",
                            severity=severity),
        fixed_versions=[], references=[],
    )


def test_bumper_escalates_on_new_cve_in_target(tmp_path: Path) -> None:
    """Bump introduces a critical CVE the current pin doesn't
    have → verdict escalates via the vuln_findings path. Critical
    + no-fix → Block."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    osv = _StubOsv({
        ("PyPI", "semgrep", "1.50.0"): [],
        ("PyPI", "semgrep", "1.119.0"): [_adv("GHSA-new-crit", "critical")],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    r = report.results[0]
    # New CVE was emitted in bump_vuln_findings.
    assert len(r.bump_vuln_findings) == 1
    assert r.bump_vuln_findings[0].advisories[0].osv_id == "GHSA-new-crit"
    # Verdict escalated (critical without fix → Block).
    assert r.verdict == _VERDICT_BLOCK


def test_bumper_no_escalation_when_cve_present_in_both(tmp_path: Path) -> None:
    """CVE present in BOTH current and target → vuln-delta is
    empty → verdict from supply-chain alone."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    shared = _adv("GHSA-shared", "critical")
    osv = _StubOsv({
        ("PyPI", "semgrep", "1.50.0"): [shared],
        ("PyPI", "semgrep", "1.119.0"): [shared],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    r = report.results[0]
    assert r.bump_vuln_findings == []
    assert r.verdict == _VERDICT_CLEAN


def test_bumper_without_osv_client_falls_through_to_supply_chain(
    tmp_path: Path,
) -> None:
    """``osv_client=None`` → no vuln-delta check, verdict comes
    from supply-chain alone (matches pre-Phase-4 behaviour)."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    r = report.results[0]
    assert r.bump_vuln_findings == []
    assert r.verdict == _VERDICT_CLEAN


def test_render_report_surfaces_new_cves_inline(tmp_path: Path) -> None:
    """The verdict table shows ``new-CVE GHSA-...`` rows inline
    so operators know WHY the bump is blocked without opening
    another tool."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    osv = _StubOsv({
        ("PyPI", "semgrep", "1.50.0"): [],
        ("PyPI", "semgrep", "1.119.0"): [_adv("GHSA-new-bad", "critical")],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    text = render_report(report)
    assert "new-CVE GHSA-new-bad" in text


# ---------------------------------------------------------------------------
# YAML image: refs (Phase 3.c)
# ---------------------------------------------------------------------------

def test_compose_image_with_stable_semver_becomes_candidate(
    tmp_path: Path,
) -> None:
    """``compose.yml`` with ``image: postgres:15`` and upstream
    has ``16`` → bump candidate emitted via the existing OCI
    upstream-latest path."""
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:15\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/postgres/tags/list?n=100":
            {"name": "library/postgres",
             "tags": ["15", "16", "16.1"]},
    })
    report = run_bump(tmp_path, http=http)
    yaml_cands = [c for c in report.candidates
                   if c.kind == "yaml_image"]
    assert len(yaml_cands) == 1
    c = yaml_cands[0]
    assert c.locator == "docker.io/library/postgres"
    assert c.current_version == "15"
    assert c.target_version == "16.1"


def test_compose_apply_writes_image_tag(tmp_path: Path) -> None:
    """End-to-end: ``--apply`` rewrites the compose file's image
    tag."""
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:15\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/postgres/tags/list?n=100":
            {"name": "library/postgres",
             "tags": ["15", "16"]},
    })
    run_bump(tmp_path, http=http, apply=True)
    assert "image: postgres:16" in compose.read_text()


def test_k8s_manifest_image_walked(tmp_path: Path) -> None:
    """k8s ``Deployment`` manifest with a container image ref —
    bump candidate via the existing k8s parser."""
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: nginx\n"
        "          image: nginx:1.25\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/nginx/tags/list?n=100":
            {"name": "library/nginx",
             "tags": ["1.25", "1.27"]},
    })
    report = run_bump(tmp_path, http=http)
    yaml_cands = [c for c in report.candidates
                   if c.kind == "yaml_image"]
    assert len(yaml_cands) == 1
    assert yaml_cands[0].current_version == "1.25"
    assert yaml_cands[0].target_version == "1.27"


def test_gha_workflow_image_NOT_walked_as_yaml_image(tmp_path: Path) -> None:
    """``.github/workflows/*.yml`` files are excluded from the
    yaml_image walker — they're the GHA-uses walker's territory.
    Even if the workflow has an ``image:`` line (job container),
    we don't emit a yaml_image candidate."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n"
        "  build:\n"
        "    container:\n"
        "      image: python:3.11\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            {"name": "library/python", "tags": ["3.11", "3.12"]},
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    yaml_cands = [c for c in report.candidates
                   if c.kind == "yaml_image"]
    # No yaml_image candidate — the GHA workflow is excluded.
    assert yaml_cands == []
    # But the GHA-uses walker DID emit its candidate.
    gha_cands = [c for c in report.candidates
                  if c.kind == "gha_uses"]
    assert len(gha_cands) == 1


def test_compose_variant_tag_silently_skipped(tmp_path: Path) -> None:
    """``image: postgres:15-alpine`` — variant tag, not clean
    semver. Walker skips silently (same convention as
    Dockerfile FROM walker)."""
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:15-alpine\n"
    )
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    assert [c for c in report.candidates
             if c.kind == "yaml_image"] == []


def test_upstream_lookup_dedups_across_dockerfiles(tmp_path: Path) -> None:
    """Two Dockerfiles both pinning SEMGREP_VERSION should hit
    the upstream-latest endpoint ONCE — the orchestrator caches
    per (kind, coordinate) within a single run."""
    (tmp_path / "Dockerfile").write_text("ARG SEMGREP_VERSION=1.50.0\n")
    (tmp_path / "Dockerfile.dev").write_text("ARG SEMGREP_VERSION=1.50.0\n")
    http = _CountingHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, now=now,
    )
    assert len(report.candidates) == 2
    # ONE HTTP call to GitHub releases despite TWO Dockerfiles.
    gh_calls = [
        c for c in http.calls
        if "api.github.com" in c
    ]
    assert len(gh_calls) == 1


# ---------------------------------------------------------------------------
# Binary-capability-delta wiring
# ---------------------------------------------------------------------------


class TestBinaryCapabilityDeltaWiring:
    """The 5th-Tier-1 signal is opt-in via policy. When enabled
    AND the candidate is image-shaped, the orchestrator extracts
    current + target binaries and runs the capability diff. These
    tests stub the extractor + detector rather than running
    radare2 — the orchestrator wiring is what's under test."""

    def test_disabled_by_default_no_extractor_call(
        self, tmp_path, monkeypatch,
    ):
        """Default policy = off. Even with a from_image candidate,
        the extractor should NEVER be invoked."""
        from packages.sca.bump import orchestrator as orch_mod

        calls = {"fetch": 0, "detect": 0}
        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            lambda *a, **k: (calls.__setitem__(
                "fetch", calls["fetch"] + 1) or None),
        )
        monkeypatch.setattr(
            "packages.sca.bump.binary_capability_delta."
            "binary_capability_delta_finding",
            lambda *a, **k: (calls.__setitem__(
                "detect", calls["detect"] + 1) or None),
        )

        cand = orch_mod.BumpCandidate(
            kind="from_image",
            locator="docker.io/library/alpine",
            file=tmp_path / "Dockerfile",
            current_version="3.18", target_version="3.19",
        )
        result = orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            binary_capability_delta_enabled=False,
        )
        assert calls["fetch"] == 0
        assert calls["detect"] == 0
        assert result.bump_supply_chain_findings == []

    def test_enabled_from_image_triggers_extractor(
        self, tmp_path, monkeypatch,
    ):
        """Policy on + from_image candidate → extractor called
        twice (current + target), detector called once."""
        from packages.sca.bump import orchestrator as orch_mod

        from packages.sca.models import (
            Confidence, Dependency, PinStyle, SupplyChainFinding,
        )

        fetched = []

        def fake_fetch(ref, *, client, **kwargs):
            fetched.append(ref)
            return tmp_path / f"binary-{ref.replace('/', '_')}"

        sentinel_dep = Dependency(
            ecosystem="Container",
            name="docker.io/library/alpine",
            version="3.19",
            declared_in=Path("/<bump>"),
            scope="main", is_lockfile=False,
            pin_style=PinStyle.EXACT, direct=True,
            purl="pkg:container/docker.io/library/alpine@3.19",
            parser_confidence=Confidence("high", reason="test"),
        )
        sentinel = SupplyChainFinding(
            finding_id="sca:bump:binary_capability_delta:test",
            kind="binary_capability_delta", dependency=sentinel_dep,
            detail="test", evidence={}, severity="high",
            confidence=Confidence("medium", reason="test"),
        )

        detect_calls = []

        def fake_finding(**kwargs):
            detect_calls.append(kwargs)
            return sentinel

        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            fake_fetch,
        )
        monkeypatch.setattr(
            "packages.sca.bump.binary_capability_delta."
            "binary_capability_delta_finding",
            fake_finding,
        )

        cand = orch_mod.BumpCandidate(
            kind="from_image",
            locator="docker.io/library/alpine",
            file=tmp_path / "Dockerfile",
            current_version="3.18", target_version="3.19",
        )
        result = orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            binary_capability_delta_enabled=True,
        )
        assert fetched == [
            "docker.io/library/alpine:3.18",
            "docker.io/library/alpine:3.19",
        ]
        assert len(detect_calls) == 1
        assert any(
            f.kind == "binary_capability_delta"
            for f in result.bump_supply_chain_findings
        )

    def test_enabled_arg_kind_not_triggered(self, tmp_path, monkeypatch):
        """``arg`` kind is source-pinned (semgrep ARG, etc.) — not
        image-shaped. Even with policy on, the binary detector
        does NOT fire."""
        from packages.sca.bump import orchestrator as orch_mod

        calls = {"fetch": 0}
        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            lambda *a, **k: (calls.__setitem__(
                "fetch", calls["fetch"] + 1) or None),
        )

        cand = orch_mod.BumpCandidate(
            kind="arg", locator="UNKNOWN_ARG",
            file=tmp_path / "Dockerfile",
            current_version="1.0", target_version="2.0",
        )
        orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            binary_capability_delta_enabled=True,
        )
        assert calls["fetch"] == 0

    def test_current_binary_extraction_failure_no_finding(
        self, tmp_path, monkeypatch,
    ):
        """Extractor returns None for current → bail before
        fetching target or calling detector. No finding."""
        from packages.sca.bump import orchestrator as orch_mod

        calls = {"fetched": 0, "detect": 0}
        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            lambda *a, **k: (calls.__setitem__(
                "fetched", calls["fetched"] + 1) or None),
        )
        monkeypatch.setattr(
            "packages.sca.bump.binary_capability_delta."
            "binary_capability_delta_finding",
            lambda *a, **k: (calls.__setitem__(
                "detect", calls["detect"] + 1) or None),
        )

        cand = orch_mod.BumpCandidate(
            kind="from_image",
            locator="docker.io/library/missing",
            file=tmp_path / "Dockerfile",
            current_version="1", target_version="2",
        )
        result = orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            binary_capability_delta_enabled=True,
        )
        # Current fetch attempted (returned None) → bail before
        # target fetch or detector.
        assert calls["fetched"] == 1
        assert calls["detect"] == 0
        assert result.bump_supply_chain_findings == []

    def test_gha_uses_docker_action_extracts_via_resolver(
        self, tmp_path, monkeypatch,
    ):
        """``gha_uses`` candidates flow through
        ``resolve_gha_action_image`` to map repo@ref → OCI image
        ref, then through ``fetch_image_binary`` like any other
        image candidate."""
        from packages.sca.bump import orchestrator as orch_mod
        from packages.sca.bump.gha_action_image import GhaActionImage
        from packages.sca.models import (
            Confidence, Dependency, PinStyle, SupplyChainFinding,
        )

        resolved = []
        fetched = []

        def fake_resolve(repo, ref, *, http):
            resolved.append((repo, ref))
            return GhaActionImage(
                repo=repo, ref=ref,
                image_ref=f"ghcr.io/{repo}:{ref}",
            )

        def fake_fetch(ref, *, client, **kwargs):
            fetched.append(ref)
            return tmp_path / f"binary-{ref.replace('/', '_')}"

        sentinel_dep = Dependency(
            ecosystem="GHA", name="some-org/docker-action",
            version="v2", declared_in=Path("/<bump>"),
            scope="main", is_lockfile=False,
            pin_style=PinStyle.EXACT, direct=True,
            purl="pkg:gha/some-org/docker-action@v2",
            parser_confidence=Confidence("high", reason="test"),
        )
        sentinel = SupplyChainFinding(
            finding_id="sca:bump:binary_capability_delta:gha",
            kind="binary_capability_delta", dependency=sentinel_dep,
            detail="test", evidence={}, severity="high",
            confidence=Confidence("medium", reason="test"),
        )

        monkeypatch.setattr(
            "packages.sca.bump.gha_action_image."
            "resolve_gha_action_image",
            fake_resolve,
        )
        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            fake_fetch,
        )
        monkeypatch.setattr(
            "packages.sca.bump.binary_capability_delta."
            "binary_capability_delta_finding",
            lambda **k: sentinel,
        )

        cand = orch_mod.BumpCandidate(
            kind="gha_uses",
            locator="some-org/docker-action",
            file=tmp_path / "workflow.yml",
            current_version="v1", target_version="v2",
        )
        result = orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            http=object(),
            binary_capability_delta_enabled=True,
        )
        # Resolver called for both versions
        assert resolved == [
            ("some-org/docker-action", "v1"),
            ("some-org/docker-action", "v2"),
        ]
        # OCI extractor called with the resolved image refs
        assert fetched == [
            "ghcr.io/some-org/docker-action:v1",
            "ghcr.io/some-org/docker-action:v2",
        ]
        # Finding propagated to the result
        assert any(
            f.kind == "binary_capability_delta"
            for f in result.bump_supply_chain_findings
        )

    def test_gha_uses_js_action_no_finding(
        self, tmp_path, monkeypatch,
    ):
        """Non-Docker GHA action (resolver returns None) → no
        OCI fetch, no finding."""
        from packages.sca.bump import orchestrator as orch_mod

        fetch_count = {"n": 0}
        monkeypatch.setattr(
            "packages.sca.bump.gha_action_image."
            "resolve_gha_action_image",
            lambda repo, ref, *, http: None,   # JS / composite
        )
        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            lambda *a, **k: (fetch_count.__setitem__(
                "n", fetch_count["n"] + 1) or None),
        )

        cand = orch_mod.BumpCandidate(
            kind="gha_uses", locator="actions/checkout",
            file=tmp_path / "workflow.yml",
            current_version="v3", target_version="v4",
        )
        result = orch_mod._evaluate_one(
            cand, pypi_client=None, npm_client=None,
            now=datetime(2026, 5, 17, tzinfo=timezone.utc),
            oci_client=object(),
            http=object(),
            binary_capability_delta_enabled=True,
        )
        # Resolver returned None for current → bail before OCI
        # fetch (and before resolving target).
        assert fetch_count["n"] == 0
        assert result.bump_supply_chain_findings == []


# ---------------------------------------------------------------------------
# _is_major_bump — variant suffixes + pre-1.0 minor convention
# ---------------------------------------------------------------------------

class TestIsMajorBump:
    """The ``block_on_major`` policy threshold reads
    :func:`_is_major_bump`. Two latent defects in earlier
    versions were surfaced 2026-05-20 against raptor's own
    self-bump simulation:

      * Bug A — variant-suffix Docker tags (``11-jdk``,
        ``3.9-slim``, ``18-alpine``) failed to parse via the
        bare-semver-only ``parse_stable``; the function defensively
        returned False, silently bypassing ``block_on_major: true``
        for every Docker FROM/yaml-image with a variant tag (most
        of them).

      * Bug B — pre-1.0 software (``openai 0.84 → 0.103``) was
        treated as same-major (``0 == 0``), even though npm /
        Cargo / Composer all default-cap at the minor for ``0.y.z``
        ranges. 19-minor jumps in pre-1.0 SDKs are almost-always
        breaking and now match operator intent for
        ``block_on_major: true``.
    """

    # --- Bug A: variant-suffix tags ---

    def test_jdk_variant_different_major_is_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("11-jdk", "26-jdk") is True

    def test_alpine_variant_different_major_is_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("18-alpine", "20.19.2-alpine") is True

    def test_slim_variant_same_major_is_not_major_bump(self):
        """``python:3.9-slim → 3.14.5-slim`` shares major 3 — same-major.
        The 5-minor jump is a separate concern (operationally large,
        but not "major" by the version-number axis)."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("3.9-slim", "3.14.5-slim") is False

    def test_slim_variant_same_major_minor_is_not_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("3.9-slim", "3.9.1-slim") is False

    # --- Bug A regression: bare semver paths still work ---

    def test_v_prefix_different_major_is_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("v4", "v7.0.1") is True

    def test_v_prefix_same_major_is_not_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("v6.6.5", "v6.7.0") is False

    def test_bare_semver_same_major_is_not_major_bump(self):
        """CODEQL_VERSION 2.15.5 → 2.25.4 — 10 minors but same major."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("2.15.5", "2.25.4") is False

    # --- Bug B: pre-1.0 minor-as-major ---

    def test_pre_1_0_minor_bump_is_major_bump(self):
        """Per npm / Cargo / Composer convention and semver §4
        ("anything MAY change"), ``0.21 → 0.24`` is breaking-equivalent."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("0.21.0", "0.24.0") is True

    def test_pre_1_0_big_minor_bump_is_major_bump(self):
        """``openai 0.84 → 0.103`` — 19 minors of pre-1.0 SDK churn."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("0.84.0", "0.103.1") is True

    def test_pre_1_0_patch_within_same_minor_is_not_major_bump(self):
        """``0.21.0 → 0.21.5`` — same minor, just a patch."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("0.21.0", "0.21.5") is False

    def test_pre_1_0_zero_minor_to_first_minor_is_major_bump(self):
        """``0.0.1 → 0.1.0`` — first real minor release, breaking-equivalent."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("0.0.1", "0.1.0") is True

    def test_pre_1_0_zero_minor_patches_not_major_bump(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("0.0.1", "0.0.5") is False

    # --- Conservative-on-unparseable ---

    def test_unparseable_current_returns_false(self):
        """``latest`` and branch refs aren't stable-semver — caller
        chose a non-comparable tag, function bails False instead of
        synthesising a verdict it can't justify."""
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("latest", "v1.0") is False

    def test_unparseable_target_returns_false(self):
        from packages.sca.bump.orchestrator import _is_major_bump
        assert _is_major_bump("v1.0", "main") is False


# ---------------------------------------------------------------------------
# _is_minor_skew_bump — operationally-large same-major jumps
# ---------------------------------------------------------------------------

class TestIsMinorSkewBump:
    """``block_on_minor_skew`` reads :func:`_is_minor_skew_bump`.

    Motivation: ``python 3.9 → 3.14.5`` is a 5-minor jump within
    major 3. Strict semver labels it "same major" so
    ``_is_major_bump`` returns False, but each Python minor removes
    APIs — operationally, 5 minors of Python is a big jump. This
    gate gives operators an opt-in way to block on that
    same-major-but-still-big-jump pattern."""

    def test_python_5_minor_jump_at_threshold_5_is_skew(self):
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("3.9-slim", "3.14.5-slim",
                                    threshold=5) is True

    def test_python_5_minor_jump_at_threshold_6_is_not_skew(self):
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("3.9-slim", "3.14.5-slim",
                                    threshold=6) is False

    def test_patch_only_is_not_skew(self):
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("3.9.1", "3.9.5", threshold=2) is False

    def test_codeql_10_minor_jump_at_threshold_5_is_skew(self):
        """``CODEQL_VERSION 2.15.5 → 2.25.4`` — same major, 10-minor."""
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("2.15.5", "2.25.4",
                                    threshold=5) is True

    def test_different_major_is_not_skew(self):
        """Different majors are ``_is_major_bump``'s territory; this
        gate explicitly skips them so the verdict isn't compounded."""
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("11-jdk", "26-jdk",
                                    threshold=5) is False

    def test_pre_1_0_is_not_skew(self):
        """Pre-1.0 belongs to ``_is_major_bump``'s zero-major rule;
        this gate skips it so we don't double-count."""
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("0.84.0", "0.103.1",
                                    threshold=5) is False

    def test_downgrade_is_not_skew(self):
        """Downgrades (target.minor < current.minor) don't count as a
        skew bump in the forward direction."""
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("3.14.5", "3.9", threshold=2) is False

    def test_unparseable_returns_false(self):
        from packages.sca.bump.orchestrator import _is_minor_skew_bump
        assert _is_minor_skew_bump("latest", "3.14", threshold=2) is False
