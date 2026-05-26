"""Tests for the bumper PR-comment renderer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


from packages.sca.bump.orchestrator import run_bump
from packages.sca.bump.pr_comment import render_pr_comment


# Reuse the stubs from test_orchestrator (small enough to repeat
# rather than couple test files via imports).

class _StubResp:
    def __init__(self, body):
        self._body = body
        self.status_code = 200
        self.headers: Dict[str, str] = {}

    @property
    def content(self):
        import json
        return json.dumps(self._body).encode()


class _StubHttp:
    def __init__(self, responses):
        self._responses = responses

    def get_json(self, url, **kw):
        if url in self._responses:
            return self._responses[url]
        from core.http import HttpError
        raise HttpError(f"no payload for {url}")

    def request(self, method, url, **kw):
        if url in self._responses:
            return _StubResp(self._responses[url])
        from core.http import HttpError
        raise HttpError(f"no payload for {url}")


class _StubPyPI:
    def __init__(self, p): self._p = p
    def get_metadata(self, n): return self._p.get(n)


class _StubOsv:
    def __init__(self, adv): self._adv = adv

    def query_batch(self, deps):
        from packages.sca.osv import OsvResult
        return [OsvResult(d.key(),
                          self._adv.get((d.ecosystem, d.name, d.version), []))
                for d in deps]


def _adv(osv_id, severity="critical"):
    from packages.sca.models import AffectedRange, Advisory, CVSSScore
    return Advisory(
        osv_id=osv_id, aliases=[], summary="proof", details="",
        affected=[AffectedRange(type="ECOSYSTEM",
                                  events=[{"introduced": "0"}])],
        severity=CVSSScore(score=9.8, vector="CVSS:3.1/AV:N",
                            severity=severity),
        fixed_versions=[], references=[],
    )


# ---------------------------------------------------------------------------
# Verdict header tiers
# ---------------------------------------------------------------------------

def test_no_candidates_renders_clean_no_bumps(tmp_path: Path) -> None:
    """Empty target → ``✓ no bumps available``."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    text = render_pr_comment(report)
    assert "no bumps available" in text
    assert "✓" in text


def test_clean_bumps_renders_check_verdict(tmp_path: Path) -> None:
    """All-Clean bumps → ``✓ N clean bumps available``."""
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
    report = run_bump(tmp_path, http=http, pypi_client=pypi, now=now)
    text = render_pr_comment(report)
    assert "1 clean bump" in text
    assert "✓" in text


def test_review_tier_bumps_render_warn_verdict(tmp_path: Path) -> None:
    """Review-tier (recent_publish on target) → ``⚠`` header."""
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
    report = run_bump(tmp_path, http=http, pypi_client=pypi, now=now)
    text = render_pr_comment(report)
    assert "⚠" in text
    assert "review-tier" in text


def test_block_tier_renders_blocker_verdict(tmp_path: Path) -> None:
    """Block-tier (new CVE in target) → ``🛑`` header + clear
    do-not-auto-merge guidance."""
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
        ("PyPI", "semgrep", "1.119.0"): [_adv("GHSA-bad", "critical")],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    text = render_pr_comment(report)
    assert "🛑" in text
    assert "block-tier" in text
    assert "do not auto-merge" in text


# ---------------------------------------------------------------------------
# Proposal table
# ---------------------------------------------------------------------------

def test_proposal_table_has_one_row_per_dedup_group(tmp_path: Path) -> None:
    """Identical bumps across multiple files dedup into one row
    with a ``N files`` annotation."""
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "a.yml").write_text(
        "      - uses: actions/checkout@v4\n"
    )
    (workflow_dir / "b.yml").write_text(
        "      - uses: actions/checkout@v4\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/releases/latest":
            {"tag_name": "v5"},
    })
    report = run_bump(tmp_path, http=http)
    text = render_pr_comment(report)
    # ONE row in the proposal table, not two.
    rows = [line for line in text.splitlines()
             if "actions/checkout" in line and "|" in line]
    assert len(rows) == 1
    assert "2 files" in rows[0]


def test_block_rows_sort_before_clean_rows(tmp_path: Path) -> None:
    """When the report has mixed verdicts, Block rows appear
    BEFORE Clean rows in the table — operators see the worst
    first."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
        "ARG BLACK_VERSION=20.0\n"
    )
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
        "https://api.github.com/repos/psf/black/releases/latest":
            {"tag_name": "25.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
        "black": {"releases": {
            "25.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    osv = _StubOsv({
        # SEMGREP bump introduces a critical CVE → Block
        ("PyPI", "semgrep", "1.50.0"): [],
        ("PyPI", "semgrep", "1.119.0"): [_adv("GHSA-bad", "critical")],
        # BLACK bump is clean
        ("PyPI", "black", "20.0"): [],
        ("PyPI", "black", "25.0"): [],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    text = render_pr_comment(report)
    semgrep_idx = text.find("SEMGREP_VERSION")
    black_idx = text.find("BLACK_VERSION")
    assert semgrep_idx >= 0 and black_idx >= 0, (
        f"both rows must appear; SEMGREP={semgrep_idx} "
        f"BLACK={black_idx}; output:\n{text}"
    )
    # Semgrep is Block, Black is Clean — Semgrep MUST appear first.
    assert semgrep_idx < black_idx


def test_new_cve_surfaces_in_notes_column(tmp_path: Path) -> None:
    """The Notes column inlines the new-CVE ID and (KEV) marker
    so reviewers don't need to open another tool."""
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
        ("PyPI", "semgrep", "1.119.0"): [_adv("GHSA-leak", "critical")],
    })
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    report = run_bump(
        tmp_path, http=http, pypi_client=pypi, osv_client=osv, now=now,
    )
    text = render_pr_comment(report)
    assert "new-CVE" in text
    assert "GHSA-leak" in text


# ---------------------------------------------------------------------------
# Cosmetic
# ---------------------------------------------------------------------------

def test_repo_label_renders_in_header(tmp_path: Path) -> None:
    """Operator-supplied label overrides the default for
    multi-job attribution."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    text = render_pr_comment(
        report, repo_label="raptor · pr#42 · sha=abc1234",
    )
    assert "raptor · pr#42 · sha=abc1234" in text


def test_pr_comment_skipped_section_lists_locators(tmp_path: Path) -> None:
    """Skipped surfaces render with locator + reason so PR
    reviewers can see exactly what wasn't bumped — counts alone
    force operators to re-run with ``-v`` to learn what
    happened. Long / multi-line reasons get collapsed to a
    single line."""
    from packages.sca.bump.orchestrator import BumpReport
    report = BumpReport(
        target=tmp_path,
        candidates=[],
        results=[],
        skipped=[
            (
                "postgresql (https://charts.bitnami.com/bitnami)",
                tmp_path / "Chart.yaml",
                "Helm index lookup failed:\n"
                "Helm index at https://charts.bitnami.com/bitnami "
                "missing entries map",
            ),
            (
                "actions/checkout",
                tmp_path / ".github/workflows/ci.yml",
                "OCI tag lookup failed: 403 Forbidden",
            ),
        ],
    )
    text = render_pr_comment(report)
    assert "Skipped: 2 surface(s)" in text
    assert "postgresql" in text
    assert "Chart.yaml" in text
    assert "actions/checkout" in text
    assert "ci.yml" in text
    # Newline in the reason becomes a space so the markdown list
    # item stays valid.
    assert "Helm index lookup failed:\nHelm index" not in text
    assert "Helm index lookup failed: Helm index" in text


def test_pr_comment_skipped_section_truncates_large_lists(
    tmp_path: Path,
) -> None:
    """A project with hundreds of skipped surfaces would blow
    out the PR-comment size limit — we cap at 20 and surface a
    "+N more skipped" footer."""
    from packages.sca.bump.orchestrator import BumpReport
    report = BumpReport(
        target=tmp_path,
        candidates=[],
        results=[],
        skipped=[
            (f"locator-{i}", tmp_path / "f.yml", "reason")
            for i in range(35)
        ],
    )
    text = render_pr_comment(report)
    assert "Skipped: 35 surface(s)" in text
    assert "locator-0" in text
    assert "locator-19" in text
    assert "locator-20" not in text
    assert "+15 more skipped" in text


def test_footer_contains_suggest_only_hint(tmp_path: Path) -> None:
    """Footer documents the suggest-only policy so reviewers
    don't expect ``--apply`` to auto-write Review/Block bumps."""
    http = _StubHttp({})
    report = run_bump(tmp_path, http=http)
    text = render_pr_comment(report)
    assert "suggest-only" in text
    assert "--apply" in text


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_pr_comment_cli_flag_via_main(tmp_path: Path, capsys) -> None:
    """``raptor-sca bump <target> --pr-comment`` flag routes
    output through the PR-comment renderer."""
    (tmp_path / "Dockerfile").write_text(
        "ARG SOME_VERSION=1.0\n"     # unknown → no candidates
    )
    from packages.sca.bump.cli import main as bump_main
    # No mocking — bump_main will construct real network clients.
    # We're only checking that the flag is parsed + dispatched;
    # without an upstream to query, the report is empty but valid.
    rc = bump_main([str(tmp_path), "--pr-comment",
                     "--no-cache"])
    out = capsys.readouterr().out
    assert rc == 0
    # The PR-comment shape carries the "Generated by raptor-sca
    # bump" footer — text-mode render doesn't.
    assert "Generated by raptor-sca bump" in out
