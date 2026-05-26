"""Tests for ``packages.sca.diff``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


from packages.sca import diff


def _vuln_row(
    *,
    eco: str = "npm",
    name: str = "lodash",
    version: str = "4.17.4",
    advisory_id: str = "GHSA-jf85",
    aliases: List[str] | None = None,
    severity: str = "critical",
    in_kev: bool = False,
    epss: float | None = None,
    suppressed: bool = False,
    reason: str | None = None,
) -> Dict[str, Any]:
    return {
        "id": f"sca:vuln:{eco}:{name}:{version}:{advisory_id}",
        "vuln_type": "sca:vulnerable_dependency",
        "severity": severity,
        "suppressed": suppressed,
        "suppression_reason": reason,
        "sca": {
            "ecosystem": eco, "name": name, "version": version,
            "advisory": {"id": advisory_id, "aliases": aliases or []},
            "in_kev": in_kev,
            "epss": epss,
        },
    }


def _hygiene_row(kind: str = "loose_pin", eco: str = "npm",
                 name: str = "lodash", version: str = "4.17.4",
                 severity: str = "low",
                 suppressed: bool = False) -> Dict[str, Any]:
    return {
        "id": f"sca:hygiene:{kind}:{eco}:{name}",
        "vuln_type": f"sca:hygiene:{kind}",
        "severity": severity,
        "suppressed": suppressed,
        "sca": {"ecosystem": eco, "name": name, "version": version,
                 "kind": kind},
    }


def _write(tmp_path: Path, name: str, rows: List[Dict[str, Any]]) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# compute_delta
# ---------------------------------------------------------------------------

def test_new_finding_in_b_only() -> None:
    a = []
    b = [_vuln_row()]
    d = diff.compute_delta(a, b)
    assert len(d.new) == 1
    assert d.resolved == []


def test_resolved_finding_in_a_only() -> None:
    a = [_vuln_row()]
    b = []
    d = diff.compute_delta(a, b)
    assert len(d.resolved) == 1
    assert d.new == []


def test_unchanged_findings_drop_from_diff() -> None:
    """Same finding in both → not in new, not in resolved."""
    a = [_vuln_row()]
    b = [_vuln_row()]
    d = diff.compute_delta(a, b)
    assert d.new == [] and d.resolved == []


def test_canonical_key_uses_cve_alias_for_dedup() -> None:
    """GHSA-X (CVE-Y) in A vs PYSEC-X (CVE-Y) in B = same finding."""
    a = [_vuln_row(advisory_id="GHSA-x", aliases=["CVE-2023-X"])]
    b = [_vuln_row(advisory_id="PYSEC-x", aliases=["CVE-2023-X"])]
    d = diff.compute_delta(a, b)
    assert d.new == [] and d.resolved == []


def test_suppressed_findings_excluded_by_default() -> None:
    """A finding suppressed in B looks like 'resolved' to default mode
    (because we don't see it as active), even though it still exists."""
    a = [_vuln_row()]
    b = [_vuln_row(suppressed=True, reason="ack")]
    d = diff.compute_delta(a, b)
    # New/resolved respect the visibility filter:
    assert d.resolved == [] and d.new == []
    # The suppression-state diff sees it as a state change, separate stream:
    assert len(d.suppression_added) == 1


def test_suppression_lifted_detected() -> None:
    a = [_vuln_row(suppressed=True, reason="ack")]
    b = [_vuln_row()]
    d = diff.compute_delta(a, b)
    assert len(d.suppression_lifted) == 1


def test_include_suppressed_treats_them_as_visible() -> None:
    a = [_vuln_row()]
    b = [_vuln_row(suppressed=True, reason="ack"),
         _vuln_row(name="other-lib", advisory_id="GHSA-other")]
    d = diff.compute_delta(a, b, include_suppressed=True)
    # Now the suppressed row counts as present, so the only "new" is
    # other-lib:
    new_names = [r["sca"]["name"] for r in d.new]
    assert new_names == ["other-lib"]
    # And it's *also* a suppression change:
    assert len(d.suppression_added) == 1


def test_hygiene_findings_keyed_separately(tmp_path: Path) -> None:
    a = [_hygiene_row(kind="loose_pin")]
    b = [_hygiene_row(kind="lockfile_drift")]
    d = diff.compute_delta(a, b)
    assert len(d.new) == 1
    assert len(d.resolved) == 1


def test_findings_without_canonical_key_skipped() -> None:
    """Rows from other tools (no advisory id, not hygiene/supply_chain)
    are silently dropped — diff is SCA-only."""
    a = [{"vuln_type": "scan:other", "severity": "high"}]
    b = []
    d = diff.compute_delta(a, b)
    assert d.resolved == []


# ---------------------------------------------------------------------------
# CLI / argparse
# ---------------------------------------------------------------------------

def test_main_writes_markdown_by_default(tmp_path: Path, capsys) -> None:
    a = _write(tmp_path, "a.json", [])
    b = _write(tmp_path, "b.json", [_vuln_row()])
    rc = diff.main([str(a), str(b)])
    assert rc == 1   # B introduces a critical → above default --severity high
    out = capsys.readouterr().out
    assert "# raptor-sca diff" in out
    assert "## New findings" in out
    assert "lodash" in out


def test_main_emits_json_with_flag(tmp_path: Path, capsys) -> None:
    a = _write(tmp_path, "a.json", [])
    b = _write(tmp_path, "b.json", [_vuln_row()])
    diff.main([str(a), str(b), "--json"])
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"]["new"] == 1
    assert parsed["summary"]["resolved"] == 0


def test_main_writes_to_out_path(tmp_path: Path, capsys) -> None:
    a = _write(tmp_path, "a.json", [_vuln_row()])
    b = _write(tmp_path, "b.json", [])
    out = tmp_path / "delta.md"
    diff.main([str(a), str(b), "--out", str(out)])
    assert out.exists()
    body = out.read_text()
    assert "## Resolved findings" in body
    # stdout matches the file body.
    assert capsys.readouterr().out.startswith(body)


def test_exit_code_zero_when_only_resolutions(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", [_vuln_row()])
    b = _write(tmp_path, "b.json", [])
    rc = diff.main([str(a), str(b)])
    assert rc == 0


def test_exit_code_zero_when_new_below_severity_threshold(
    tmp_path: Path,
) -> None:
    a = _write(tmp_path, "a.json", [])
    b = _write(tmp_path, "b.json", [_vuln_row(severity="medium")])
    rc = diff.main([str(a), str(b), "--fail-on-severity", "high"])
    assert rc == 0


def test_exit_code_two_for_missing_file(tmp_path: Path) -> None:
    rc = diff.main([str(tmp_path / "nope.json"),
                    str(tmp_path / "also-nope.json")])
    assert rc == 2


def test_exit_code_two_for_corrupt_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    good = _write(tmp_path, "ok.json", [])
    assert diff.main([str(bad), str(good)]) == 2


def test_exit_code_two_for_non_list_top_level(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"results": []}), encoding="utf-8")
    good = _write(tmp_path, "ok.json", [])
    assert diff.main([str(bad), str(good)]) == 2


def test_no_changes_renders_explanatory_message(
    tmp_path: Path, capsys,
) -> None:
    """When A and B are identical, the report should explain the
    state — either "No changes." (truly empty) or a persistent-
    backlog message that distinguishes "no findings at all" from
    "same backlog as last week" (the original report ambiguity
    that motivated the persistent bucket)."""
    # Truly-empty case: both sides empty.
    a = _write(tmp_path, "a.json", [])
    b = _write(tmp_path, "b.json", [])
    diff.main([str(a), str(b)])
    out = capsys.readouterr().out
    assert "No changes." in out

    # Steady-state case: one finding present in both, no churn.
    rows = [_vuln_row()]
    a2 = _write(tmp_path, "a2.json", rows)
    b2 = _write(tmp_path, "b2.json", rows)
    diff.main([str(a2), str(b2)])
    out = capsys.readouterr().out
    assert "persistent backlog of 1 unchanged" in out
    assert "Persistent: **1**" in out


# ---------------------------------------------------------------------------
# Persistent bucket
# ---------------------------------------------------------------------------

def test_persistent_bucket_carries_unchanged_findings() -> None:
    """Findings present in both A and B with no suppression-state
    change populate the ``persistent`` bucket — replaces the
    pre-fix silent drop. Pre-fix bug: empty new/resolved sections
    were ambiguous between "no findings at all" and "stable
    backlog"."""
    row = _vuln_row(advisory_id="GHSA-stable")
    d = diff.compute_delta([row], [row])
    assert len(d.persistent) == 1
    assert d.persistent[0]["sca"]["advisory"]["id"] == "GHSA-stable"
    assert d.new == []
    assert d.resolved == []


def test_persistent_excludes_suppression_state_changes() -> None:
    """A finding whose suppression bit flipped goes to
    ``suppression_added`` / ``suppression_lifted`` — it is NOT
    persistent (the operator's relationship to it changed)."""
    base = _vuln_row(advisory_id="GHSA-flip", suppressed=False)
    after = _vuln_row(advisory_id="GHSA-flip", suppressed=True,
                       reason="accepted-risk")
    d = diff.compute_delta([base], [after])
    assert len(d.persistent) == 0
    assert len(d.suppression_added) == 1


def test_persistent_excludes_suppressed_on_both_sides_by_default() -> None:
    """Findings suppressed on both sides are the operator's accepted-
    risk pile; surfacing them as "persistent" double-counts the
    backlog. ``include_suppressed=True`` opts them in for the
    audit case."""
    row_sup = _vuln_row(advisory_id="GHSA-sup", suppressed=True,
                         reason="accepted")
    d_default = diff.compute_delta([row_sup], [row_sup])
    assert len(d_default.persistent) == 0
    d_audit = diff.compute_delta([row_sup], [row_sup],
                                  include_suppressed=True)
    assert len(d_audit.persistent) == 1


def test_license_findings_carry_canonical_key() -> None:
    """Pre-fix license rows had no canonical key — invisibly
    dropped from every diff bucket. A new policy violation in a
    PR didn't surface; a steady-state license backlog wasn't
    counted in ``persistent``."""
    row = {
        "id": "sca:license_unknown:PyPI:gpl-pkg@1.0:/r/req.txt",
        "finding_id": "sca:license_unknown:PyPI:gpl-pkg@1.0:/r/req.txt",
        "vuln_type": "sca:license:denied",
        "severity": "high",
        "suppressed": False,
        "sca": {"ecosystem": "PyPI", "name": "gpl-pkg",
                 "version": "1.0", "kind": "license_denied"},
    }
    d = diff.compute_delta([row], [row])
    # Both sides carry the same license row → persistent bucket
    # (not silently dropped, which was the pre-fix behaviour).
    assert len(d.persistent) == 1


def test_persistent_severity_breakdown_in_summary() -> None:
    """Markdown report's persistent line carries the severity
    breakdown so operators reading CI logs see whether the backlog
    is critical-heavy or low-only without opening the full table."""
    rows = [
        _vuln_row(advisory_id="A", severity="critical"),
        _vuln_row(advisory_id="B", severity="critical"),
        _vuln_row(advisory_id="C", severity="medium"),
    ]
    d = diff.compute_delta(rows, rows)
    md = diff._render_markdown("a.json", "b.json", d)
    assert "Persistent: **3**" in md
    assert "2 critical" in md
    assert "1 medium" in md


def test_persistent_full_table_only_with_show_persistent_flag(
    tmp_path: Path, capsys,
) -> None:
    """Default markdown render shows the count + breakdown but
    NOT the per-row table — defeats the point of ``--baseline``
    quiet-mode if every steady-state run dumps the full backlog
    into CI logs."""
    rows = [_vuln_row(advisory_id="A"),
            _vuln_row(advisory_id="B")]
    a = _write(tmp_path, "a.json", rows)
    b = _write(tmp_path, "b.json", rows)
    diff.main([str(a), str(b)])
    out = capsys.readouterr().out
    assert "Persistent: **2**" in out
    # Without --show-persistent there's no full-table heading.
    assert "## Persistent backlog" not in out

    diff.main([str(a), str(b), "--show-persistent"])
    out = capsys.readouterr().out
    assert "## Persistent backlog" in out
    # Both rows should appear in the table — the row label is
    # ``<eco>:<name>@<version> <advisory_id>``.
    assert "npm:lodash@4.17.4 A" in out
    assert "npm:lodash@4.17.4 B" in out


def test_persistent_in_json_output_with_summary_breakdown(
    tmp_path: Path, capsys,
) -> None:
    """JSON consumers (dashboards / trend lines) need both the
    full row list AND the summary breakdown counts."""
    rows = [_vuln_row(advisory_id="A", severity="high"),
            _vuln_row(advisory_id="B", severity="low")]
    a = _write(tmp_path, "a.json", rows)
    b = _write(tmp_path, "b.json", rows)
    diff.main([str(a), str(b), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "persistent" in payload
    assert len(payload["persistent"]) == 2
    assert payload["summary"]["persistent"] == 2
    assert payload["summary"]["persistent_by_severity"] == {
        "high": 1, "low": 1,
    }


# ---------------------------------------------------------------------------
# PR-comment renderer
# ---------------------------------------------------------------------------

def test_pr_comment_kev_finding_lifted_to_blocker_verdict() -> None:
    """A new KEV-listed finding is the most operator-actionable
    signal we have: surface it as a leading 🛑 verdict so PR
    reviewers don't have to scroll into the table to see it."""
    rows_a: List[Dict[str, Any]] = []
    rows_b = [_vuln_row(advisory_id="GHSA-kev",
                         severity="high",   # not even critical
                         in_kev=True)]
    d = diff.compute_delta(rows_a, rows_b)
    text = diff.render_pr_comment(d)
    assert "🛑" in text
    assert "KEV-listed" in text
    # And the per-row table is still present for context.
    assert "GHSA-kev" in text


def test_pr_comment_critical_without_kev_still_blocker() -> None:
    """No KEV but a new critical → 🛑 (blocker tier, distinct from
    high/medium which are warn/info)."""
    d = diff.compute_delta(
        [],
        [_vuln_row(advisory_id="GHSA-crit", severity="critical")],
    )
    text = diff.render_pr_comment(d)
    assert "🛑" in text
    assert "critical" in text


def test_pr_comment_high_severity_only_renders_warn_verdict() -> None:
    d = diff.compute_delta(
        [],
        [_vuln_row(advisory_id="GHSA-h", severity="high")],
    )
    text = diff.render_pr_comment(d)
    # Warn tier — distinct symbol from blocker.
    assert "⚠" in text
    assert "🛑" not in text


def test_pr_comment_clean_run_renders_resolved_celebration() -> None:
    """All findings cleared since baseline: don't bury the win in
    a table — say it in the verdict line so reviewers see it."""
    rows_a = [_vuln_row(advisory_id="GHSA-old", severity="high")]
    d = diff.compute_delta(rows_a, [])
    text = diff.render_pr_comment(d)
    assert "✓" in text
    assert "resolved" in text


def test_pr_comment_steady_state_distinguishes_from_truly_clean() -> None:
    """Same persistent ambiguity the markdown renderer fixed: a
    PR with no diff should distinguish "no findings at all" from
    "same backlog as before" so reviewers know what they're
    looking at."""
    row = _vuln_row(advisory_id="GHSA-stable", severity="medium")
    d_steady = diff.compute_delta([row], [row])
    text_steady = diff.render_pr_comment(d_steady)
    assert "no change vs baseline" in text_steady
    assert "1 persistent finding" in text_steady

    d_truly_clean = diff.compute_delta([], [])
    text_clean = diff.render_pr_comment(d_truly_clean)
    assert "no findings" in text_clean


def test_pr_comment_truncates_large_new_findings_table() -> None:
    """GitHub comments cap around ~65k chars; on a PR that
    introduces hundreds of findings (e.g. a major dep upgrade),
    enumerating every row would push the comment over the cap.
    Truncate at 20 by default with a drop-off message."""
    rows_b = [
        _vuln_row(advisory_id=f"GHSA-{i:03d}", severity="medium")
        for i in range(35)
    ]
    d = diff.compute_delta([], rows_b)
    text = diff.render_pr_comment(d)
    assert "Showing top 20 of 35" in text
    # Default truncation count is reflected in the count cell too.
    assert "**35**" in text


def test_pr_comment_repo_label_overrides_default_header() -> None:
    """Operators run multiple raptor-sca jobs against the same
    PR (frontend / backend / docker images). The label keeps the
    comments distinguishable in the PR thread."""
    d = diff.compute_delta([], [_vuln_row(advisory_id="GHSA-x")])
    text = diff.render_pr_comment(
        d, repo_label="raptor-sca · backend · sha=abc123",
    )
    assert "backend" in text
    assert "abc123" in text


def test_pr_comment_persistent_inline_summary_only() -> None:
    """PR comments must NOT enumerate the persistent backlog (the
    full table use case lives in baseline-delta.md). Only the
    severity breakdown line should appear."""
    persistent_rows = [
        _vuln_row(advisory_id=f"GHSA-p-{i}", severity="medium")
        for i in range(50)
    ]
    d = diff.compute_delta(persistent_rows, persistent_rows)
    text = diff.render_pr_comment(d)
    assert "Persistent backlog: 50" in text
    # No detailed table for persistent — would explode the comment.
    assert "GHSA-p-0" not in text


def test_pr_comment_via_main_writes_to_stdout(
    tmp_path: Path, capsys,
) -> None:
    rows_b = [_vuln_row(advisory_id="GHSA-flag", severity="critical")]
    a = _write(tmp_path, "a.json", [])
    b = _write(tmp_path, "b.json", rows_b)
    diff.main([str(a), str(b), "--pr-comment",
                "--repo-label", "myrepo · pr#42"])
    out = capsys.readouterr().out
    assert "myrepo · pr#42" in out
    assert "🛑" in out
    assert "GHSA-flag" in out
