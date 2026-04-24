"""Tests for run-diff computation."""

from __future__ import annotations

from packages.studio.services.diff_reader import compute_diff


def _mk(file, line, vtype, **kw):
    base = {"file": file, "line": line, "vuln_type": vtype}
    base.update(kw)
    return base


def test_diff_empty_runs():
    d = compute_diff("a", [], "b", [])
    assert d.counts == {"resolved": 0, "carried": 0, "new": 0}


def test_diff_identifies_new_findings():
    a = [_mk("src/a.py", 10, "command_injection")]
    b = [_mk("src/a.py", 10, "command_injection"),
         _mk("src/b.py", 22, "sql_injection")]
    d = compute_diff("run1", a, "run2", b)
    assert d.counts == {"resolved": 0, "carried": 1, "new": 1}
    assert d.new[0]["file"] == "src/b.py"


def test_diff_identifies_resolved_findings():
    a = [_mk("src/a.py", 10, "command_injection"),
         _mk("src/b.py", 22, "sql_injection")]
    b = [_mk("src/a.py", 10, "command_injection")]
    d = compute_diff("run1", a, "run2", b)
    assert d.counts == {"resolved": 1, "carried": 1, "new": 0}
    assert d.resolved[0]["file"] == "src/b.py"


def test_diff_normalizes_vuln_type_for_identity():
    # 'Command Injection' vs 'command_injection' — should match.
    a = [_mk("src/a.py", 10, "Command Injection")]
    b = [_mk("src/a.py", 10, "command_injection")]
    d = compute_diff("run1", a, "run2", b)
    assert d.counts == {"resolved": 0, "carried": 1, "new": 0}


def test_diff_carried_tracks_status_changes():
    a = [_mk("src/a.py", 10, "xss", final_status="pending")]
    b = [_mk("src/a.py", 10, "xss", final_status="exploitable")]
    d = compute_diff("run1", a, "run2", b)
    assert len(d.carried) == 1
    c = d.carried[0]
    assert c.status_a == "pending"
    assert c.status_b == "exploitable"
    assert c.status_changed is True


def test_diff_carried_tracks_verdict_changes():
    a = [_mk("src/a.py", 10, "buffer_overflow",
             feasibility={"verdict": "unknown"})]
    b = [_mk("src/a.py", 10, "buffer_overflow",
             feasibility={"verdict": "difficult"})]
    d = compute_diff("run1", a, "run2", b)
    c = d.carried[0]
    assert c.verdict_a == "unknown"
    assert c.verdict_b == "difficult"
    assert c.verdict_changed is True


def test_diff_deduplicates_within_a_run():
    a = [_mk("x.py", 1, "t"), _mk("x.py", 1, "t")]
    b = []
    d = compute_diff("run1", a, "run2", b)
    # Dup within A collapses; resolved count is 1, not 2.
    assert d.counts["resolved"] == 1


def test_diff_with_none_line_values():
    # Some SARIF findings have no line number; identity still works.
    a = [_mk("x.py", None, "secret")]
    b = [_mk("x.py", None, "secret")]
    d = compute_diff("run1", a, "run2", b)
    assert d.counts == {"resolved": 0, "carried": 1, "new": 0}


def test_diff_sorts_results_deterministically():
    a = [_mk("z.py", 1, "t"), _mk("a.py", 1, "t")]
    b = []
    d = compute_diff("r1", a, "r2", b)
    assert [f["file"] for f in d.resolved] == ["a.py", "z.py"]
