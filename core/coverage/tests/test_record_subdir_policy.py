"""Two-direction tests for the subdir record trust policy (the
load_records chokepoint).

Escalation direction: several run-dir subdirs are sandbox write
grants handed to children executing over untrusted input; a child
that plants a review-capable coverage record there (any label — the
label space is unlimited — or the legacy nested ``files{}`` shape)
must earn NOTHING in any consumer of the loader. Probed end-to-end:
store_view / --fail-under / --residual / the audit covered-set fold /
the real CLI.

Refusal direction: every legitimate producer home keeps loading —
top-level records of every grade, scan/ + codeql/ + sca/ scanner
records, autonomous/ review records.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from core.coverage.record import load_records
from core.coverage.store_summary import (
    coverage_view,
    no_lane_residual,
    store_coverage_threshold_met,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-coverage-summary"

_CHECKLIST = {
    "target_path": "/x/target",
    "files": [
        {"path": "src/a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20,
             "kind": "function"},
            {"name": "f2", "line_start": 30, "line_end": 60,
             "kind": "function"},
        ]},
    ],
}

_ALL_ROWS = [{"file": "src/a.c", "function": "f1"},
             {"file": "src/a.c", "function": "f2"}]

# Review-capable labels a child could forge (llm/analysed under the
# registry) — the escalation lever the chokepoint must refuse.
_REVIEW_LABELS = ("llm", "validate", "audit", "journal", "mark",
                  "claude", "agentic", "annotations")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run1"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".raptor-run.json").write_text("{}")
    _write(d / "checklist.json", _CHECKLIST)
    return d


def _forge(run: Path, subdir: str, tool: str, **extra) -> None:
    _write(run / subdir / f"coverage-{tool}.json", {
        "tool": tool, "timestamp": "t",
        "functions_analysed": list(_ALL_ROWS), **extra,
    })


def _tools(run: Path) -> set:
    return {r.get("tool") for r in load_records(run) if isinstance(r, dict)}


# ----------------------------------------------------- escalation dead


def test_forged_review_records_in_child_subdir_never_load(tmp_path):
    run = _run_dir(tmp_path)
    for tool in _REVIEW_LABELS:
        _forge(run, "openant_scan", tool)
    assert _tools(run) == set()


def test_forged_records_earn_zero_credit_everywhere(tmp_path):
    run = _run_dir(tmp_path)
    for tool in _REVIEW_LABELS:
        _forge(run, "openant_scan", tool)
    view = coverage_view([run], _CHECKLIST, tmp_path / "cov.json", None)
    assert view["functions_reviewed"] == 0
    assert view["gap_no_llm"] == 2
    assert not store_coverage_threshold_met(view, 100.0)
    # --residual stays full: no lane examined anything.
    assert len(no_lane_residual(view)) == 2

    from core.audit.gaps import _build_covered_set
    from core.audit.loaders import load_coverage_records
    assert _build_covered_set(load_coverage_records(run)) == set()


def test_forged_legacy_files_shape_refused_from_scanner_subdirs(tmp_path):
    # The legacy nested files{} shape earns audit covered keys for ANY
    # non-runtime category — review-capable by shape, so even a
    # scanner-labelled record carrying it is refused from scanner
    # subdirs (no legit producer writes that shape there).
    run = _run_dir(tmp_path)
    _forge(run, "scan", "semgrep",
           files={"src/a.c": {"functions": {"f1": {}, "f2": {}}}})
    assert _tools(run) == set()

    from core.audit.gaps import _build_covered_set
    from core.audit.loaders import load_coverage_records
    assert _build_covered_set(load_coverage_records(run)) == set()


def test_review_label_refused_from_scanner_subdirs(tmp_path):
    run = _run_dir(tmp_path)
    _forge(run, "scan", "llm")
    _forge(run, "codeql", "journal")
    _forge(run, "sca", "audit")
    assert _tools(run) == set()


def test_scanner_grade_record_refused_from_unknown_subdir(tmp_path):
    # Unknown subdirs are refused outright (fail-closed) — even
    # scanner-grade labels: a new producer home gets allowlisted
    # deliberately, never granted by a child picking a fresh dir name.
    run = _run_dir(tmp_path)
    _forge(run, "openant_scan", "semgrep")
    _forge(run, "somedir", "openant")
    assert _tools(run) == set()


# --------------------------------------------- refusal is read-free


def test_untrusted_subdir_refusal_never_reads_the_file(tmp_path,
                                                       monkeypatch):
    # The PATH tier decides from p.parent.name alone: plants in an
    # untrusted subdir must never be opened/parsed — reading first
    # handed a hostile child a full-budget read per plant on EVERY
    # render (near-budget sparse files made that a parent stall).
    import core.coverage.record as record_mod

    run = _run_dir(tmp_path)
    (run / "openant_scan").mkdir()
    for i in range(4):
        # Sparse at the read budget — a read here is also SLOW, but
        # the assertion is the deterministic call count, not wall time.
        with open(run / "openant_scan" / f"coverage-forge{i}.json",
                  "wb") as f:
            f.truncate(record_mod.RUN_ARTIFACT_MAX_BYTES)
    _write(run / "coverage-openant.json", {"tool": "openant"})
    _write(run / "scan" / "coverage-semgrep.json", {"tool": "semgrep"})

    read_paths: list[str] = []
    real_load = record_mod.load_json

    def counting_load(path, *a, **kw):
        read_paths.append(Path(path).name)
        return real_load(path, *a, **kw)

    monkeypatch.setattr(record_mod, "load_json", counting_load)
    assert _tools(run) == {"openant", "semgrep"}
    assert not any(p.startswith("coverage-forge") for p in read_paths)


def test_nested_read_budget_refuses_and_continues(tmp_path, monkeypatch):
    # Trusted scanner homes must be READ to shape-check, so that class
    # pays a cumulative budget — and a later small legit record still
    # loads after a near-budget plant is refused (refuse-and-continue).
    import core.coverage.record as record_mod

    run = _run_dir(tmp_path)
    big = run / "scan" / "coverage-abig.json"
    _write(big, {"tool": "bigpad", "pad": "x" * 4000})
    _write(run / "scan" / "coverage-semgrep.json",
           {"tool": "semgrep", "files_examined": []})
    monkeypatch.setattr(record_mod, "_NESTED_READ_MAX_BYTES", 500)
    assert _tools(run) == {"semgrep"}


def test_nested_candidate_cap_bounds_the_read_class(tmp_path,
                                                    monkeypatch):
    import core.coverage.record as record_mod

    run = _run_dir(tmp_path)
    for i in range(6):
        _write(run / "scan" / f"coverage-t{i}.json", {"tool": f"t{i}"})
    monkeypatch.setattr(record_mod, "_NESTED_CANDIDATE_CAP", 2)
    assert len(_tools(run)) == 2


# ------------------------------------------- child-grant subdir names


def test_child_grant_subdirs_are_untrusted(tmp_path):
    # The hostile-input children's write grants are dedicated subdirs
    # (openant_scan/, the web scanner's ffuf/, the semgrep child's
    # semgrep-child/) — none is a trusted record home, so a record
    # planted in any of them refuses at the PATH tier.
    run = _run_dir(tmp_path)
    for sub in ("openant_scan", "ffuf", "semgrep-child"):
        _forge(run, sub, "llm")
        _forge(run, sub, "semgrep")
    assert _tools(run) == set()


# -------------------------------------- the autonomous/ structural tie


def test_cc_dispatch_tools_exclude_write_capable_tools():
    # autonomous/ is a trusted review-record home at this module's
    # load chokepoint, and the llm_analysis agent's per-finding
    # `claude -p` sub-agent receives autonomous/ as its OS-level
    # write grant — the ACTUAL guard is that child's CLI tool
    # allowlist. This tie pins it: widening the allowlist with any
    # write-capable tool means a hostile-repo-steered sub-agent can
    # mint review-grade coverage records in a trusted home, so the
    # _REVIEW_RECORD_SUBDIRS entry must move behind the refusal
    # FIRST.
    import re

    src = (REPO_ROOT / "packages" / "llm_analysis"
           / "cc_dispatch.py").read_text(encoding="utf-8")
    matches = re.findall(r'tools\s*=\s*"([^"]*)"', src)
    assert matches, "cc_dispatch tool allowlist not found"
    for spec in matches:
        granted = {t.strip() for t in spec.split(",") if t.strip()}
        assert granted <= {"Read", "Grep", "Glob"}, (
            f"cc_dispatch grants {sorted(granted)} — write-capable "
            "tools would let the sub-agent mint coverage records in "
            "autonomous/, a trusted review-record home "
            "(core/coverage/record.py _REVIEW_RECORD_SUBDIRS)")


# ------------------------------------- audit fold container hardening


def test_covered_set_tolerates_hostile_container_shapes():
    # A LIST ``files`` passed the old null screen and crashed the
    # audit fold on .items() — a child-plantable record became a
    # /audit + --gap-audit DoS. Every container level degrades.
    from core.audit.gaps import _build_covered_set

    hostile = [
        {"tool": "semgrep", "files": ["src/a.c", 7]},
        {"tool": "semgrep", "files": {"src/a.c": ["f1"]}},
        {"tool": "semgrep", "files": {"src/a.c": {"functions": ["f1"]}}},
        {"tool": "semgrep", "files": {"src/a.c": {"functions": "f1"}}},
        {"tool": "semgrep", "files": "src/a.c"},
    ]
    assert _build_covered_set(hostile) == set()
    # Control: the genuine legacy shape still earns its covered key.
    legacy = [{"tool": "semgrep",
               "files": {"src/a.c": {"functions": {"f1": {}}}}}]
    assert len(_build_covered_set(legacy)) == 1


# ------------------------------------------------------ legit unchanged


def test_legitimate_producer_homes_still_load(tmp_path):
    run = _run_dir(tmp_path)
    # Top level: every grade.
    _write(run / "coverage-llm.json",
           {"tool": "llm", "functions_analysed": list(_ALL_ROWS)})
    _write(run / "coverage-openant.json",
           {"tool": "openant", "functions_analysed": []})
    # Scanner homes: scanner-grade records.
    _write(run / "scan" / "coverage-semgrep.json",
           {"tool": "semgrep", "files_examined": ["src/a.c"]})
    _write(run / "codeql" / "coverage-codeql.json",
           {"tool": "codeql", "files_examined": ["src/a.c"]})
    _write(run / "sca" / "coverage-sca.json",
           {"tool": "sca", "files_examined": []})
    # Review home: the llm_analysis agent's journal-derived record.
    _write(run / "autonomous" / "coverage-journal.json",
           {"tool": "journal", "functions_analysed": list(_ALL_ROWS)})
    assert _tools(run) == {
        "llm", "openant", "semgrep", "codeql", "sca", "journal"}


def test_top_level_wins_dedup_over_subdir_unchanged(tmp_path):
    run = _run_dir(tmp_path)
    _write(run / "coverage-semgrep.json",
           {"tool": "semgrep", "files_examined": ["top"]})
    _write(run / "scan" / "coverage-semgrep.json",
           {"tool": "semgrep", "files_examined": ["nested"]})
    recs = [r for r in load_records(run) if isinstance(r, dict)]
    assert [r["files_examined"] for r in recs
            if r["tool"] == "semgrep"] == [["top"]]


# ------------------------------------------------------- real CLI probe


def test_cli_shows_no_review_credit_for_forged_subdir_records(tmp_path):
    run = _run_dir(tmp_path)
    for tool in ("llm", "journal", "mark"):
        _forge(run, "openant_scan", tool)
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    r = subprocess.run(
        [sys.executable, str(CLI), str(run), "--store"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "no LLM review:  2" in r.stdout
    r2 = subprocess.run(
        [sys.executable, str(CLI), str(run), "--residual"],
        env=env, capture_output=True, text=True,
    )
    assert r2.returncode == 0, r2.stderr
    assert "2 item(s) analysed by NO lane" in r2.stdout
