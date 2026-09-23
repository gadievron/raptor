"""Smoke tests for libexec/raptor-coverage-summary --store wiring.

Drives the CLI as a subprocess; the store view logic itself is unit-tested
in test_store_summary.py. Here we only confirm the wiring + trust marker.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# parents[3] = core/coverage/tests -> core/coverage -> core -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-coverage-summary"


def _run(*args, marker=True):
    env = dict(os.environ)
    if marker:
        env["_RAPTOR_TRUSTED"] = "1"
    else:
        env.pop("_RAPTOR_TRUSTED", None)
        env.pop("CLAUDECODE", None)
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env, capture_output=True, text=True,
    )


def _run_dir(tmp_path):
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps({"files": [
        {"path": "a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]}]}))
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    return d


def test_store_view_renders(tmp_path):
    r = _run(str(_run_dir(tmp_path)), "--store")
    assert r.returncode == 0, r.stderr
    assert "Coverage (persistent store)" in r.stdout
    # Both functions are semgrep(static)-covered, neither LLM -> LLM gap of 2.
    assert "no LLM review:  2" in r.stdout
    assert "a.c:f1" in r.stdout


def test_store_refuses_without_trust_marker(tmp_path):
    r = _run(str(_run_dir(tmp_path)), "--store", marker=False)
    assert r.returncode == 2
    assert "internal dispatch" in r.stderr


def test_import_gcov_persists_and_shows_runtime(tmp_path):
    # Fixture-based (no gcc needed): a .gcov whose executed lines fall in f1's
    # range. --import should parse, mark the durable store, and persist.
    run = _run_dir(tmp_path)
    gdir = tmp_path / "gcov"
    gdir.mkdir()
    (gdir / "a.c.gcov").write_text(
        "        -:    0:Source:a.c\n"
        "        9:    5:int f1(void){\n"
        "    #####:   25:  dead();\n")
    imp = _run(str(run), "--import", str(gdir))
    assert imp.returncode == 0, imp.stderr
    assert "Imported" in imp.stdout
    assert (run / "coverage.json").exists()            # persisted
    # The default report now shows runtime coverage non-zero.
    rep = _run(str(run))
    assert rep.returncode == 0, rep.stderr
    assert "runtime" in rep.stdout
    assert "runtime      0 (0.0%)" not in rep.stdout


def test_help_flag_prints_usage(tmp_path):
    # Pre-fix --help was silently ignored and the summary ran instead.
    res = _run("--help")
    assert res.returncode == 0
    assert "Usage:" in res.stdout
    assert "--mark" in res.stdout


def test_run_listing_shows_target_path(tmp_path):
    # The acquisition stamp's "source" is the acquisition KIND
    # ("directory"), not a target; the listing must show the real path.
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text(json.dumps({
        "command": "scan", "status": "completed",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "target_path": "/repos/myproj",
        "manifest": {"target": {"source": "directory"}},
    }))
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    res = _run(str(d))
    assert "target: /repos/myproj" in res.stdout
    assert "target: directory" not in res.stdout


def _project_fixture(tmp_path):
    """Project dir + run dir + target source so mark journaling engages."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text(
        "int f1(void) {\n  return 1;\n}\n" + "\n" * 10)
    proj = tmp_path / "proj"
    run = proj / "audit-1"
    run.mkdir(parents=True)
    (run / ".raptor-run.json").write_text("{}")
    (proj / "checklist.json").write_text(json.dumps({
        "target_path": str(target),
        "files": [{"path": "a.c", "lines": 13, "items": [
            {"name": "f1", "line_start": 1, "line_end": 3},
        ]}],
    }))
    return proj, run


def test_mark_journals_to_project_index(tmp_path):
    proj, run = _project_fixture(tmp_path)
    res = _run(str(run), "--mark", "a.c:f1")
    assert "journaled to project index" in res.stdout, res.stderr
    index = json.loads((proj / "review-journal-index.json").read_text())
    rows = list(index["entries"].values())
    assert len(rows) == 1
    row = rows[0]
    assert (row["file"], row["function"]) == ("a.c", "f1")
    assert row["producer"] == "mark"
    # Subprocess test runner has no TTY: the invocation-context stamp
    # records the agent tier, never a hardcoded "operator".
    assert row["model"] == "agent-mark"
    assert row["verdict"] == "clean"
    assert row["source_hash"]        # target resolvable → hash-aware


def test_unmark_neutralises_journaled_mark(tmp_path):
    proj, run = _project_fixture(tmp_path)
    _run(str(run), "--mark", "a.c:f1")
    _run(str(run), "--unmark", "a.c:f1")
    index = json.loads((proj / "review-journal-index.json").read_text())
    rows = list(index["entries"].values())
    assert len(rows) == 1              # same key — latest-wins replaced it
    assert rows[0]["verdict"] == "error"


def test_mark_skips_unmatched_and_reports_count(tmp_path):
    # A mark naming a (file, item) pair absent from the inventory must not
    # record phantom review credit — and must be reported, not silently
    # counted as marked.
    run = _run_dir(tmp_path)
    res = _run(str(run), "--mark", "a.c:f1", "a.c:ghost")
    assert res.returncode == 0, res.stderr
    assert "Marked 1 item as reviewed (1 unmatched)" in res.stdout
    assert "a.c:ghost" in res.stderr
    rec = json.loads((run / "coverage-llm.json").read_text())
    assert rec["functions_analysed"] == [{"file": "a.c", "function": "f1"}]


def test_mark_file_skips_unmatched_and_reports_count(tmp_path):
    run = _run_dir(tmp_path)
    marks = tmp_path / "marks.json"
    marks.write_text(json.dumps([
        {"file": "a.c", "item": "f1"},
        {"file": "a.c", "item": "f2"},
        {"file": "a.c", "item": "no_such_item"},
        {"file": "missing.c", "item": "f1"},
    ]))
    res = _run(str(run), "--mark-file", str(marks))
    assert res.returncode == 0, res.stderr
    assert "Marked 2 items as reviewed (2 unmatched)" in res.stdout
    assert "a.c:no_such_item" in res.stderr
    assert "missing.c:f1" in res.stderr
    rec = json.loads((run / "coverage-llm.json").read_text())
    assert {(fa["file"], fa["function"]) for fa in rec["functions_analysed"]} \
        == {("a.c", "f1"), ("a.c", "f2")}


def test_mark_accepts_tool_spelled_paths(tmp_path):
    # The store importer resolves functions_analysed paths via
    # _to_inventory_path (exact / ./ strip / basename / suffix match) —
    # absolute and ./-prefixed spellings must earn credit here too, and
    # must be stored under the inventory key so the fold joins.
    run = _run_dir(tmp_path)
    res = _run(str(run), "--mark", "/some/build/root/a.c:f1", "./a.c:f2")
    assert res.returncode == 0, res.stderr
    assert "Marked 2 items as reviewed in" in res.stdout
    assert "unmatched" not in res.stdout
    rec = json.loads((run / "coverage-llm.json").read_text())
    assert {(fa["file"], fa["function"]) for fa in rec["functions_analysed"]} \
        == {("a.c", "f1"), ("a.c", "f2")}


def test_mark_with_zero_key_inventory_stays_unvalidated(tmp_path):
    # A checklist that yields no (file, item) keys gives the gate nothing
    # to validate against — marks must be accepted, not all refused.
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps(
        {"files": [{"path": "a.c", "lines": 100, "items": []}]}))
    res = _run(str(d), "--mark", "a.c:f1")
    assert res.returncode == 0, res.stderr
    assert "Marked 1 item as reviewed" in res.stdout
    assert "unmatched" not in res.stdout
    rec = json.loads((d / "coverage-llm.json").read_text())
    assert rec["functions_analysed"] == [{"file": "a.c", "function": "f1"}]


def test_mark_items_key_supersedes_legacy_functions(tmp_path):
    # The store fold ignores legacy `functions` whenever the `items` key
    # is present (even empty) — the gate must refuse exactly what the
    # fold would never credit.
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps({"files": [
        {"path": "a.c", "lines": 100, "items": [],
         "functions": [{"name": "legacy_f", "line_start": 1, "line_end": 5}]},
        {"path": "b.c", "lines": 100, "items": [
            {"name": "g1", "line_start": 1, "line_end": 5}]},
    ]}))
    res = _run(str(d), "--mark", "b.c:g1", "a.c:legacy_f")
    assert res.returncode == 0, res.stderr
    assert "Marked 1 item as reviewed (1 unmatched)" in res.stdout
    assert "a.c:legacy_f" in res.stderr
    rec = json.loads((d / "coverage-llm.json").read_text())
    assert rec["functions_analysed"] == [{"file": "b.c", "function": "g1"}]


def test_mark_without_project_context_stays_record_only(tmp_path):
    d = tmp_path / "standalone-run"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    res = _run(str(d), "--mark", "a.c:f1")
    assert "journaled" not in res.stdout
    assert not (tmp_path / "review-journal-index.json").exists()
    rec = json.loads((d / "coverage-llm.json").read_text())
    assert rec["functions_analysed"] == [{"file": "a.c", "function": "f1"}]


def test_journaled_mark_suppresses_audit_gap(tmp_path):
    # The full loop: --mark → journal index → compute_gaps fold.
    proj, run = _project_fixture(tmp_path)
    _run(str(run), "--mark", "a.c:f1")

    from core.audit.gaps import compute_gaps
    checklist = json.loads((proj / "checklist.json").read_text())
    fresh_run = proj / "audit-2"
    fresh_run.mkdir()
    gaps = compute_gaps(
        checklist, [], out_dir=fresh_run, project_dir=proj,
    )
    assert "f1" not in {g["name"] for g in gaps}
    # And the withdrawal restores the gap.
    _run(str(run), "--unmark", "a.c:f1")
    gaps = compute_gaps(
        checklist, [], out_dir=fresh_run, project_dir=proj,
    )
    assert "f1" in {g["name"] for g in gaps}


class TestBoundedReads:
    def test_every_load_json_is_capped(self):
        """Run-dir/operator JSON reads must carry the shared 64MB
        artifact ceiling — the sibling raptor-review caps the same
        files, calling an unbounded read "an OOM lever"."""
        import re
        src = CLI.read_text(encoding="utf-8")
        for m in re.finditer(r"load_json\(([^;]*?)\)\s", src):
            call = m.group(1)
            assert "max_bytes" in call, (
                f"uncapped load_json call: load_json({call})"
            )


def test_gaps_output_scrubs_hostile_target_names(tmp_path):
    # File/function names come from the SCANNED target's checklist --
    # a hostile repo controls those bytes; the gaps listing prints
    # straight to the operator's terminal and must escape ESC/BEL.
    d = tmp_path / "scan-evil"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    evil_file = "evil\x1b]0;pwn\x07.c"
    (d / "checklist.json").write_text(json.dumps({"files": [
        {"path": evil_file, "lines": 100, "items": [
            {"name": "f\x1b[2J1", "line_start": 0, "line_end": 20},
        ]}]}))
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": [evil_file],
         "timestamp": "t"}))
    r = _run(str(d), "--gaps")
    assert r.returncode == 0, r.stderr
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "pwn" in r.stdout  # content survives, escaped

    r2 = _run(str(d), "--store")
    assert r2.returncode == 0, r2.stderr
    assert "\x1b" not in r2.stdout and "\x07" not in r2.stdout
