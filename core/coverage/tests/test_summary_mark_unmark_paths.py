"""Mark/unmark path handling in libexec/raptor-coverage-summary.

Drives the CLI as a subprocess (same pattern as test_summary_cli.py):
path-spelling normalisation symmetry between --mark and --unmark,
structured --mark-file entries with ':' in item names, dangling
value-taking flags, and items/functions precedence in journaled marks.
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


def _run(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env, capture_output=True, text=True, timeout=60,
    )


def _project(tmp_path: Path, files: list[dict] | None = None) -> tuple[Path, Path]:
    """Project dir with a checklist plus one run dir inside it."""
    proj = tmp_path / "proj"
    run = proj / "run1"
    run.mkdir(parents=True)
    (run / ".raptor-run.json").write_text("{}")
    if files is None:
        files = [
            {"path": "src/auth.c", "items": [
                {"name": "check_pw", "line_start": 0, "line_end": 3}]},
            {"path": "src/util.c", "items": [
                {"name": "helper", "line_start": 0, "line_end": 2}]},
            {"path": "src/a.cpp", "items": [
                {"name": "ns::fn", "line_start": 0, "line_end": 2}]},
        ]
    (proj / "checklist.json").write_text(json.dumps(
        {"target_path": "", "files": files}))
    return proj, run


def _llm_functions(run: Path) -> list[tuple[str, str]]:
    record = json.loads((run / "coverage-llm.json").read_text())
    return [(fa.get("file"), fa.get("function"))
            for fa in record.get("functions_analysed", [])]


def _index_rows(proj: Path) -> list[dict]:
    index = json.loads((proj / "review-journal-index.json").read_text())
    return [r for r in (index.get("entries") or {}).values()
            if isinstance(r, dict)]


class TestUnmarkNormalisesSpellings:
    def test_unmark_with_equivalent_spelling_removes_entry(self, tmp_path):
        proj, run = _project(tmp_path)
        # Mark with the canonical inventory spelling plus an unrelated item.
        r = _run(str(run), "--mark", "src/auth.c:check_pw", "src/util.c:helper")
        assert r.returncode == 0, r.stderr
        assert "Marked 2 items" in r.stdout
        assert set(_llm_functions(run)) == {
            ("src/auth.c", "check_pw"), ("src/util.c", "helper")}

        # Unmark with a different-but-equivalent spelling (./-prefixed).
        r = _run(str(run), "--unmark", "./src/auth.c:check_pw")
        assert r.returncode == 0, r.stderr
        assert "Removed 1 item" in r.stdout
        # The unrelated entry is untouched.
        assert _llm_functions(run) == [("src/util.c", "helper")]

    def test_unmark_withdraws_journaled_mark(self, tmp_path):
        proj, run = _project(tmp_path)
        r = _run(str(run), "--mark", "./src/auth.c:check_pw")
        assert r.returncode == 0, r.stderr
        assert "journaled to project index" in r.stdout
        rows = [r_ for r_ in _index_rows(proj)
                if r_.get("file") == "src/auth.c"
                and r_.get("function") == "check_pw"]
        assert rows and all(r_.get("verdict") == "clean" for r_ in rows)

        r = _run(str(run), "--unmark", "src/auth.c:check_pw")
        assert r.returncode == 0, r.stderr
        assert "Removed 1 item" in r.stdout
        rows = [r_ for r_ in _index_rows(proj)
                if r_.get("file") == "src/auth.c"
                and r_.get("function") == "check_pw"]
        # Latest-wins merge replaced the mark row with the error
        # (withdrawal) entry, restoring the function to the gap list.
        assert rows and all(r_.get("verdict") == "error" for r_ in rows)


class TestMarkFileStructuredEntries:
    def test_item_name_with_colons_survives(self, tmp_path):
        proj, run = _project(tmp_path)
        mark_file = tmp_path / "marks.json"
        mark_file.write_text(json.dumps([
            {"file": "src/a.cpp", "item": "ns::fn", "status": "suspicious"},
        ]))
        r = _run(str(run), "--mark-file", str(mark_file))
        assert r.returncode == 0, r.stderr
        assert "Marked 1 item" in r.stdout
        assert "unmatched" not in r.stdout
        # The pair is stored intact, not re-split on the last colon.
        assert _llm_functions(run) == [("src/a.cpp", "ns::fn")]
        rows = [r_ for r_ in _index_rows(proj)
                if r_.get("function") == "ns::fn"]
        assert rows and rows[0].get("file") == "src/a.cpp"
        # The per-entry status keyed on the structured pair still lands.
        assert rows[0].get("verdict") == "suspicious"


class TestDanglingValueFlags:
    def test_dangling_import_errors(self, tmp_path):
        r = _run("--import")
        assert r.returncode == 1
        assert "requires a value" in r.stderr

    def test_dangling_format_errors(self, tmp_path):
        r = _run("--format")
        assert r.returncode == 1
        assert "requires a value" in r.stderr

    def test_dangling_mark_file_errors(self, tmp_path):
        _proj, run = _project(tmp_path)
        r = _run(str(run), "--mark-file")
        assert r.returncode == 1
        assert "requires a value" in r.stderr

    def test_dangling_mark_errors(self, tmp_path):
        _proj, run = _project(tmp_path)
        r = _run(str(run), "--mark")
        assert r.returncode == 1
        assert "requires at least one" in r.stderr

    def test_plain_summary_still_runs(self, tmp_path):
        _proj, run = _project(tmp_path)
        r = _run(str(run))
        assert r.returncode == 0, r.stderr


class TestJournalItemsPrecedence:
    def test_empty_items_supersedes_legacy_functions(self, tmp_path):
        # A present-but-empty `items` list must win over legacy
        # `functions` in the journal's range lookup, matching the gate
        # (_checklist_item_keys) and the store fold.
        _proj, run = _project(tmp_path, files=[
            {"path": "src/x.c", "items": [],
             "functions": [{"name": "g", "line_start": 5, "line_end": 9}]},
        ])
        # No keys anywhere -> the gate accepts the mark as-is.
        r = _run(str(run), "--mark", "src/x.c:g")
        assert r.returncode == 0, r.stderr
        assert "Marked 1 item" in r.stdout
        entries = [json.loads(line) for line in
                   (run / "review-journal.jsonl").read_text().splitlines()
                   if line.strip()]
        rows = [e for e in entries if e.get("function") == "g"]
        # The legacy `functions` range (line_start 5) is never credited.
        assert rows and rows[0].get("line_start") == 0
