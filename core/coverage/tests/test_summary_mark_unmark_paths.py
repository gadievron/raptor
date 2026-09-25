"""Mark/unmark path handling in libexec/raptor-coverage-summary.

Drives the CLI as a subprocess (same pattern as test_summary_cli.py):
path-spelling normalisation symmetry between --mark and --unmark,
structured --mark-file entries with ':' in item names, dangling
value-taking flags, and items/functions precedence in journaled marks.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.coverage.tests.summary_cli_support import CLI, run_cli

_run = run_cli


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
        r = _run(str(run), "--mark", "src/auth.c:check_pw",
                 "src/util.c:helper", operator=True)
        assert r.returncode == 0, r.stderr
        assert "Marked 2 items" in r.stdout
        assert set(_llm_functions(run)) == {
            ("src/auth.c", "check_pw"), ("src/util.c", "helper")}

        # Unmark with a different-but-equivalent spelling (./-prefixed).
        r = _run(str(run), "--unmark", "./src/auth.c:check_pw",
                 operator=True)
        assert r.returncode == 0, r.stderr
        assert "Removed 1 item" in r.stdout
        # The unrelated entry is untouched.
        assert _llm_functions(run) == [("src/util.c", "helper")]

    def test_unmark_withdraws_journaled_mark(self, tmp_path):
        proj, run = _project(tmp_path)
        r = _run(str(run), "--mark", "./src/auth.c:check_pw",
                 operator=True)
        assert r.returncode == 0, r.stderr
        assert "journaled to project index" in r.stdout
        rows = [r_ for r_ in _index_rows(proj)
                if r_.get("file") == "src/auth.c"
                and r_.get("function") == "check_pw"]
        assert rows and all(r_.get("verdict") == "clean" for r_ in rows)

        r = _run(str(run), "--unmark", "src/auth.c:check_pw",
                 operator=True)
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
        r = _run(str(run), "--mark-file", str(mark_file), operator=True)
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
        r = _run(str(run), "--mark", "src/x.c:g", operator=True)
        assert r.returncode == 0, r.stderr
        assert "Marked 1 item" in r.stdout
        entries = [json.loads(line) for line in
                   (run / "review-journal.jsonl").read_text().splitlines()
                   if line.strip()]
        rows = [e for e in entries if e.get("function") == "g"]
        # The legacy `functions` range (line_start 5) is never credited.
        assert rows and rows[0].get("line_start") == 0


class TestMarkUnmarkLocking:
    """mark/unmark are read-modify-write cycles over the same record a
    live run's completion snapshot mutates — they must run under the
    cross-process coverage lock (the import path already does). The
    lock helper creates a sibling .lock file; its presence after a
    mark is the observable witness that the lock engaged."""

    def test_mark_takes_the_record_lock(self, tmp_path: Path):
        _proj, run = _project(tmp_path)
        res = _run(str(run), "--mark", "src/auth.c:check_pw",
                   operator=True)
        assert res.returncode == 0, res.stderr
        assert (run / "coverage-llm.json.lock").exists(), (
            "mark ran without the cross-process record lock"
        )

    def test_unmark_takes_the_record_lock(self, tmp_path: Path):
        _proj, run = _project(tmp_path)
        res = _run(str(run), "--mark", "src/auth.c:check_pw",
                   operator=True)
        assert res.returncode == 0, res.stderr
        (run / "coverage-llm.json.lock").unlink()
        res = _run(str(run), "--unmark", "src/auth.c:check_pw")
        assert res.returncode == 0, res.stderr
        assert (run / "coverage-llm.json.lock").exists()


class TestMarkRowProvenance:
    """Journal rows stamp who actually minted the assertion.

    model="operator" was hardcoded regardless of caller — an agent's
    --mark was indistinguishable from an operator's in the durable
    project index. The stamp now follows the /annotate rule: operator
    only under an interactive TTY, else "agent-mark".
    """

    def _load_module(self):
        import importlib.util
        from importlib.machinery import SourceFileLoader
        os.environ.setdefault("_RAPTOR_TRUSTED", "1")
        loader = SourceFileLoader(
            "raptor_coverage_summary_prov", str(CLI))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_non_tty_mark_demotes_to_map_grade(self, tmp_path):
        # A non-operator context cannot journal a review assertion at
        # all: the CLI demotes the mark to map-grade (understand
        # record) with a notice — no journal row, no llm record.
        proj, run = _project(tmp_path)
        r = _run(str(run), "--mark", "src/auth.c:check_pw")
        assert r.returncode == 0, r.stderr
        assert "review-grade marks are operator-tier" in r.stdout
        assert "examined (map-grade)" in r.stdout
        assert not (proj / "review-journal-index.json").exists()
        assert not (run / "coverage-llm.json").exists()
        rec = json.loads((run / "coverage-understand.json").read_text())
        assert rec["functions_analysed"] == [
            {"file": "src/auth.c", "function": "check_pw"}]

    def test_non_tty_mark_drops_statuses_with_notice(self, tmp_path):
        proj, run = _project(tmp_path)
        mark_file = run / "marks.json"
        mark_file.write_text(json.dumps([
            {"file": "src/auth.c", "item": "check_pw",
             "status": "suspicious"},
        ]))
        r = _run(str(run), "--mark-file", str(mark_file))
        assert r.returncode == 0, r.stderr
        assert "statuses dropped" in r.stderr
        assert not (proj / "review-journal-index.json").exists()

    def test_non_tty_unmark_journals_agent_mark_withdrawal(self, tmp_path):
        # Unmark stays available to agent contexts (withdrawing credit
        # fails toward re-review) — the neutralising error row stamps
        # the agent tier so the withdrawal's minter is on record.
        proj, run = _project(tmp_path)
        assert _run(str(run), "--mark", "src/auth.c:check_pw",
                    operator=True).returncode == 0
        assert _run(str(run), "--unmark",
                    "src/auth.c:check_pw").returncode == 0
        rows = [row for row in _index_rows(proj)
                if row.get("function") == "check_pw"]
        withdrawals = [row for row in rows
                       if row.get("verdict") == "error"]
        assert withdrawals and all(
            row.get("model") == "agent-mark" for row in withdrawals)

    def test_journaled_mark_records_invocation_context(self, tmp_path):
        # The /annotate guarantee holds for marks: the full context
        # rides the journaled row BODY (an existing MAC-covered
        # field — an additive row field demotes at older readers), so
        # every operator grant is auditable after the fact.
        proj, run = _project(tmp_path)
        r = _run(str(run), "--mark", "src/auth.c:check_pw",
                 operator=True)
        assert r.returncode == 0, r.stderr
        rows = [row for row in _index_rows(proj)
                if row.get("function") == "check_pw"]
        assert rows
        body = rows[0].get("body") or ""
        assert body.startswith("[mark-context] ")
        for fact in ("tty=", "provenance=", "sid=", "envm=", "parents="):
            assert fact in body, fact

    def test_unmark_withdrawal_records_invocation_context(self, tmp_path):
        proj, run = _project(tmp_path)
        assert _run(str(run), "--mark", "src/auth.c:check_pw",
                    operator=True).returncode == 0
        assert _run(str(run), "--unmark",
                    "src/auth.c:check_pw").returncode == 0
        rows = [row for row in _index_rows(proj)
                if row.get("function") == "check_pw"
                and row.get("verdict") == "error"]
        assert rows
        assert (rows[0].get("body") or "").startswith("[mark-context] ")

    _OPERATOR_CTX = {
        "tty": "stdin", "provenance": "interactive-tty",
        "sid": "inherited", "envm": "none", "parents": "bash,sshd",
    }

    def test_interactive_corroborated_context_stamps_operator(
            self, monkeypatch):
        import core.annotations.provenance as prov
        mod = self._load_module()
        monkeypatch.setattr(
            prov, "detect_invocation_context",
            lambda: dict(self._OPERATOR_CTX))
        assert mod._mark_model() == "operator"

    def test_uncorroborated_tty_stamps_agent_mark(self, monkeypatch):
        # The fd stamp alone is pty-forgeable: an interactive claim
        # whose corroborating facts contradict it (agent-session
        # environment marker) demotes — the /annotate layered rule.
        import core.annotations.provenance as prov
        mod = self._load_module()
        laundered = dict(self._OPERATOR_CTX, envm="claudecode,trusted")
        monkeypatch.setattr(
            prov, "detect_invocation_context", lambda: laundered)
        assert mod._mark_model() == "agent-mark"

    def test_non_tty_stamps_agent_mark(self, monkeypatch):
        import core.annotations.provenance as prov
        mod = self._load_module()
        monkeypatch.setattr(
            prov, "detect_invocation_context",
            lambda: {"tty": "none", "provenance": "non-tty"})
        assert mod._mark_model() == "agent-mark"
