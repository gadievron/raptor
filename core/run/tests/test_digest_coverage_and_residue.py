"""Digest honesty for audit runs: run-scope coverage + residue.

The end-of-run digest rendered two dishonest lines for gap-audit /
residual-queue runs:

* ``Coverage: 0.0% of reviewable units`` — the coverage store view is
  built with ``store_path=<run>/coverage.json``, so its project-dir
  derivation lands on the RUN dir (the project journal index is never
  found), and the store is line-interval based, so line-less (binary)
  checklist items can never earn credit. A run that reviewed 4 of its
  6 queued functions rendered 0.0% over the full checklist.
* ``No verified or exploitable-unverified findings.`` — implied
  all-clear while suspicious journal rows and low-confidence graded
  items sat unmentioned in the run artifacts.

These tests pin the honest replacements.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.run.digest import read_run_digest, render_run_digest


def _meta(run: Path, **over: Any) -> None:
    meta: dict[str, Any] = {
        "command": "audit",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "status": "completed",
    }
    meta.update(over)
    (run / ".raptor-run.json").write_text(json.dumps(meta),
                                          encoding="utf-8")


def _append(out_dir: Path, **kw: Any) -> None:
    from core.coverage.journal import ReviewJournalEntry, append_entry
    base: dict[str, Any] = {
        "run_id": "t", "file": "binary:lib.so", "source_hash": "",
    }
    base.update(kw)
    append_entry(out_dir, ReviewJournalEntry(**base))


def _seed_gap_audit_run(run: Path) -> None:
    """6-item residual queue; 4 completed reviews, 2 errored —
    modeled on a live gap-audit run's shapes (line-less binary
    items)."""
    _meta(run)
    (run / "gaps.json").write_text(json.dumps({
        "count": 6,
        "gaps": [
            {"file": "binary:lib.so", "name": f"FUN_{i}"}
            for i in range(6)
        ],
    }))
    verdicts = ["clean", "clean", "suspicious", "suspicious"]
    for i, verdict in enumerate(verdicts):
        _append(run, ts=f"2026-01-01T00:00:0{i}+00:00",
                function=f"FUN_{i}", verdict=verdict)
    for i in (4, 5):
        _append(run, ts=f"2026-01-01T00:00:0{i}+00:00",
                function=f"FUN_{i}", verdict="error",
                error_class="task_exception")


class TestRunScopeCoverage:
    def test_gap_audit_run_reports_run_scope(self, tmp_path: Path) -> None:
        _seed_gap_audit_run(tmp_path)

        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 4
        assert d.coverage_total == 6
        assert d.coverage_percent is not None
        assert abs(d.coverage_percent - 100.0 * 4 / 6) < 0.01

        out = render_run_digest(d)
        assert "4 of 6" in out
        assert "0.0%" not in out

    def test_errored_reviews_do_not_earn_run_coverage(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 2,
            "gaps": [
                {"file": "binary:lib.so", "name": "FUN_0"},
                {"file": "binary:lib.so", "name": "FUN_1"},
            ],
        }))
        for i in (0, 1):
            _append(tmp_path, ts=f"2026-01-01T00:00:0{i}+00:00",
                    function=f"FUN_{i}", verdict="error",
                    error_class="task_exception")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 0
        assert d.coverage_total == 2

    def test_mechanical_echoes_do_not_earn_run_coverage(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 1,
            "gaps": [{"file": "binary:lib.so", "name": "FUN_0"}],
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="suspicious",
                strategies=["post-loop-mechanical"],
                body="[mechanical] sweep rule hit")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 0

    def test_run_without_queue_keeps_prior_behaviour(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path, command="agentic")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope != "run"
        assert d.coverage_percent is None  # store layer absent → absent

    # ── hostile gaps.json shapes ─────────────────────────────────
    # run_scope_coverage's contract is None / fall-back, never
    # raise. gaps.json is a run artifact a hostile target's build
    # tooling can influence; each shape below crashed the accessor
    # on direct call before the guard (str count reached the legacy
    # subtraction raw; truthy non-list / mixed rows reached the
    # per-row ``.get``).

    def test_str_count_without_gap_list_falls_back_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({"count": "6"}))
        for i in range(2):
            _append(tmp_path, ts=f"2026-01-01T00:00:0{i}+00:00",
                    function=f"FUN_{i}", verdict="clean")
        assert run_scope_coverage(tmp_path) == (2, 6)

    def test_str_gaps_field_falls_back_to_count_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 3, "gaps": "corrupted-by-truncation",
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="clean")
        assert run_scope_coverage(tmp_path) == (1, 3)

    def test_dict_gaps_field_falls_back_to_count_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 2, "gaps": {"file": "binary:lib.so"},
        }))
        assert run_scope_coverage(tmp_path) == (0, 2)

    def test_mixed_non_dict_gap_rows_are_ignored_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 4,
            "gaps": [
                {"file": "binary:lib.so", "name": "FUN_0"},
                "junk-row", 42,
                {"file": "binary:lib.so", "name": "FUN_1"},
            ],
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="clean")
        # Denominator and set-difference both see dict rows only.
        assert run_scope_coverage(tmp_path) == (1, 2)


def _write_graded(run: Path, findings: list[dict[str, Any]],
                  stats: dict[str, Any]) -> None:
    (run / "findings-graded.json").write_text(json.dumps({
        "findings": findings, "stats": stats,
    }), encoding="utf-8")


class TestDigestResidue:
    def test_residue_announced_instead_of_bare_all_clear(
        self, tmp_path: Path,
    ) -> None:
        _seed_gap_audit_run(tmp_path)
        _write_graded(tmp_path, [
            {"id": "GR-1", "status": "suspicious", "confidence": "low",
             "title": "unchecked length feeds memcpy",
             "file": "binary:lib.so", "function": "FUN_2"},
            {"id": "GR-2", "status": "suspicious", "confidence": "low",
             "title": "index from packet without bound",
             "file": "binary:lib.so", "function": "FUN_3"},
        ], {"total": 2, "low_confidence": 2, "dark": 0})

        d = read_run_digest(tmp_path)
        assert d.residue_counts.get("llm_suspicious") == 2
        assert d.residue_counts.get("errored") == 2
        assert d.residue_top, "top items must surface per-item detail"

        out = render_run_digest(d)
        # The all-clear implication must be qualified, not bare.
        assert "not all-clear" in out
        assert "LLM suspicious" in out
        assert "Errored reviews" in out
        # Top items carry function + one-line title from the graded
        # export, and the browse pointer names the query command.
        assert "FUN_2" in out
        assert "unchecked length feeds memcpy" in out
        assert "raptor-review findings" in out

    def test_clean_run_keeps_bare_all_clear(self, tmp_path: Path) -> None:
        _meta(tmp_path)
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="clean")
        d = read_run_digest(tmp_path)
        assert d.residue_counts == {}
        out = render_run_digest(d)
        assert "No verified or exploitable-unverified findings." in out
        assert "residue" not in out.lower()

    def test_journal_fallback_when_graded_export_absent(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path)
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_jrn", verdict="suspicious",
                body="len field trusted before copy\nmore detail")
        d = read_run_digest(tmp_path)
        assert any(
            item.get("function") == "FUN_jrn" for item in d.residue_top
        )
        out = render_run_digest(d)
        assert "FUN_jrn" in out
        assert "len field trusted before copy" in out
        assert "more detail" not in out  # one-line title only

    def test_residue_strings_escaped_at_render(
        self, tmp_path: Path,
    ) -> None:
        # Display integrity: graded titles / function names are
        # target-derived — a forged export carrying OSC/ESC bytes,
        # raw C1 controls (0x85 NEL, 0x9b CSI, 0x9d OSC, 0x90 DCS),
        # or bidi overrides (U+202E RLO, U+2066 LRI) must render
        # inert. The digest seam (``sanitise_for_terminal``) escapes
        # C1 to ``\xHH`` and bidi to ``\uHHHH`` text.
        _meta(tmp_path)
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_evil", verdict="suspicious")
        _write_graded(tmp_path, [
            {"id": "GR-1", "status": "suspicious", "confidence": "low",
             "title": "own \x1b]0;pwned\x07\x85\x9d the ‮eltit",
             "file": "binary:lib.so",
             "function": "FUN_evil\x1b[31m\x9b\x90⁦"},
        ], {"total": 1, "low_confidence": 1, "dark": 0})
        out = render_run_digest(read_run_digest(tmp_path))
        assert "FUN_evil" in out  # the item DID render
        for raw in ("\x1b", "\x07", "\x85", "\x9b", "\x9d", "\x90",
                    "‮", "⁦"):
            assert raw not in out
        assert "\\x9b" in out    # C1 escaped to inert text
        assert "\\u202e" in out  # bidi escaped, not silently dropped

    def test_unparsable_journal_never_implies_all_clear(
        self, tmp_path: Path,
    ) -> None:
        # A PRESENT but wholly-undecodable journal parses to zero
        # entries → zero residue counts → the digest used to render
        # the bare all-clear line. Never imply all-clear over a
        # journal that contributed no evidence.
        _meta(tmp_path)
        (tmp_path / "review-journal.jsonl").write_bytes(
            b"\x00\xff" * 512)
        d = read_run_digest(tmp_path)
        assert d.residue_journal_unreadable is True
        out = render_run_digest(d)
        assert "No verified or exploitable-unverified findings." \
            not in out
        assert "cannot confirm all-clear" in out

    def test_partially_corrupt_journal_keeps_residue_path(
        self, tmp_path: Path,
    ) -> None:
        # Partial corruption already degrades correctly: any
        # parsable row feeds the residue classes and the qualified
        # line — the unreadable-journal disclosure must not replace
        # that path.
        _meta(tmp_path)
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_bad", verdict="suspicious")
        with (tmp_path / "review-journal.jsonl").open("ab") as fh:
            fh.write(b"\xff\xfe garbage line, not json\n")
        d = read_run_digest(tmp_path)
        assert d.residue_counts.get("llm_suspicious") == 1
        out = render_run_digest(d)
        assert "not all-clear" in out
        assert "cannot confirm all-clear" not in out

    def test_absent_journal_keeps_bare_all_clear(
        self, tmp_path: Path,
    ) -> None:
        # No journal at all is NOT "unreadable" — a non-audit run
        # must keep the plain line, no disclosure.
        _meta(tmp_path, command="scan")
        d = read_run_digest(tmp_path)
        assert d.residue_journal_unreadable is False
        out = render_run_digest(d)
        assert "No verified or exploitable-unverified findings." in out

    def test_findings_rank_above_residue(self, tmp_path: Path) -> None:
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f1", "file": "a.c", "is_exploitable": True},
        ]), encoding="utf-8")
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_res", verdict="suspicious")
        out = render_run_digest(read_run_digest(tmp_path))
        assert "Unverified residue" in out
        assert (out.index("Exploitable, unverified")
                < out.index("Unverified residue"))
