"""Report honesty for unverified residue.

The /audit report derives its verdict stats from the review journal
via a latest-per-site collapse. Post-loop mechanical echoes
(decomp-sweep pattern hits, consistency-census rows) are journalled
AFTER the review loop, so a single latest-per-site map let a later
mechanical echo shadow the LLM verdict at the same site — a live
binary-target run's report counted 2 LLM-suspicious + 2 errored
functions as 0/0 because sweep rows outran them on timestamp.

Every stats consumer already excludes mechanical rows from verdict
authority (`_apply_journal_verdict_overrides`,
`_count_remaining_gaps`); these tests pin the collapse itself to the
same rule: mechanical and LLM rows collapse in separate maps so both
stay visible and neither evicts the other.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.audit.report import generate_report


def _entry(**kw: Any) -> Any:
    from core.coverage.journal import ReviewJournalEntry
    base: dict[str, Any] = {
        "run_id": "t", "file": "binary:lib.so", "source_hash": "",
    }
    base.update(kw)
    return ReviewJournalEntry(**base)


def _append(out_dir: Path, **kw: Any) -> None:
    from core.coverage.journal import append_entry
    append_entry(out_dir, _entry(**kw))


class TestMechanicalShadowing:
    def test_later_mechanical_echo_does_not_shadow_llm_verdict(
        self, tmp_path: Path,
    ) -> None:
        # LLM review verdict during the loop ...
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_a", verdict="suspicious")
        # ... then a decomp-sweep echo at the SAME site, journalled
        # later (post-loop), as on every binary-target run.
        _append(tmp_path, ts="2026-01-01T00:10:00+00:00",
                function="FUN_a", verdict="suspicious",
                strategies=["post-loop-mechanical"],
                body="[mechanical] sweep rule hit")

        stats = generate_report(tmp_path)["stats"]
        assert stats["suspicious"] == 1, (
            "the LLM suspicious verdict must survive a later "
            "mechanical echo at the same site"
        )
        assert stats["reviewed"] == 1
        assert stats["mechanical"] == 1

    def test_errored_review_not_shadowed(self, tmp_path: Path) -> None:
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_b", verdict="error",
                error_class="task_exception")
        _append(tmp_path, ts="2026-01-01T00:10:00+00:00",
                function="FUN_b", verdict="suspicious",
                strategies=["post-loop-mechanical"],
                body="[mechanical] sweep rule hit")

        stats = generate_report(tmp_path)["stats"]
        assert stats["error"] == 1, (
            "an errored LLM review must stay counted when a "
            "mechanical echo lands on the same site later"
        )
        assert stats["mechanical"] == 1

    def test_llm_rows_still_collapse_latest_per_site(
        self, tmp_path: Path,
    ) -> None:
        # Reflexion-style correction: the LATEST LLM row at a site
        # keeps verdict authority within its own bucket.
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_c", verdict="suspicious")
        _append(tmp_path, ts="2026-01-01T00:05:00+00:00",
                function="FUN_c", verdict="clean")

        stats = generate_report(tmp_path)["stats"]
        assert stats["reviewed"] == 1
        assert stats["clean"] == 1
        assert stats["suspicious"] == 0

    def test_mechanical_rows_still_collapse_latest_per_site(
        self, tmp_path: Path,
    ) -> None:
        for ts in ("2026-01-01T00:10:00+00:00",
                   "2026-01-01T00:11:00+00:00"):
            _append(tmp_path, ts=ts, function="FUN_d",
                    verdict="suspicious",
                    strategies=["post-loop-mechanical"],
                    body="[mechanical] sweep rule hit")

        stats = generate_report(tmp_path)["stats"]
        assert stats["mechanical"] == 1
        assert stats["reviewed"] == 0


def _seed_residue_run(out_dir: Path) -> None:
    """A synthetic run modeled on a live gap-audit run's shapes:
    LLM suspicious + errored reviews, later mechanical sweep echoes,
    and a graded export carrying two low-confidence suspicious items
    plus one dark item."""
    _append(out_dir, ts="2026-01-01T00:00:01+00:00",
            function="FUN_00250bc0", verdict="suspicious",
            confidence=0.3)
    _append(out_dir, ts="2026-01-01T00:00:02+00:00",
            function="FUN_0036b4c0", verdict="error",
            error_class="task_exception")
    _append(out_dir, ts="2026-01-01T00:00:03+00:00",
            function="FUN_00003000", verdict="clean")
    for i, fn in enumerate(("FUN_00250bc0", "FUN_00777000")):
        _append(out_dir, ts=f"2026-01-01T00:10:0{i}+00:00",
                function=fn, verdict="suspicious",
                strategies=["post-loop-mechanical"],
                body="[mechanical] sweep rule hit")
    (out_dir / "findings-graded.json").write_text(json.dumps({
        "findings": [
            {"id": "GR-1", "status": "suspicious", "confidence": "low",
             "title": "unchecked length feeds memcpy",
             "file": "binary:lib.so", "function": "FUN_00250bc0"},
            {"id": "GR-2", "status": "suspicious", "confidence": "low",
             "title": "index from packet without bound",
             "file": "binary:lib.so", "function": "FUN_00251000"},
            {"id": "GR-3", "status": "dark",
             "title": "auth decision from client field",
             "file": "binary:lib.so", "function": "FUN_00252000"},
        ],
        "stats": {"total": 3, "low_confidence": 2, "dark": 1},
    }))


class TestUnverifiedResidue:
    def test_report_names_residue_classes_and_artifacts(
        self, tmp_path: Path,
    ) -> None:
        _seed_residue_run(tmp_path)
        residue = generate_report(tmp_path)["unverified_residue"]

        assert residue["llm_suspicious"]["count"] == 1
        assert residue["mechanical_suspicious"]["count"] == 2
        assert residue["dark"]["count"] == 1
        assert residue["graded_low_confidence"]["count"] == 2
        assert residue["errored"]["count"] == 1
        # Every class points at the artifact holding its per-item
        # records and at the browse command — a count is never a
        # dead end.
        for rec in residue.values():
            assert rec["detail"]
            assert "raptor-review" in rec["browse"]
        assert "findings-graded.json" in residue["llm_suspicious"]["detail"]
        assert "review-journal.jsonl" in residue["errored"]["detail"]
        assert (
            "decomp-sweep.json"
            in residue["mechanical_suspicious"]["detail"]
        )

    def test_summary_prints_residue_when_nonzero(
        self, tmp_path: Path,
    ) -> None:
        _seed_residue_run(tmp_path)
        summary = generate_report(tmp_path)["summary"]
        assert "Unverified residue" in summary
        assert "findings-graded.json" in summary
        assert "raptor-review" in summary

    def test_summary_silent_when_all_zero(self, tmp_path: Path) -> None:
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_clean", verdict="clean")
        report = generate_report(tmp_path)
        # JSON always carries the full schema (zero counts included);
        # the console section is the only thing that goes silent.
        assert set(report["unverified_residue"]) >= {
            "llm_suspicious", "mechanical_suspicious", "dark",
            "graded_low_confidence", "errored",
        }
        assert all(
            rec["count"] == 0
            for rec in report["unverified_residue"].values()
        )
        assert "Unverified residue" not in report["summary"]

    def test_residue_lines_render_seam(self, tmp_path: Path) -> None:
        from core.audit.report import format_residue_lines
        _seed_residue_run(tmp_path)
        report = generate_report(tmp_path)
        lines = format_residue_lines(report)
        assert lines and "Unverified residue" in lines[0]
        assert format_residue_lines({"unverified_residue": {}}) == []


class TestErroredFunctions:
    def test_json_carries_full_per_item_list(self, tmp_path: Path) -> None:
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0036b4c0", verdict="error",
                error_class="task_exception")
        _append(tmp_path, ts="2026-01-01T00:00:02+00:00",
                function="FUN_005278e0", verdict="error",
                error_class="task_exception")

        report = generate_report(tmp_path)
        errored = report["errored_functions"]
        assert {e["function"] for e in errored} == {
            "FUN_0036b4c0", "FUN_005278e0",
        }
        assert all(e["file"] == "binary:lib.so" for e in errored)
        assert all(e["error_class"] == "task_exception" for e in errored)

    def test_console_lists_items_below_bound(self, tmp_path: Path) -> None:
        for i in range(3):
            _append(tmp_path, ts=f"2026-01-01T00:00:0{i}+00:00",
                    function=f"FUN_err{i}", verdict="error",
                    error_class="task_exception")

        summary = generate_report(tmp_path)["summary"]
        assert "Errored reviews (3)" in summary
        for i in range(3):
            assert f"FUN_err{i}" in summary
        assert "task_exception" in summary
        assert "more" not in summary.split("Errored reviews")[1].split(
            "###")[0].lower()

    def test_console_bounds_systemic_failure_runs(
        self, tmp_path: Path,
    ) -> None:
        # Over-bound direction: a systemic failure (25 errored rows)
        # must not swamp the console — first 20 plus an explicit
        # elision naming the remainder and the full-list artifact.
        for i in range(25):
            _append(tmp_path, ts=f"2026-01-01T00:{i:02d}:00+00:00",
                    function=f"FUN_err{i:02d}", verdict="error",
                    error_class="environment")

        report = generate_report(tmp_path)
        assert len(report["errored_functions"]) == 25  # JSON stays full
        summary = report["summary"]
        assert "Errored reviews (25)" in summary
        listed = sum(
            1 for i in range(25) if f"FUN_err{i:02d}" in summary
        )
        assert listed == 20
        assert "5 more" in summary
        assert "audit-report.json" in summary

    def test_errored_render_is_escaped(self, tmp_path: Path) -> None:
        # Display integrity: journal fields land in terminal output —
        # a forged row carrying OSC/ESC, raw C1 controls (0x85 NEL,
        # 0x9b CSI, 0x9d OSC, 0x90 DCS), or bidi overrides
        # (U+202E RLO, U+2066 LRI) must render inert. The seam
        # (``sanitise_string``) escapes C1 to ``\xHH`` text and drops
        # bidi controls.
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_x\x1b]0;pwned\x07\x85\x9b", verdict="error",
                error_class="bad\x1b[31m\x9d\x90class‮gnp⁦")
        summary = generate_report(tmp_path)["summary"]
        assert "FUN_x" in summary  # the errored section DID render
        for raw in ("\x1b", "\x07", "\x85", "\x9b", "\x9d", "\x90",
                    "‮", "⁦"):
            assert raw not in summary
        assert "\\x9b" in summary  # C1 escaped to inert text, not dropped
        assert "class" in summary  # content around bidi survives


class TestMarkdownReportWiring:
    def test_markdown_report_includes_residue_section(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import write_markdown_report
        _seed_residue_run(tmp_path)
        report = generate_report(tmp_path)
        text = write_markdown_report(report, tmp_path).read_text(
            encoding="utf-8")
        assert "Unverified residue" in text
        assert "findings-graded.json" in text

    def test_finalise_tail_writes_markdown_report(self) -> None:
        # The finalise tail must write audit-report.md alongside
        # audit-report.json (the renderer existed caller-less; the
        # report verb and the finalise tail are its two consumers).
        import re
        launcher = (
            Path(__file__).resolve().parents[3]
            / "libexec" / "raptor-audit"
        ).read_text(encoding="utf-8")
        assert re.search(r"write_markdown_report\(", launcher), (
            "libexec/raptor-audit must call write_markdown_report"
        )
