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
