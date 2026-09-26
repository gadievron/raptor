"""``journal compact --supersede`` — the lossy-with-archive tier.

The contract under test: a journal dominated by DISTINCT-bodied live
review rows (multi-pass mega-audit shape — nothing the lossless
duplicate prune can drop) wedges the spend-authorizing resume once it
crosses the loader budget; the superseding tier unwedges it by keeping
only the newest row per review identity while

* preserving the journal spend floor bit-exactly (each dropped
  cost-bearing row is replaced in place by a spend-carrier row with
  the identical ``cost_usd`` value);
* leaving every latest-wins consumer's view of real functions
  identical (latest verdict per key, reviewed-key set);
* retaining claim rows, corrections, provisional and error/dark rows,
  and unparseable lines outright;
* archiving the full original as ``review-journal.jsonl.pre-supersede``
  (numbered family, never overwritten).
"""

from __future__ import annotations

import importlib.util
import random
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.coverage.journal as journal_mod
from core.audit.resume import journal_spend_usd
from core.coverage.journal import (
    JOURNAL_FILENAME,
    JournalIncomplete,
    ReviewJournalEntry,
    append_entry,
    compact_hint,
    entry_earns_function_coverage,
    is_mechanical_echo,
    latest_entries,
    load_entries,
    load_entries_checked,
    now_iso,
    require_complete_entries,
    reviewed_set,
)
import core.coverage.journal_compact as journal_compact
from core.coverage.journal_compact import (
    SPEND_CARRIER_FUNCTION,
    CompactRefused,
    compact_journal,
    is_spend_carrier,
)

#: Essay-sized review body — the mega-audit journal shape is a MEDIAN
#: row in the tens of KiB, dominated by prose bodies.
_BODY = "adversarial review prose, hypotheses and receipts. " * 45


def _entry(i: int, **over) -> ReviewJournalEntry:
    fields = dict(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i % 7}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash=f"{i:08x}",
        line_start=1 + i,
        line_end=5 + i,
        strategies=["bounds"],
        model="model-a",
        body=_BODY,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _mega_audit_run(out: Path, n_sites: int = 40,
                    n_passes: int = 4) -> float:
    """Multi-pass live-review journal: every pass re-reviews every
    site with a DISTINCT body and a real cost — zero rows the lossless
    duplicate prune may drop. Returns the total journaled spend."""
    spend = 0.0
    for p in range(n_passes):
        for i in range(n_sites):
            cost = 0.11 + i / 977 + p / 83
            spend += cost
            append_entry(out, _entry(
                i, cost_usd=cost, body=f"{_BODY} pass {p} site {i}",
            ))
    return spend


def _latest_view(out: Path) -> dict[str, tuple[str, str]]:
    """Latest verdict/ts per key, spend carriers excluded (carriers
    live under their own reserved key and are asserted separately)."""
    return {
        k: (e.verdict, e.ts) for k, e in latest_entries(out).items()
        if not is_spend_carrier(e)
    }


class TestMegaAuditWedge:
    def test_wedge_reproduced_then_supersede_unwedges(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _mega_audit_run(tmp_path)

        # Oracles from a FULL (default-budget) load.
        full = load_entries_checked(tmp_path)
        assert full.complete
        oracle_latest = _latest_view(tmp_path)
        oracle_reviewed = reviewed_set(tmp_path)
        oracle_spend = journal_spend_usd(tmp_path)

        budget = 192 * 1024
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", budget)

        # The wedge: plain compaction is a no-op (nothing prunable) …
        stats = compact_journal(tmp_path)
        assert stats.dropped_reemissions == 0
        assert stats.bytes_after == stats.bytes_before
        assert stats.ratio == 1.0
        # … the loader flags the journal incomplete …
        loaded = load_entries_checked(tmp_path)
        assert not loaded.complete
        # … and the spend-authorizing read refuses, naming BOTH tiers.
        with pytest.raises(JournalIncomplete) as exc:
            require_complete_entries(tmp_path)
        assert "journal compact" in str(exc.value)
        assert "--supersede" in str(exc.value)

        # The remedy: --supersede brings the journal under budget.
        sstats = compact_journal(tmp_path, supersede=True)
        assert sstats.dropped_superseded > 0
        assert sstats.bytes_after < budget
        assert sstats.spend_usd_after == sstats.spend_usd_before

        post = load_entries_checked(tmp_path)
        assert post.complete
        assert require_complete_entries(tmp_path)

        # Newest-per-identity verdicts identical to the full load.
        assert _latest_view(tmp_path) == oracle_latest
        assert reviewed_set(tmp_path) == oracle_reviewed
        # Spend floor bit-identical, not merely to the cent.
        assert journal_spend_usd(tmp_path) == oracle_spend

    def test_archive_preserves_original_and_numbers_generations(
        self, tmp_path: Path,
    ) -> None:
        _mega_audit_run(tmp_path, n_sites=3, n_passes=2)
        journal = tmp_path / JOURNAL_FILENAME
        original = journal.read_bytes()

        stats = compact_journal(tmp_path, supersede=True)
        backup = Path(stats.backup_path)
        assert backup.name == "review-journal.jsonl.pre-supersede"
        assert backup.read_bytes() == original

        # A second pass never clobbers the first archive generation.
        second = compact_journal(tmp_path, supersede=True)
        assert Path(second.backup_path).name \
            == "review-journal.jsonl.pre-supersede.2"

    def test_idempotent_second_pass_drops_nothing(
        self, tmp_path: Path,
    ) -> None:
        _mega_audit_run(tmp_path, n_sites=4, n_passes=3)
        compact_journal(tmp_path, supersede=True)
        first = (tmp_path / JOURNAL_FILENAME).read_bytes()
        spend = journal_spend_usd(tmp_path)

        stats = compact_journal(tmp_path, supersede=True)
        assert stats.dropped_superseded == 0
        assert stats.spend_carriers == 0
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == first
        assert journal_spend_usd(tmp_path) == spend


class TestRetention:
    def test_claims_corrections_provisional_error_dark_survive(
        self, tmp_path: Path,
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        # Two distinct-bodied claim emissions: both survive.
        append_entry(tmp_path, _entry(
            1, verdict="finding", cwe="CWE-787", cost_usd=0.5,
            body="first emission"))
        append_entry(tmp_path, _entry(
            1, verdict="finding", cwe="CWE-787", cost_usd=0.2,
            body="re-validation emission"))
        append_entry(tmp_path, _entry(2, verdict="suspicious",
                                      cost_usd=0.3))
        # Correction / lesson rows: read from non-latest rows by
        # survival stats and FP feedback — never superseded.
        append_entry(tmp_path, _entry(
            3, validate_verdict="disproven", prior_review="finding",
            cost_usd=0.0))
        append_entry(tmp_path, _entry(3, lesson="keep me",
                                      cost_usd=0.0))
        append_entry(tmp_path, _entry(4, provisional=True,
                                      verdict="finding", cost_usd=0.4))
        append_entry(tmp_path, _entry(5, verdict="error", cost_usd=0.0))
        append_entry(tmp_path, _entry(6, verdict="dark", cost_usd=0.1))
        with journal.open("ab") as fh:
            fh.write(b"{corrupt json\n")

        rows_before = len(journal.read_bytes().splitlines())
        stats = compact_journal(tmp_path, supersede=True)
        rows_after = len(journal.read_bytes().splitlines())
        assert stats.dropped_superseded == 0
        assert rows_after == rows_before
        assert b"{corrupt json" in journal.read_bytes()

    def test_kept_rows_are_verbatim_original_lines(
        self, tmp_path: Path,
    ) -> None:
        """Every surviving non-carrier line is byte-identical to an
        original line (MAC-preserving; no re-serialization)."""
        _mega_audit_run(tmp_path, n_sites=4, n_passes=3)
        original = set(
            (tmp_path / JOURNAL_FILENAME).read_bytes().splitlines())
        compact_journal(tmp_path, supersede=True)
        for line in (tmp_path / JOURNAL_FILENAME).read_bytes() \
                .splitlines():
            if SPEND_CARRIER_FUNCTION.encode() in line:
                continue
            assert line in original

    def test_correction_chain_terminal_row_survives(
        self, tmp_path: Path,
    ) -> None:
        """A downgraded claim: the correction chain's terminal row is
        what every latest-wins consumer sees after superseding — the
        older finding-grade row never resurfaces as the key's verdict
        through the live journal."""
        # Older finding claim, then the downgrade correction.
        append_entry(tmp_path, _entry(
            1, verdict="finding", cwe="CWE-787", cost_usd=0.9))
        append_entry(tmp_path, _entry(
            1, verdict="clean", validate_verdict="disproven",
            prior_review="finding", lesson="fp: bounded copy",
            cost_usd=0.0))
        # A bare final-status corrective row (no lesson/validate) over
        # older clean passes: the older passes supersede, the terminal
        # corrective row wins.
        for p in range(3):
            append_entry(tmp_path, _entry(
                2, cost_usd=0.2 + p / 100, body=f"pass {p}"))

        before_latest = _latest_view(tmp_path)
        stats = compact_journal(tmp_path, supersede=True)
        assert stats.dropped_superseded == 2      # fn2's older passes

        latest = latest_entries(tmp_path)
        corrected = latest["src/f1.c:fn1"]
        assert corrected.verdict == "clean"
        assert corrected.validate_verdict == "disproven"
        assert _latest_view(tmp_path) == before_latest
        # The finding emission is retained (claim row), but only as
        # history — never as the key's latest verdict.
        findings = [e for e in load_entries(tmp_path)
                    if e.verdict == "finding"]
        assert len(findings) == 1


class TestSpendCarriers:
    def test_carriers_are_loader_valid_and_inert(
        self, tmp_path: Path,
    ) -> None:
        _mega_audit_run(tmp_path, n_sites=3, n_passes=3)
        stats = compact_journal(tmp_path, supersede=True)
        assert stats.spend_carriers == stats.dropped_superseded == 6

        carriers = [e for e in load_entries(tmp_path)
                    if is_spend_carrier(e)]
        assert len(carriers) == 6
        for c in carriers:
            # Inert on every authority path: error verdict (excluded
            # from reviewed_set, coverage import, drift, reuse folds),
            # reserved identity, mechanical-echo counting exclusion.
            assert c.verdict == "error"
            assert c.function == SPEND_CARRIER_FUNCTION
            assert c.file == ""
            assert is_mechanical_echo(c)
            assert not entry_earns_function_coverage(c)
        assert not any(
            SPEND_CARRIER_FUNCTION in k for k in reviewed_set(tmp_path)
        )

    def test_project_index_merge_tolerates_carriers(
        self, tmp_path: Path,
    ) -> None:
        from core.coverage.journal import load_index, merge_into_index
        run = tmp_path / "run1"
        run.mkdir()
        _mega_audit_run(run, n_sites=3, n_passes=3)
        compact_journal(run, supersede=True)

        project = tmp_path / "project"
        assert merge_into_index(project, run) > 0
        idx = load_index(project)
        # Real keys all present; carriers collapse to (at most) their
        # single reserved key and shadow nothing.
        for i in range(3):
            assert f"src/f{i}.c:fn{i}" in idx
        carrier_keys = [k for k in idx if SPEND_CARRIER_FUNCTION in k]
        assert len(carrier_keys) <= 1


class TestHardStops:
    def test_value_corrupting_carrier_writer_refuses_swap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The floor check verifies the WRITTEN bytes: a carrier
        writer that corrupts the cost value (not merely omits it)
        must refuse the swap with the journal untouched."""
        _mega_audit_run(tmp_path, n_sites=3, n_passes=3)
        original = (tmp_path / JOURNAL_FILENAME).read_bytes()

        orig_writer = journal_compact._spend_carrier_line

        def forged(entry: ReviewJournalEntry, raw: dict,
                   *args: object) -> bytes | None:
            # *args: tolerate additive positional params on the real
            # writer (the slim tier's archive-suffix) — this double
            # only forges the cost value.
            raw = dict(raw)
            cost = raw.get("cost_usd")
            if isinstance(cost, (int, float)):
                raw["cost_usd"] = cost * 2
            return orig_writer(entry, raw, *args)

        monkeypatch.setattr(
            journal_compact, "_spend_carrier_line", forged)

        with pytest.raises(CompactRefused, match="spend floor"):
            compact_journal(tmp_path, supersede=True)
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == original
        assert not (tmp_path
                    / "review-journal.jsonl.pre-supersede").exists()
        assert not list(tmp_path.glob(".~compact-*")), (
            "tmp file leaked after the refused swap"
        )

    def test_live_run_refused_with_supersede(
        self, tmp_path: Path,
    ) -> None:
        import json as _json
        import os as _os

        from core.run.metadata import RUN_METADATA_FILE
        _mega_audit_run(tmp_path, n_sites=2, n_passes=2)
        (tmp_path / RUN_METADATA_FILE).write_text(_json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": _os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        before = (tmp_path / JOURNAL_FILENAME).read_bytes()
        with pytest.raises(CompactRefused, match="in flight"):
            compact_journal(tmp_path, supersede=True)
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == before


class TestHostileRows:
    @staticmethod
    def _force_stdlib_json(monkeypatch: pytest.MonkeyPatch) -> None:
        # Same two-namespace forcing as the append-side hostility
        # pins: patch the live core.json.utils module AND the globals
        # the compactor's module-level ``loads`` binding actually
        # reads (a sibling suite's sys.modules purge can detach them).
        import core.json.utils as json_utils
        monkeypatch.setattr(json_utils, "_orjson", None)
        monkeypatch.setitem(
            journal_compact.loads.__globals__, "_orjson", None)

    def test_inf_cost_plant_cannot_mask_forged_carrier(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """stdlib-json arm: a planted ``cost_usd: 1e400`` parses to
        ``inf``; unclamped it lands on BOTH sides of the floor check
        (``inf == inf``), silently accepting a forged carrier value.
        With the loader-matching clamp the forgery must still refuse."""
        self._force_stdlib_json(monkeypatch)
        _mega_audit_run(tmp_path, n_sites=3, n_passes=3)
        journal = tmp_path / JOURNAL_FILENAME
        with journal.open("a", encoding="ascii") as fh:
            fh.write(
                '{"ts": "2099-01-01T00:00:00.000001Z", "run_id": '
                '"audit-run", "file": "src/p.c", "function": "pf", '
                '"verdict": "clean", "schema_version": 1, '
                '"cost_usd": 1e400}\n'
            )
        original = journal.read_bytes()

        orig_writer = journal_compact._spend_carrier_line

        def forged(entry: ReviewJournalEntry, raw: dict,
                   *args: object) -> bytes | None:
            # *args: tolerate additive positional params on the real
            # writer (the slim tier's archive-suffix) — this double
            # only forges the cost value.
            raw = dict(raw)
            cost = raw.get("cost_usd")
            if isinstance(cost, (int, float)):
                raw["cost_usd"] = cost * 2
            return orig_writer(entry, raw, *args)

        monkeypatch.setattr(
            journal_compact, "_spend_carrier_line", forged)
        with pytest.raises(CompactRefused, match="spend floor"):
            compact_journal(tmp_path, supersede=True)
        assert journal.read_bytes() == original

    def test_inf_cost_plant_kept_verbatim_on_honest_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._force_stdlib_json(monkeypatch)
        _mega_audit_run(tmp_path, n_sites=2, n_passes=2)
        journal = tmp_path / JOURNAL_FILENAME
        plant = (
            '{"ts": "2099-01-01T00:00:00.000001Z", "run_id": '
            '"audit-run", "file": "src/p.c", "function": "pf", '
            '"verdict": "clean", "schema_version": 1, '
            '"cost_usd": 1e400}'
        )
        with journal.open("a", encoding="ascii") as fh:
            fh.write(plant + "\n")

        stats = compact_journal(tmp_path, supersede=True)
        assert stats.dropped_superseded > 0
        assert plant.encode("ascii") in journal.read_bytes()

    def test_cross_producer_reused_twin_does_not_orphan_identity(
        self, tmp_path: Path,
    ) -> None:
        """The dedup identity lacks the producer axis, so a newer
        reused twin from ANOTHER producer wins the dedup election and
        the same-producer reused row drops. That row must then never
        be elected as a superseding winner — its siblings would be
        dropped against a winner that never lands, leaving the
        producer's identity with zero surviving rows (a live
        function-grade audit review lost to a finding-grade twin)."""
        # Live audit review ($-bearing, function-grade evidence) ...
        append_entry(tmp_path, _entry(1, cost_usd=0.4))
        # ... a newer reused re-emission of it (same producer) ...
        append_entry(tmp_path, _entry(
            1, reused=True, cost_usd=0.0,
            body="[reused: verdict imported]"))
        # ... and the newest reused twin stamped by ANOTHER producer.
        append_entry(tmp_path, _entry(
            1, reused=True, cost_usd=0.0, producer="agentic",
            body="[reused: verdict imported]"))

        stats = compact_journal(tmp_path, supersede=True)

        from core.coverage.journal import entry_producer
        survivors = [e for e in load_entries(tmp_path)
                     if not is_spend_carrier(e)]
        audit_rows = [e for e in survivors
                      if entry_producer(e) == "audit"]
        assert audit_rows, (
            "superseding orphaned the audit-producer identity "
            "(zero surviving rows)"
        )
        # The live function-grade evidence itself survives.
        assert any((e.cost_usd or 0.0) > 0 for e in audit_rows)
        # The cross-producer duplicate still dedups normally.
        assert stats.dropped_reemissions == 1
        assert stats.dropped_superseded == 0


class TestStaleTmpSweep:
    def test_stale_tmp_from_killed_compaction_swept(
        self, tmp_path: Path,
    ) -> None:
        _mega_audit_run(tmp_path, n_sites=2, n_passes=2)
        stale = tmp_path / ".~compact-killed.jsonl"
        stale.write_bytes(b"leftover from a pre-rename kill")
        compact_journal(tmp_path, supersede=True)
        assert not stale.exists()


class TestTierComposition:
    def test_supersede_after_prior_dedup_compaction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The duplicate-heavy resume-chain shape: a journal that
        already went through the lossless dedup pass and is STILL over
        budget (multi-pass distinct-bodied live rows underneath the
        duplicates) — the superseding tier must compose with the prior
        pass and finish the unwedge."""
        # Live multi-pass rows (dedup-immune) …
        _mega_audit_run(tmp_path, n_sites=30, n_passes=3)
        # … plus reused zero-cost re-emissions of every site across
        # segments (dedup-prunable multiplicity).
        for _seg in range(3):
            for i in range(30):
                append_entry(tmp_path, _entry(
                    i, reused=True, cost_usd=0.0,
                    body="[reused: verdict imported]",
                ))
        full_spend = journal_spend_usd(tmp_path)
        oracle_latest = _latest_view(tmp_path)
        oracle_reviewed = reviewed_set(tmp_path)

        budget = 160 * 1024
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", budget)

        # Pass 1: the lossless tier drops the duplicates …
        dedup = compact_journal(tmp_path)
        assert dedup.dropped_reemissions == 60   # 2 dropped per site
        # … but the journal stays wedged.
        assert not load_entries_checked(tmp_path).complete

        # Pass 2: the superseding tier finishes the job.
        sstats = compact_journal(tmp_path, supersede=True)
        assert sstats.dropped_superseded > 0
        assert sstats.bytes_after < budget
        assert load_entries_checked(tmp_path).complete
        assert _latest_view(tmp_path) == oracle_latest
        assert reviewed_set(tmp_path) == oracle_reviewed
        assert journal_spend_usd(tmp_path) == full_spend
        # Both archive generations coexist.
        assert (tmp_path
                / "review-journal.jsonl.pre-compact").is_file()
        assert (tmp_path
                / "review-journal.jsonl.pre-supersede").is_file()


class TestTimestampTieBreak:
    """Identical-``ts`` rows within one review identity: the
    superseding tier must keep the row every latest-wins consumer
    elects — consumer parity, never a private tie convention."""

    def test_tie_survivor_matches_latest_entries(
        self, tmp_path: Path,
    ) -> None:
        """Two same-identity rows stamped in the same microsecond,
        differing only in non-identity fields (body, cost): whatever
        ``latest_entries`` picks for the key BEFORE compaction must be
        the row that survives ``--supersede``."""
        ts = now_iso()
        append_entry(tmp_path, _entry(
            1, ts=ts, cost_usd=0.2, body=f"{_BODY} emission A"))
        append_entry(tmp_path, _entry(
            1, ts=ts, cost_usd=0.3, body=f"{_BODY} emission B"))
        before = latest_entries(tmp_path)

        stats = compact_journal(tmp_path, supersede=True)

        assert stats.dropped_superseded == 1
        after = {
            k: e for k, e in latest_entries(tmp_path).items()
            if not is_spend_carrier(e)
        }
        (key,) = after
        # Consumer parity: the survivor IS the row the latest-wins
        # consumers elected on the tie — same non-identity fields,
        # not merely the same verdict/ts.
        assert after[key].body == before[key].body
        assert after[key].cost_usd == before[key].cost_usd

    def test_newer_ts_wins_regardless_of_file_order(
        self, tmp_path: Path,
    ) -> None:
        """Control: a strictly newer ``ts`` always wins, even when
        the newer row sits EARLIER in the file (out-of-order append —
        the merge/import shape)."""
        t1 = now_iso()
        t2 = now_iso()
        while t2 <= t1:      # never tie: this test is the ordered arm
            t2 = now_iso()
        # Newer row FIRST in file, older row second.
        append_entry(tmp_path, _entry(
            1, ts=t2, cost_usd=0.2, body=f"{_BODY} newer"))
        append_entry(tmp_path, _entry(
            1, ts=t1, cost_usd=0.3, body=f"{_BODY} older"))
        before = latest_entries(tmp_path)

        stats = compact_journal(tmp_path, supersede=True)

        assert stats.dropped_superseded == 1
        after = {
            k: e for k, e in latest_entries(tmp_path).items()
            if not is_spend_carrier(e)
        }
        (key,) = after
        assert after[key].ts == t2
        assert after[key].body == before[key].body


class TestSpendFloorProperty:
    """Property test (shared shape with the lossless tier's): over
    randomized journals — live multi-pass rows, reused duplicates,
    corrections, claims, errors, provisional rows, corrupt lines —
    the spend floor is BIT-IDENTICAL and every latest-wins verdict
    view is unchanged after superseding."""

    @pytest.mark.parametrize("seed", [7, 23, 1291])
    def test_semantics_identical(self, tmp_path: Path,
                                 seed: int) -> None:
        rng = random.Random(seed)
        out = tmp_path / f"run{seed}"
        out.mkdir()
        verdicts = ["clean", "clean", "clean", "suspicious",
                    "finding", "dormant", "error", "dark"]
        for i in range(rng.randint(20, 50)):
            verdict = rng.choice(verdicts)
            for p in range(rng.randint(1, 4)):
                row = _entry(
                    i, verdict=verdict,
                    cost_usd=rng.random() / 3,
                    body=f"{_BODY} pass {p}",
                    reused=rng.random() < 0.2 or None,
                )
                if rng.random() < 0.15:
                    row.validate_verdict = "survived"
                    row.prior_review = verdict
                if rng.random() < 0.1:
                    row.lesson = "keep"
                if rng.random() < 0.1:
                    row.provisional = True
                append_entry(out, row)
        journal = out / JOURNAL_FILENAME
        with journal.open("ab") as fh:
            fh.write(b"{torn\n")

        before_entries = load_entries(out)
        before_latest = _latest_view(out)
        before_reviewed = reviewed_set(out)
        before_spend = journal_spend_usd(out)
        before_claims = sorted(
            e.ts for e in before_entries
            if e.verdict in ("finding", "suspicious")
        )
        before_corrections = sorted(
            e.ts for e in before_entries
            if e.validate_verdict or e.lesson
        )

        compact_journal(out, supersede=True)

        after_entries = load_entries(out)
        assert _latest_view(out) == before_latest
        assert reviewed_set(out) == before_reviewed
        assert journal_spend_usd(out) == before_spend
        assert sorted(
            e.ts for e in after_entries
            if e.verdict in ("finding", "suspicious")
        ) == before_claims
        assert sorted(
            e.ts for e in after_entries
            if e.validate_verdict or e.lesson
        ) == before_corrections
        assert b"{torn" in journal.read_bytes()


class TestRemedyLine:
    def test_compact_hint_names_both_tiers(self, tmp_path: Path) -> None:
        hint = compact_hint(tmp_path)
        assert "journal compact" in hint
        assert "--supersede" in hint
        assert ".pre-supersede" in hint


class TestCli:
    def _load_cli(self):
        cli_path = str(
            Path(__file__).resolve().parents[3]
            / "libexec" / "raptor-audit",
        )
        loader = SourceFileLoader("raptor_audit_cli_supersede_test",
                                  cli_path)
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_supersede_test", loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_journal_compact_supersede_flag(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        _mega_audit_run(tmp_path, n_sites=3, n_passes=2)
        cli = self._load_cli()
        rc = cli.cmd_journal(SimpleNamespace(
            journal_command="compact",
            out_dir=str(tmp_path),
            supersede=True,
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "superseded row(s) dropped" in out
        assert "spend-carrier" in out
        assert "preserved exactly" in out
        assert (tmp_path
                / "review-journal.jsonl.pre-supersede").is_file()
