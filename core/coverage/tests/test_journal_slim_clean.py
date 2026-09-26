"""``journal compact --slim-clean`` — the body-offload tier.

The contract under test: a CLAIM-DOMINATED mega-audit journal —
thousands of DISTINCT latest rows, each tens of KiB of prose and
per-row domain-knowledge snapshot lists — stays over the loader's
retained-byte budget even after ``--supersede`` (nothing left to
supersede: every row is already the newest of its identity), which
permanently wedges the spend-authorizing resume. The slim tier
unwedges it by moving the surviving eligible clean/dormant rows' fat
fields to the ``review-journal-bodies.jsonl`` sidecar while

* leaving claim rows (finding/suspicious) BYTE-IDENTICAL — their
  bodies always travel inline for sweep validation and /validate;
* preserving the spend floor bit-exactly and every latest-wins
  consumer's view (latest verdict per key, reviewed-key set);
* never upgrading a row's MAC tier (authenticate-then-re-attest);
* archiving the full original as ``review-journal.jsonl.pre-slim``
  (byte-exact reversibility) while the stub + sidecar record
  reconstruct each original row's content exactly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
from core.audit.resume import journal_spend_usd
from core.coverage import journal_mac
from core.coverage.journal import (
    JOURNAL_FILENAME,
    JournalIncomplete,
    ReviewJournalEntry,
    append_entry,
    compact_hint,
    is_mechanical_echo,
    latest_entries,
    load_entries,
    load_entries_checked,
    now_iso,
    require_complete_entries,
    reviewed_set,
)
from core.coverage.journal_compact import (
    compact_journal,
    is_spend_carrier,
)
from core.coverage.journal_sidecar import (
    SIDECAR_FILENAME,
    entry_context_offloaded,
    hydrate_entry,
    reconstruct_row,
    resolve_offload,
)

#: Snapshot-list shape of a real mega-audit row: the domain model's
#: invariant IDs, repeated per row — the dominant fat field observed.
_INVARIANTS = [f"inv-buffer-{i:04d}" for i in range(220)]
_CONCEPTS = ["ownership", "pool-lifetime", "brigade"]
_BODY = "adversarial review prose, receipts and reasoning. " * 40
_HYPS = [
    {"mechanism": "index past bounds on the resize path " * 4,
     "status": "disproven", "claim": "OOB write"},
]


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
        domain_model_hash="aabbccdd",
        domain_concepts_available=list(_CONCEPTS),
        invariants_available=list(_INVARIANTS),
        hypotheses=[dict(h) for h in _HYPS],
        body=_BODY,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _claim_dominated_run(out: Path, n_clean: int = 30,
                         n_claims: int = 8) -> float:
    """Single-pass journal of DISTINCT latest rows: every row is
    already the newest of its identity, so both the lossless prune
    and the superseding tier are no-ops. Returns journaled spend."""
    spend = 0.0
    for i in range(n_clean):
        cost = 0.17 + i / 991
        spend += cost
        append_entry(out, _entry(i, cost_usd=cost,
                                 body=f"{_BODY} site {i}"))
    for i in range(n_claims):
        cost = 0.31 + i / 733
        spend += cost
        append_entry(out, _entry(
            1000 + i, verdict="suspicious" if i % 2 else "finding",
            cwe="CWE-787", cost_usd=cost,
            body=f"claim evidence prose {i} " * 30))
    return spend


def _stubs(out: Path) -> list[ReviewJournalEntry]:
    return [e for e in load_entries(out) if e.body_offload]


class TestClaimDominatedWedge:
    def test_supersede_insufficient_then_slim_unwedges(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _claim_dominated_run(tmp_path)

        # Oracles from a FULL (default-budget) load.
        full = load_entries_checked(tmp_path)
        assert full.complete
        oracle_latest = {
            k: (e.verdict, e.ts)
            for k, e in latest_entries(tmp_path).items()
            if not is_spend_carrier(e)
        }
        oracle_reviewed = reviewed_set(tmp_path)
        oracle_spend = journal_spend_usd(tmp_path)
        original = (tmp_path / JOURNAL_FILENAME).read_bytes()
        claim_lines = [
            ln for ln in original.splitlines()
            if b'"verdict":"finding"' in ln
            or b'"verdict":"suspicious"' in ln
        ]
        assert claim_lines

        budget = 96 * 1024
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", budget)

        # The wedge: superseding is a NO-OP on distinct latest rows …
        sstats = compact_journal(tmp_path, supersede=True)
        assert sstats.dropped_superseded == 0
        assert sstats.dropped_reemissions == 0
        assert sstats.bytes_after == sstats.bytes_before
        assert sstats.bytes_after > budget
        # … the loader still flags the journal incomplete …
        assert not load_entries_checked(tmp_path).complete
        # … and the spend-authorizing read refuses, naming the tier.
        with pytest.raises(JournalIncomplete) as exc:
            require_complete_entries(tmp_path)
        assert "--supersede" in str(exc.value)
        assert "--slim-clean" in str(exc.value)

        # The remedy: --slim-clean brings the journal under budget.
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows > 0
        assert stats.offloaded_bytes > 0
        assert stats.bytes_after < budget
        assert Path(stats.backup_path).name \
            == "review-journal.jsonl.pre-slim"
        assert Path(stats.backup_path).read_bytes() == original
        assert (tmp_path / SIDECAR_FILENAME).is_file()

        post = load_entries_checked(tmp_path)
        assert post.complete
        assert require_complete_entries(tmp_path)

        # Verdict views and spend floor identical to the full load.
        assert {
            k: (e.verdict, e.ts)
            for k, e in latest_entries(tmp_path).items()
            if not is_spend_carrier(e)
        } == oracle_latest
        assert reviewed_set(tmp_path) == oracle_reviewed
        assert journal_spend_usd(tmp_path) == oracle_spend

        # Claim rows are byte-identical — never slimmed.
        after = (tmp_path / JOURNAL_FILENAME).read_bytes()
        for ln in claim_lines:
            assert ln in after

    def test_slim_implies_supersede(self, tmp_path: Path) -> None:
        """Older superseded passes drop (with carriers) in the same
        --slim-clean invocation; the archive family is .pre-slim."""
        for p in range(3):
            append_entry(tmp_path, _entry(
                4, cost_usd=0.2 + p / 100, body=f"pass {p} {_BODY}"))
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.dropped_superseded == 2
        assert stats.spend_carriers == 2
        assert stats.slimmed_rows == 1
        assert ".pre-slim" in stats.backup_path
        assert journal_spend_usd(tmp_path) == stats.spend_usd_before

    def test_idempotent_second_pass(self, tmp_path: Path) -> None:
        _claim_dominated_run(tmp_path, n_clean=6, n_claims=2)
        compact_journal(tmp_path, slim_clean=True)
        first = (tmp_path / JOURNAL_FILENAME).read_bytes()
        sidecar_first = (tmp_path / SIDECAR_FILENAME).read_bytes()
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 0
        assert (tmp_path / JOURNAL_FILENAME).read_bytes() == first
        # Sidecar is append-only and untouched by the no-op pass.
        assert (tmp_path / SIDECAR_FILENAME).read_bytes() == sidecar_first


class TestEligibility:
    def test_protected_rows_never_slim(self, tmp_path: Path) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        protected = [
            _entry(1, verdict="finding", cwe="CWE-787", cost_usd=0.5),
            _entry(2, verdict="suspicious", cost_usd=0.3),
            _entry(3, validate_verdict="disproven",
                   prior_review="finding"),
            _entry(4, lesson="fp: bounded copy"),
            _entry(5, provisional=True, verdict="finding",
                   cost_usd=0.4),
            _entry(6, verdict="error"),
            _entry(7, verdict="dark", cost_usd=0.1),
            _entry(8, edge_callee="src/callee.c:helper"),
            # Consistency-census mechanical row: settled CLEAN verdict
            # whose body prefix drives is_mechanical_echo — slimming
            # it would flip the single counting/coverage rule.
            _entry(9, strategies=["consistency-census"],
                   body="[consistency: settled clean]" + _BODY),
        ]
        for e in protected:
            append_entry(tmp_path, e)
        original_lines = set(journal.read_bytes().splitlines())

        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 0
        for ln in journal.read_bytes().splitlines():
            assert ln in original_lines
        # Eager-locking cost (documented): the walk materialises the
        # sidecar file, but with zero rows slimmed it stays EMPTY —
        # readers treat absent and empty alike.
        sidecar = tmp_path / SIDECAR_FILENAME
        assert not sidecar.exists() or sidecar.stat().st_size == 0
        for e in load_entries(tmp_path):
            assert is_mechanical_echo(e) == (
                (e.body or "").startswith("[consistency:"))

    def test_min_offload_threshold_both_directions(
        self, tmp_path: Path,
    ) -> None:
        # Below the threshold: tiny fat fields stay inline.
        append_entry(tmp_path, _entry(
            1, body="short note", hypotheses=[],
            invariants_available=[], domain_concepts_available=[]))
        # Above: a multi-KiB body offloads.
        append_entry(tmp_path, _entry(2))
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 1
        stubs = _stubs(tmp_path)
        assert len(stubs) == 1
        assert stubs[0].function == "fn2"
        small = next(e for e in load_entries(tmp_path)
                     if e.function == "fn1")
        assert small.body == "short note"
        assert small.body_offload is None

    def test_dormant_rows_slim(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1, verdict="dormant"))
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 1
        assert reviewed_set(tmp_path) == {"src/f1.c:fn1"}

    def test_finding_grade_producer_rows_never_slim(
        self, tmp_path: Path,
    ) -> None:
        """/agentic and /validate producer rows (finding-grade) are
        excluded outright: the prior-claims context injection keeps
        those rows of EVERY verdict — including clean — and quotes
        their bodies as hints, so slimming one would feed an empty
        body there with no marker."""
        journal = tmp_path / JOURNAL_FILENAME
        append_entry(tmp_path, _entry(1, producer="agentic"))
        append_entry(tmp_path, _entry(2, producer="validate"))
        # Legacy pre-producer-field agentic row (machine run-id shape
        # heuristic) — same finding-grade classification, same
        # exclusion.
        append_entry(tmp_path, _entry(
            3, run_id="scan_target_20240101_120000"))
        # Control: the same shape with an audit producer slims.
        append_entry(tmp_path, _entry(4, producer="audit"))
        original_lines = set(journal.read_bytes().splitlines())

        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 1
        stubs = _stubs(tmp_path)
        assert [e.function for e in stubs] == ["fn4"]
        for ln in journal.read_bytes().splitlines():
            if b'"function":"fn4"' in ln:
                continue
            assert ln in original_lines   # byte-identical survivors


class TestStubShape:
    def test_stub_keeps_verdict_fields_and_pointer(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(3, cost_usd=0.77,
                                      duration_s=12.5, cwe=None))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        assert stub.verdict == "clean"
        assert stub.source_hash == "00000003"
        assert stub.line_start == 4 and stub.line_end == 8
        assert stub.model == "model-a"
        assert stub.strategies == ["bounds"]
        assert stub.cost_usd == 0.77
        assert stub.body == ""
        assert stub.hypotheses == []
        assert stub.invariants_available == []
        ptr = stub.body_offload
        assert ptr["sidecar"] == SIDECAR_FILENAME
        assert isinstance(ptr["offset"], int)
        assert len(ptr["sha256"]) == 64
        assert set(ptr["fields"]) == {
            "body", "hypotheses", "invariants_available",
            "domain_concepts_available",
        }
        assert entry_context_offloaded(stub)

    def test_mac_verified_row_restamps_verified(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1, cost_usd=0.2))
        (orig,) = load_entries(tmp_path)
        assert journal_mac.entry_provenance(orig) == "verified"
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        assert journal_mac.entry_provenance(stub) == "verified"

    def test_unstamped_row_slims_without_upgrade(
        self, tmp_path: Path,
    ) -> None:
        row = _entry(1).to_dict()
        row.pop("integrity", None)
        with (tmp_path / JOURNAL_FILENAME).open("ab") as fh:
            fh.write((json.dumps(row) + "\n").encode())
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 1
        (stub,) = _stubs(tmp_path)
        assert journal_mac.entry_provenance(stub) == "unstamped"
        # Content still hydrates (consistency-checked, not
        # authenticated — the tier the un-slimmed row already had).
        hydrated = hydrate_entry(tmp_path, stub)
        assert hydrated is not None and hydrated.body == _BODY

    def test_tampered_row_keeps_original_token_and_tier(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / JOURNAL_FILENAME
        row = json.loads(journal.read_bytes())
        row["verdict"] = "clean"          # unchanged value …
        row["confidence"] = 0.99          # … but edited content
        journal.write_bytes((json.dumps(row) + "\n").encode())
        (orig,) = load_entries(tmp_path)
        assert journal_mac.entry_provenance(orig) == "tampered"
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        assert journal_mac.entry_provenance(stub) == "tampered"
        assert stub.integrity == row["integrity"]


class TestSidecarIntegrity:
    def test_resolve_and_hydrate_roundtrip(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        fields = resolve_offload(tmp_path, stub)
        assert fields["body"] == _BODY
        assert fields["invariants_available"] == _INVARIANTS
        hydrated = hydrate_entry(tmp_path, stub)
        assert hydrated is not stub          # copy, never in-place
        assert stub.body == ""               # shared object untouched
        assert hydrated.body == _BODY
        assert hydrated.hypotheses == _HYPS
        assert hydrated.domain_concepts_available == _CONCEPTS

    def test_corrupted_sidecar_refuses(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        sidecar = tmp_path / SIDECAR_FILENAME
        data = sidecar.read_bytes()
        sidecar.write_bytes(data.replace(b"adversarial", b"tampered!!!"))
        assert resolve_offload(tmp_path, stub) is None
        assert hydrate_entry(tmp_path, stub) is None

    def test_missing_sidecar_refuses(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        (tmp_path / SIDECAR_FILENAME).unlink()
        assert resolve_offload(tmp_path, stub) is None
        assert hydrate_entry(tmp_path, stub) is None

    def test_wrong_typed_sidecar_fields_refuse_hydration(
        self, tmp_path: Path,
    ) -> None:
        """Behind an UNSTAMPED stub the content hash is consistency,
        not authenticity — a wrong-typed plant (str where the
        snapshot list belongs) that recomputes its own hash must
        still refuse hydration, never flow into consumers that
        set()/iterate the fields."""
        row = _entry(1).to_dict()
        row.pop("integrity", None)
        with (tmp_path / JOURNAL_FILENAME).open("ab") as fh:
            fh.write((json.dumps(row) + "\n").encode())
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        sidecar = tmp_path / SIDECAR_FILENAME
        record = json.loads(sidecar.read_bytes())
        record["fields"]["invariants_available"] = "not-a-list"
        from core.coverage.journal_sidecar import fields_sha256
        stub.body_offload["sha256"] = fields_sha256(record["fields"])
        sidecar.write_bytes((json.dumps(
            record, separators=(",", ":")) + "\n").encode())
        stub.body_offload["offset"] = 0
        assert resolve_offload(tmp_path, stub) is not None  # hash ok
        assert hydrate_entry(tmp_path, stub) is None        # type bad

    def test_forged_pointer_never_steers_the_read(
        self, tmp_path: Path,
    ) -> None:
        """The pointer's ``sidecar`` value is attacker-writable; the
        reader opens only the fixed name in the stub's own run dir."""
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        stub.body_offload["sidecar"] = "../../../etc/passwd"
        # Still resolves — against the run dir's own sidecar only.
        assert resolve_offload(tmp_path, stub) is not None
        stub.body_offload["offset"] = -5
        assert resolve_offload(tmp_path, stub) is None
        stub.body_offload["offset"] = 10**13
        assert resolve_offload(tmp_path, stub) is None

    def test_reconstruction_matches_original_and_token_verifies(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1, cost_usd=0.42))
        journal = tmp_path / JOURNAL_FILENAME
        orig_raw = json.loads(journal.read_bytes())
        compact_journal(tmp_path, slim_clean=True)
        stub_raw = json.loads(journal.read_bytes())
        with (tmp_path / SIDECAR_FILENAME).open("rb") as fh:
            fh.seek(stub_raw["body_offload"]["offset"])
            record = json.loads(fh.readline())
        recon = reconstruct_row(stub_raw, record)
        assert recon == orig_raw
        assert journal_mac.verify_row(recon, recon["integrity"])


class TestStalenessGateContract:
    """The one verdict-relevant consumer of the offloaded snapshot
    lists: reuse eligibility's context-staleness relevance diff."""

    _DOMAIN_CTX = {
        "hash": "11223344",              # differs from entries' hash
        "canonical": True,
        "concepts": {"ownership": ["bounds"],
                     "new-concept": ["bounds"]},
        "invariant_concept": {"inv-buffer-0000": "ownership"},
    }

    @staticmethod
    def _strategies(key: str, line: int) -> list[str]:
        return ["bounds"]

    def _gate(self, entry, hydrate_fn=None):
        from core.audit.gaps import _context_staleness
        return _context_staleness(
            entry, entry.key, self._DOMAIN_CTX, self._strategies,
            hydrate_fn=hydrate_fn)

    def test_hydrated_stub_matches_unslimmed_verdict(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        (orig,) = load_entries(tmp_path)
        oracle = self._gate(orig)
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        got = self._gate(
            stub, hydrate_fn=lambda e: hydrate_entry(tmp_path, e))
        assert got == oracle
        # And it is a REAL diff: the model gained 'new-concept'.
        assert got is not None
        assert "new-concept" in got

    def test_unresolvable_stub_fails_toward_re_review(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.gaps import _reuse_block_class
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        # No hydration route (project-index fold): explicit refusal.
        reason = self._gate(stub)
        assert reason is not None and reason.startswith(
            "context offloaded")
        assert _reuse_block_class(reason) == "context_offloaded"
        # Sidecar destroyed: hydration returns None → same refusal.
        (tmp_path / SIDECAR_FILENAME).unlink()
        reason = self._gate(
            stub, hydrate_fn=lambda e: hydrate_entry(tmp_path, e))
        assert reason is not None and reason.startswith(
            "context offloaded")

    def test_matching_hash_never_touches_the_sidecar(
        self, tmp_path: Path,
    ) -> None:
        """Hash-fresh entries short-circuit before the relevance
        diff — a slimmed run with an unchanged domain model keeps
        full $0 reuse even with the sidecar gone."""
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (tmp_path / SIDECAR_FILENAME).unlink()
        (stub,) = _stubs(tmp_path)
        ctx = dict(self._DOMAIN_CTX, hash="aabbccdd")
        from core.audit.gaps import _context_staleness
        assert _context_staleness(
            stub, stub.key, ctx, self._strategies) is None


class TestReusedOutcomeMarker:
    def test_reuse_emits_offload_marker_not_prose(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        compact_journal(tmp_path, slim_clean=True)
        (stub,) = _stubs(tmp_path)
        from core.audit.verdict_reuse import outcome_from_entry
        outcome = outcome_from_entry(stub)
        assert outcome.status == "clean"
        # The marker names BOTH offloaded prose surfaces: the body
        # and the hypotheses (the outcome's hypothesis line is empty
        # for the same reason).
        assert ("[body and hypotheses offloaded: "
                "review-journal-bodies.jsonl") in outcome.body
        assert outcome.hypothesis == ""
        assert _BODY not in outcome.body   # deliberately not hydrated


class TestRemedyLine:
    def test_compact_hint_names_all_three_tiers(self) -> None:
        hint = compact_hint(Path("/x/run"))
        assert "journal compact" in hint
        assert "--supersede" in hint
        assert "--slim-clean" in hint
        assert "review-journal-bodies.jsonl" in hint
        assert ".pre-slim" in hint


class TestShardInteraction:
    """Slim x journal shard set (the shard substrate rolls the
    active file; compaction walks the contiguous set per shard)."""

    @pytest.fixture
    def tiny_roll(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 8 * 1024)

    def test_multi_shard_slim_one_sidecar_per_shard_archives(
        self, tmp_path: Path, tiny_roll,
    ) -> None:
        from core.coverage.journal import journal_shard_paths
        for i in range(10):
            append_entry(tmp_path, _entry(i, cost_usd=0.2 + i / 100))
        append_entry(tmp_path, _entry(
            900, verdict="finding", cwe="CWE-787", cost_usd=0.5))
        shards = journal_shard_paths(tmp_path)
        assert len(shards) > 2                    # premise: real set
        oracle_latest = {
            k: (e.verdict, e.ts)
            for k, e in latest_entries(tmp_path).items()
        }
        oracle_reviewed = reviewed_set(tmp_path)
        oracle_spend = journal_spend_usd(tmp_path)
        originals = {p: p.read_bytes() for p in shards}

        stats = compact_journal(tmp_path, slim_clean=True)
        # Every eligible clean row slimmed, across EVERY shard (the
        # aggregation must sum, not report shard 1 only).
        assert stats.slimmed_rows == 10
        assert stats.offloaded_bytes > 0
        # ONE run-dir sidecar; every stub (whatever its shard)
        # resolves against it.
        assert (tmp_path / SIDECAR_FILENAME).is_file()
        stubs = _stubs(tmp_path)
        assert len(stubs) == 10
        for e in stubs:
            assert resolve_offload(tmp_path, e) is not None
        # Stubs live in MORE than one shard file.
        shard_with_stub = [
            p for p in shards if b'"body_offload"' in p.read_bytes()
        ]
        assert len(shard_with_stub) > 1
        # Per-shard .pre-slim archive, byte-exact each.
        for p in shards:
            backup = p.with_name(p.name + ".pre-slim")
            assert backup.is_file()
            assert backup.read_bytes() == originals[p]
            assert str(backup) in stats.backup_path
        # Views and spend floor preserved across the set.
        assert {
            k: (e.verdict, e.ts)
            for k, e in latest_entries(tmp_path).items()
        } == oracle_latest
        assert reviewed_set(tmp_path) == oracle_reviewed
        assert journal_spend_usd(tmp_path) == oracle_spend
        loaded = load_entries_checked(tmp_path)
        assert loaded.complete

    def test_cross_shard_superseded_clean_rows_slim(
        self, tmp_path: Path, tiny_roll,
    ) -> None:
        """Per-shard superseding cannot drop a non-latest clean row
        whose newer twin lives in a LATER shard — the slim tier still
        offloads its fat fields (that is where an older shard's byte
        win comes from), and latest-wins views are unchanged."""
        from core.coverage.journal import journal_shard_paths
        # Two emissions of the same identity, far enough apart in
        # bytes that they land in different shards.
        append_entry(tmp_path, _entry(1, cost_usd=0.3))
        for i in range(2, 6):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        append_entry(tmp_path, _entry(1, cost_usd=0.4))
        shards = journal_shard_paths(tmp_path)
        assert len(shards) > 1
        first, last = shards[0], shards[-1]
        assert b'"function":"fn1"' in first.read_bytes()
        assert b'"function":"fn1"' in last.read_bytes()

        stats = compact_journal(tmp_path, slim_clean=True)
        # The cross-shard pair: NEITHER emission dropped (per-shard
        # supersede keeps both), BOTH slimmed.
        assert stats.dropped_superseded == 0
        assert stats.slimmed_rows == 6
        fn1_rows = [e for e in load_entries(tmp_path)
                    if e.function == "fn1"]
        assert len(fn1_rows) == 2
        assert all(e.body_offload for e in fn1_rows)
        assert all(
            resolve_offload(tmp_path, e) is not None for e in fn1_rows)

    def test_mid_set_refusal_keeps_earlier_shards_slimmed(
        self, tmp_path: Path, tiny_roll,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A floor-check refusal on a later shard leaves earlier
        shards slimmed + archived (the shard tiers' documented
        mid-set contract) and the refused shard byte-untouched; the
        refused shard's sidecar records are inert orphans."""
        from core.coverage import journal_compact as jc
        from core.coverage.journal import journal_shard_paths
        for i in range(10):
            append_entry(tmp_path, _entry(i, cost_usd=0.2))
        shards = journal_shard_paths(tmp_path)
        assert len(shards) > 2
        originals = {p: p.read_bytes() for p in shards}

        real = jc._file_spend
        calls = {"n": 0}

        def poisoned(path: Path) -> float:
            calls["n"] += 1
            if calls["n"] >= 2:            # shard 2 onward refuses
                return -1.0
            return real(path)

        monkeypatch.setattr(jc, "_file_spend", poisoned)
        with pytest.raises(jc.CompactRefused, match="spend floor"):
            compact_journal(tmp_path, slim_clean=True)

        first, second = shards[0], shards[1]
        assert first.read_bytes() != originals[first]     # slimmed
        assert b'"body_offload"' in first.read_bytes()
        assert (first.with_name(first.name + ".pre-slim")
                .read_bytes() == originals[first])
        assert second.read_bytes() == originals[second]   # untouched
        assert not second.with_name(
            second.name + ".pre-slim").exists()
        # Shard 1's stubs still resolve (their records were synced
        # before shard 1's swap; later records are inert orphans).
        stubs = [e for e in load_entries(tmp_path) if e.body_offload]
        assert stubs
        assert all(
            resolve_offload(tmp_path, e) is not None for e in stubs)


class TestSidecarLockProbes:
    """The shared sidecar writer's locking contract under the
    per-shard-flock world: offset integrity between concurrent
    writers, the lock-ordering rule, abort/unwind release, and
    mixed-generation stub immutability."""

    def test_second_writer_blocks_then_rereads_offset_under_lock(
        self, tmp_path: Path,
    ) -> None:
        """Deterministic interleave of two writers: the second blocks
        on the sidecar flock until the first closes, then re-reads
        the size UNDER the lock — its records land after the
        first's, no overlap, no torn line."""
        import threading

        from core.coverage.journal_compact import _SidecarWriter
        w1 = _SidecarWriter(tmp_path)
        w1.open()
        off1, len1 = w1.append({"gen": 1, "n": 0, "pad": "a" * 64})
        off2, len2 = w1.append({"gen": 1, "n": 1, "pad": "b" * 64})
        assert (off1, off2) == (0, len1)

        got: dict[str, tuple[int, int]] = {}
        opened = threading.Event()

        def second() -> None:
            w2 = _SidecarWriter(tmp_path)
            w2.open()                      # blocks on w1's flock
            opened.set()
            got["r"] = w2.append({"gen": 2, "n": 0, "pad": "c" * 64})
            w2.close()

        t = threading.Thread(target=second)
        t.start()
        # The second writer must NOT get through while w1 holds the
        # lock (bounded wait — a failure here means no exclusion).
        assert not opened.wait(0.3)
        w1.close()
        t.join(timeout=10)
        assert not t.is_alive()
        # Offset re-read under the lock: w2's record starts exactly
        # where w1's appends ended.
        assert got["r"][0] == len1 + len2
        raw = (tmp_path / SIDECAR_FILENAME).read_bytes()
        assert raw.endswith(b"\n")
        lines = raw.splitlines()
        assert len(lines) == 3
        assert [json.loads(ln)["gen"] for ln in lines] == [1, 1, 2]

    def test_concurrent_slim_walks_offsets_and_stubs_hold(
        self, tmp_path: Path,
    ) -> None:
        """Two whole slim walks racing one run dir: both finish, the
        sidecar parses whole, every stub resolves, and no two
        pointers overlap byte ranges (no stub points into the other
        walk's record)."""
        import threading

        for i in range(8):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        errors: list[BaseException] = []

        def walk() -> None:
            try:
                compact_journal(tmp_path, slim_clean=True)
            except BaseException as exc:  # noqa: BLE001 — collected for assertion
                errors.append(exc)

        threads = [threading.Thread(target=walk) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not any(t.is_alive() for t in threads)
        assert not errors, errors
        raw = (tmp_path / SIDECAR_FILENAME).read_bytes()
        for ln in raw.splitlines():
            json.loads(ln)                 # no torn/interleaved line
        stubs = _stubs(tmp_path)
        assert len(stubs) == 8
        spans = []
        for e in stubs:
            assert resolve_offload(tmp_path, e) is not None
            ptr = e.body_offload
            spans.append((ptr["offset"], ptr["offset"] + ptr["bytes"]))
        spans.sort()
        for (_, end_a), (start_b, _) in zip(spans, spans[1:]):
            assert end_a <= start_b       # disjoint record ranges

    def test_lock_order_sidecar_before_any_shard_flock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Behavioral pin of the documented ordering rule: on a slim
        walk the sidecar lock is already held when the FIRST shard is
        entered (sidecar < shard_1 < …); a plain walk never takes it
        (sidecar=None all the way down)."""
        from core.coverage import journal_compact as jc
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 8 * 1024)
        for i in range(6):
            append_entry(tmp_path, _entry(i))
        real = jc._compact_one_file
        seen: list[tuple[bool, bool]] = []

        def spying(journal_path, out_dir, **kw):
            sidecar = kw.get("sidecar")
            seen.append((
                sidecar is not None,
                sidecar is not None and sidecar._fd is not None,
            ))
            return real(journal_path, out_dir, **kw)

        monkeypatch.setattr(jc, "_compact_one_file", spying)
        compact_journal(tmp_path, slim_clean=True)
        assert seen and all(
            has and locked for has, locked in seen)
        seen.clear()
        compact_journal(tmp_path)          # plain walk
        assert seen and all(
            not has and not locked for has, locked in seen)

    def test_interrupt_and_refusal_release_the_sidecar_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """KeyboardInterrupt mid-walk (after records were appended)
        and a CompactRefused floor refusal both unwind through the
        writer close: the flock is FREE afterwards, the sidecar
        carries no torn line, and the interrupted shard is
        byte-untouched."""
        import fcntl

        from core.coverage import journal_compact as jc
        for i in range(4):
            append_entry(tmp_path, _entry(i, cost_usd=0.2))
        journal = tmp_path / JOURNAL_FILENAME
        original = journal.read_bytes()

        def probe_lock_free() -> None:
            fd = os.open(
                str(tmp_path / SIDECAR_FILENAME), os.O_WRONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

        real = jc._file_spend
        monkeypatch.setattr(
            jc, "_file_spend",
            lambda p: (_ for _ in ()).throw(KeyboardInterrupt()))
        with pytest.raises(KeyboardInterrupt):
            compact_journal(tmp_path, slim_clean=True)
        probe_lock_free()                  # LOCK_NB would raise if held
        raw = (tmp_path / SIDECAR_FILENAME).read_bytes()
        assert raw.endswith(b"\n")
        for ln in raw.splitlines():
            json.loads(ln)                 # records whole, never torn
        assert journal.read_bytes() == original

        monkeypatch.setattr(jc, "_file_spend", lambda p: -1.0)
        with pytest.raises(jc.CompactRefused, match="spend floor"):
            compact_journal(tmp_path, slim_clean=True)
        probe_lock_free()
        assert journal.read_bytes() == original
        monkeypatch.setattr(jc, "_file_spend", real)
        # And the run is not wedged by the aborts: a clean pass works.
        stats = compact_journal(tmp_path, slim_clean=True)
        assert stats.slimmed_rows == 4

    def test_old_generation_stubs_never_reoffload_or_repoint(
        self, tmp_path: Path,
    ) -> None:
        """Mixed-generation pass, arm level: a later slim over a
        journal containing old-generation stubs leaves each old
        stub's LINE BYTES untouched (same pointer, no restamp churn)
        and appends NO new sidecar record for it — only the new fat
        rows offload."""
        for i in range(3):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        compact_journal(tmp_path, slim_clean=True)   # generation 1
        journal = tmp_path / JOURNAL_FILENAME
        gen1_stub_lines = [
            ln for ln in journal.read_bytes().splitlines()
            if b'"body_offload"' in ln
        ]
        assert len(gen1_stub_lines) == 3
        sidecar = tmp_path / SIDECAR_FILENAME
        gen1_records = sidecar.read_bytes()

        for i in range(10, 13):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        stats = compact_journal(tmp_path, slim_clean=True)  # gen 2
        assert stats.slimmed_rows == 3     # ONLY the new rows

        after_lines = journal.read_bytes().splitlines()
        for ln in gen1_stub_lines:         # byte-identical survivors
            assert ln in after_lines
        # Sidecar strictly extended: gen-1 records untouched at their
        # offsets, exactly 3 records appended, none for gen-1 keys.
        raw = sidecar.read_bytes()
        assert raw.startswith(gen1_records)
        new_records = [
            json.loads(ln)
            for ln in raw[len(gen1_records):].splitlines()
        ]
        assert len(new_records) == 3
        gen1_keys = {json.loads(ln)["key"]
                     for ln in gen1_records.splitlines()}
        assert not gen1_keys & {r["key"] for r in new_records}
        # Every stub of BOTH generations still resolves.
        stubs = _stubs(tmp_path)
        assert len(stubs) == 6
        for e in stubs:
            assert resolve_offload(tmp_path, e) is not None


class TestSlimSwapCacheInvalidation:
    """Slim swaps ride the same per-shard swap seam as the other
    tiers, so the loader-cache invalidation (dropped after EACH shard
    swap, set-level identity) must fire for them too — a cached
    pre-slim parse served over stub bytes would resurrect the fat
    rows the swap just removed."""

    def test_slim_swap_drops_cache_record_and_reload_sees_stubs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 8 * 1024)
        for i in range(6):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        from core.coverage.journal import journal_shard_paths
        assert len(journal_shard_paths(tmp_path)) > 1
        warm = load_entries_checked(tmp_path)     # populates the cache
        assert warm.complete
        key = os.path.realpath(tmp_path)
        assert key in journal_mod._load_cache

        compact_journal(tmp_path, slim_clean=True)
        # Direct dict inspection BEFORE any reload: the per-shard-swap
        # invalidation fired for the slim swaps (the (dev, ino)
        # identity check alone is not the mechanism under test —
        # recycled inodes defeat it).
        assert key not in journal_mod._load_cache

        served = load_entries_checked(tmp_path)
        fresh = load_entries_checked(tmp_path, fresh=True)
        assert [e.to_dict() for e in served.entries] \
            == [e.to_dict() for e in fresh.entries]
        assert sum(1 for e in served.entries if e.body_offload) == 6
        assert all(e.body == "" for e in served.entries
                   if e.body_offload)

    def test_mid_set_refusal_still_leaves_no_stale_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A refusal LATER in the set must not leave a cache record
        describing the pre-swap bytes of the shards that DID swap
        (the invalidation is per swapped shard, not end-of-walk)."""
        from core.coverage import journal_compact as jc
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 8 * 1024)
        for i in range(6):
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
        load_entries_checked(tmp_path)
        key = os.path.realpath(tmp_path)
        assert key in journal_mod._load_cache

        real = jc._file_spend
        calls = {"n": 0}

        def poisoned(path: Path) -> float:
            calls["n"] += 1
            if calls["n"] >= 2:
                return -1.0
            return real(path)

        monkeypatch.setattr(jc, "_file_spend", poisoned)
        with pytest.raises(jc.CompactRefused, match="spend floor"):
            compact_journal(tmp_path, slim_clean=True)
        assert key not in journal_mod._load_cache
        # And the next load sees shard 1's stubs, never cached fat.
        loaded = load_entries_checked(tmp_path)
        stubs = [e for e in loaded.entries if e.body_offload]
        assert stubs
        assert all(e.body == "" for e in stubs)
