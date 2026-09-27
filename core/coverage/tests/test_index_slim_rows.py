"""Index-row slimming at the project-index write boundary.

The project index is a cross-run VERDICT store: the producing run
journal keeps every row whole, yet merged index rows carried the full
review prose (``body``, ``hypotheses``, the per-row domain-snapshot
lists) — ~90% of a real mega-project index's bytes — which is what
forced the per-run merge cap to stay small enough that legitimate
mega-runs overflowed into aggregates. The contract under test:
``merge_into_index`` slims eligible rows into offload stubs at the
write boundary (existing on-disk fat rows included — the merge
rewrites the whole document), while

* claim rows, corrections, mechanical echoes, edge-contract rows,
  finding-grade producer rows, and spend carriers stay byte-identical
  (the run-side slim tier's eligibility, one consumer analysis);
* MAC tiers never upgrade (authenticate-then-re-attest): verified
  rows re-stamp verified, unstamped stay unstamped, tampered stay
  tampered;
* stub-aware consumers keep working: $0 reuse renders the offload
  marker, the context-staleness gate short-circuits on a matching
  domain-model hash and refuses toward re-review otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import core.coverage.journal as journal_mod
from core.coverage import journal_mac
from core.coverage.journal import (
    INDEX_FILENAME,
    ReviewJournalEntry,
    append_entry,
    is_mechanical_echo,
    load_index,
    load_index_full,
    merge_into_index,
    now_iso,
)
from core.coverage.journal_sidecar import (
    entry_context_offloaded,
    offload_pointer,
    resolve_offload,
)

#: Snapshot-list shape of a real mega-audit row (the dominant fat
#: field observed on a live 140 MB project index).
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


def _merge(project: Path, name: str,
           *entries: ReviewJournalEntry) -> int:
    run = project / name
    run.mkdir(parents=True, exist_ok=True)
    for e in entries:
        append_entry(run, e)
    return merge_into_index(project, run)


def _index_rows(project: Path) -> dict[str, dict]:
    doc = json.loads((project / INDEX_FILENAME).read_text())
    return doc["entries"]


class TestSlimAtMerge:
    def test_fat_clean_row_merges_as_stub(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        assert _merge(project, "run1", _entry(1)) == 1

        (row,) = _index_rows(project).values()
        assert row["verdict"] == "clean"
        assert row["body"] == ""
        assert row["hypotheses"] == []
        assert row["invariants_available"] == []
        assert row["domain_concepts_available"] == []
        # Verdict/coverage/spend-relevant fields stay inline.
        assert row["source_hash"] == "00000001"
        assert row["line_start"] == 2 and row["line_end"] == 6
        assert row["model"] == "model-a"
        assert row["strategies"] == ["bounds"]
        assert row["domain_model_hash"] == "aabbccdd"
        ptr = row["body_offload"]
        assert ptr["sidecar"] == ""       # no sidecar route from here
        assert set(ptr["fields"]) == {
            "body", "hypotheses", "invariants_available",
            "domain_concepts_available",
        }
        assert len(ptr["sha256"]) == 64
        # The stub round-trips the loader (loader-valid pointer).
        (entry,) = load_index_full(project).values()
        assert offload_pointer(entry) is not None
        assert entry_context_offloaded(entry)
        # The producing RUN journal keeps the full row.
        from core.coverage.journal import load_entries
        (run_row,) = load_entries(project / "run1")
        assert run_row.body == _BODY
        assert run_row.invariants_available == _INVARIANTS

    def test_existing_fat_rows_slim_on_next_write_pass(
        self, tmp_path: Path,
    ) -> None:
        # A fat row an earlier (pre-slim) writer left on disk slims on
        # the next merge THROUGH THE SAME CHOKEPOINT — even a merge
        # that updates no entry (merged == 0) rewrites the document.
        project = tmp_path / "project"
        project.mkdir()
        fat = _entry(1, ts="2026-01-02T00:00:00.000000Z")
        journal_mod._write_index(
            project / INDEX_FILENAME, {fat.index_key: fat.to_dict()})
        assert _index_rows(project)[fat.index_key]["body"] == _BODY

        # Merge an OLDER row of the same identity: latest-wins keeps
        # the on-disk row, merged == 0, yet the slim pass fires.
        merged = _merge(project, "run2", _entry(
            1, ts="2026-01-01T00:00:00.000000Z"))
        assert merged == 0
        row = _index_rows(project)[fat.index_key]
        assert row["body"] == ""
        assert row["body_offload"]["fields"]

    def test_idempotent_second_merge(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        _merge(project, "run1", _entry(1))
        first = _index_rows(project)
        # A later merge of an unrelated tiny row leaves the stub
        # byte-identical (no re-slim, no restamp churn).
        _merge(project, "run2", _entry(
            2, body="", hypotheses=[], invariants_available=[],
            domain_concepts_available=[]))
        after = _index_rows(project)
        assert after[next(iter(first))] == first[next(iter(first))]

    def test_index_shrinks(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        entries = [_entry(i) for i in range(20)]
        _merge(project, "run1", *entries)
        on_disk = (project / INDEX_FILENAME).stat().st_size
        fat = sum(len(json.dumps({e.index_key: e.to_dict()}, indent=2))
                  for e in entries)
        assert on_disk < fat / 3


class TestEligibility:
    def test_protected_rows_never_slim(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        protected = [
            _entry(1, verdict="finding", cwe="CWE-787"),
            _entry(2, verdict="suspicious"),
            _entry(3, validate_verdict="disproven",
                   prior_review="finding"),
            _entry(4, lesson="fp: bounded copy"),
            _entry(5, provisional=True, verdict="finding"),
            _entry(6, verdict="error"),
            _entry(7, verdict="dark"),
            _entry(8, edge_callee="src/callee.c:helper"),
            _entry(9, strategies=["consistency-census"],
                   body="[consistency: settled clean]" + _BODY),
            _entry(10, producer="agentic"),
            _entry(11, producer="validate"),
            # Legacy pre-producer-field agentic row (machine run-id
            # shape): same finding-grade exclusion.
            _entry(12, run_id="scan_target_20240101_120000"),
        ]
        _merge(project, "run1", *protected)
        rows = _index_rows(project)
        assert len(rows) == len(protected)
        for row in rows.values():
            assert "body_offload" not in row
            assert row["body"], row["function"]
        # The mechanical-echo counting rule is intact on the loaded
        # view (body prefix preserved).
        echoes = [e for e in load_index_full(project).values()
                  if is_mechanical_echo(e)]
        assert [e.function for e in echoes] == ["fn9"]

    def test_min_offload_floor_both_directions(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "project"
        # Below the floor: tiny prose stays inline (the pointer would
        # cost more than it saves).
        _merge(project, "run1",
               _entry(1, body="short note", hypotheses=[],
                      invariants_available=[],
                      domain_concepts_available=[]),
               _entry(2))
        by_fn = {r["function"]: r for r in _index_rows(project).values()}
        assert by_fn["fn1"]["body"] == "short note"
        assert "body_offload" not in by_fn["fn1"]
        assert by_fn["fn2"]["body"] == ""
        assert by_fn["fn2"]["body_offload"]

    def test_dormant_rows_slim(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        _merge(project, "run1", _entry(1, verdict="dormant"))
        (row,) = _index_rows(project).values()
        assert row["verdict"] == "dormant"
        assert row["body_offload"]

    def test_run_slim_stubs_pass_through_untouched(
        self, tmp_path: Path,
    ) -> None:
        # A row the RUN-side compactor already slimmed (pointer names
        # the run sidecar) merges verbatim — never re-pointed.
        project = tmp_path / "project"
        run_ptr = {"sidecar": "review-journal-bodies.jsonl",
                   "offset": 128, "bytes": 512, "sha256": "a" * 64,
                   "fields": ["body"]}
        _merge(project, "run1", _entry(
            1, body="", hypotheses=[], invariants_available=[],
            domain_concepts_available=[], body_offload=dict(run_ptr)))
        (row,) = _index_rows(project).values()
        assert row["body_offload"] == run_ptr


class TestMacTiers:
    def test_verified_row_restamps_verified(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        append_entry(run, _entry(1))
        (orig,) = journal_mod.load_entries(run)
        assert journal_mac.entry_provenance(orig) == "verified"
        merge_into_index(project, run)
        (entry,) = load_index_full(project).values()
        assert entry.body == "" and entry.body_offload
        assert journal_mac.entry_provenance(entry) == "verified"

    def test_unstamped_row_slims_without_upgrade(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        row = _entry(1).to_dict()
        row.pop("integrity", None)
        with (run / journal_mod.JOURNAL_FILENAME).open("ab") as fh:
            fh.write((json.dumps(row) + "\n").encode())
        merge_into_index(project, run)
        (entry,) = load_index_full(project).values()
        assert entry.body == "" and entry.body_offload
        assert journal_mac.entry_provenance(entry) == "unstamped"

    def test_tampered_row_keeps_original_token_and_tier(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        append_entry(run, _entry(1))
        journal = run / journal_mod.JOURNAL_FILENAME
        row = json.loads(journal.read_bytes())
        row["confidence"] = 0.99          # edited content
        journal.write_bytes((json.dumps(row) + "\n").encode())
        merge_into_index(project, run)
        (entry,) = load_index_full(project).values()
        assert entry.body == "" and entry.body_offload
        assert journal_mac.entry_provenance(entry) == "tampered"
        assert entry.integrity == row["integrity"]

    def test_edge_rows_keep_verifying_for_edge_suppression(
        self, tmp_path: Path,
    ) -> None:
        # The edge re-review suppressor requires ROW_VERIFIED on the
        # index row; edge-contract rows are excluded from slimming so
        # their original token still covers their content verbatim.
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        append_entry(run, _entry(1, edge_callee="src/callee.c:helper"))
        merge_into_index(project, run)
        (entry,) = load_index_full(project).values()
        assert entry.edge_callee == "src/callee.c:helper"
        assert entry.body == _BODY
        assert journal_mac.entry_provenance(entry) == "verified"


class TestConsumersOnSlimRows:
    """The census-critical consumers, exercised on INDEX stubs."""

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

    def _slim_entry(self, tmp_path: Path):
        project = tmp_path / "project"
        _merge(project, "run1", _entry(1))
        (entry,) = load_index_full(project).values()
        assert entry.body_offload
        return project, entry

    def test_reuse_emits_offload_marker_not_prose(
        self, tmp_path: Path,
    ) -> None:
        _, entry = self._slim_entry(tmp_path)
        from core.audit.verdict_reuse import outcome_from_entry
        outcome = outcome_from_entry(entry)
        assert outcome.status == "clean"
        assert outcome.cost_usd == 0.0
        assert "offloaded" in outcome.body
        assert outcome.hypothesis == ""
        assert _BODY not in outcome.body

    def test_staleness_gate_fresh_on_matching_hash(
        self, tmp_path: Path,
    ) -> None:
        # The $0-reuse-preserving direction: an unchanged domain
        # model short-circuits BEFORE the offloaded lists are needed.
        _, entry = self._slim_entry(tmp_path)
        from core.audit.gaps import _context_staleness
        ctx = dict(self._DOMAIN_CTX, hash="aabbccdd")
        assert _context_staleness(
            entry, entry.key, ctx, self._strategies) is None

    def test_staleness_gate_refuses_toward_re_review_on_changed_hash(
        self, tmp_path: Path,
    ) -> None:
        # No hydration route from the project dir: a changed domain
        # model refuses the reuse explicitly (re-review, the safe
        # direction) instead of trusting absent context.
        _, entry = self._slim_entry(tmp_path)
        from core.audit.gaps import _context_staleness, _reuse_block_class
        reason = _context_staleness(
            entry, entry.key, self._DOMAIN_CTX, self._strategies)
        assert reason is not None
        assert reason.startswith("context offloaded")
        assert _reuse_block_class(reason) == "context_offloaded"

    def test_pointer_resolution_fails_safe_in_project_dir(
        self, tmp_path: Path,
    ) -> None:
        project, entry = self._slim_entry(tmp_path)
        # No sidecar exists in the project dir — resolution degrades
        # to None (consumers keep the stub view), never raises.
        assert resolve_offload(project, entry) is None

    def test_importer_coverage_screen_fields_survive(
        self, tmp_path: Path,
    ) -> None:
        # The coverage importer's screen reads verdict + the
        # mechanical-echo rule + spans off load_index rows.
        project, _ = self._slim_entry(tmp_path)
        (entry,) = load_index(project).values()
        assert entry.verdict == "clean"
        assert not is_mechanical_echo(entry)
        assert entry.line_start == 2 and entry.line_end == 6

    def test_synthesis_seeds_keep_their_reasoning(
        self, tmp_path: Path,
    ) -> None:
        # seeds_from_journal reads hypotheses[].mechanism / body off
        # verdict=="finding" index rows — never slimmed.
        project = tmp_path / "project"
        _merge(project, "run1",
               _entry(1, verdict="finding", cwe="CWE-787"), _entry(2))
        finding = next(e for e in load_index_full(project).values()
                       if e.verdict == "finding")
        assert finding.hypotheses == _HYPS
        assert finding.body == _BODY


class TestQuarantinedRowsStayWhole:
    def test_unparseable_row_never_slims(self, tmp_path: Path) -> None:
        # A row the reader quarantines (wrong-typed field) must pass
        # through the write boundary byte-identical — slimming content
        # we cannot parse would destroy evidence readers might regain.
        project = tmp_path / "project"
        project.mkdir()
        bad = _entry(1).to_dict()
        bad["strategies"] = "not-a-list"
        path = project / INDEX_FILENAME
        journal_mod._write_index(path, {"k": bad})
        _merge(project, "run1", _entry(
            2, body="", hypotheses=[], invariants_available=[],
            domain_concepts_available=[]))
        assert _index_rows(project)["k"] == bad
