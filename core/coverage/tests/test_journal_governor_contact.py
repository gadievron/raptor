"""Composed semantics of the journal → governor escalation contact
over the merge byte ceiling, two directions:

* a FROZEN merge — the terminal refusal arm: nothing of this run left
  to shed and the document still over the ceiling — records a
  ``journal_index_over_budget`` governor escalation when the project
  carries an artifact ledger (and stays a quiet loud-refusal without
  one);
* a merge the byte ceiling resolves by DEGRADATION — oldest incoming
  identities evicted to the aggregates disclosure, the write lands —
  records NO escalation. Designed degradation is not a write failure:
  the disclosure is recorded, counts are conserved, and a re-merge at
  more headroom re-lands the evicted identities as full rows.
  Escalating on it would burn the governor's per-kind escalation
  bound on non-failures and mask a later genuine freeze.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from unittest import mock

import pytest

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    load_index_aggregates,
    load_index_full,
    merge_into_index,
    now_iso,
)
from core.engagement import ledger as ledger_mod


def _write_elf(path: Path) -> None:
    path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        + path.name.encode())


def _build_ledger(tmp_path: Path, project: Path) -> None:
    import core.binary.elf as elf_mod

    target = tmp_path / "install"
    target.mkdir()
    _write_elf(target / "alpha")
    with mock.patch.object(elf_mod, "_read_build_id",
                           lambda p: (None, None)):
        ledger_mod.build_ledger(target, project)


def _claim_row(i: int, *, ts: str | None = None,
               body_bytes: int = 900) -> dict:
    """A suspicious (claim) row — the write-boundary slim never
    touches it, so its inline body genuinely occupies index bytes."""
    return {
        "ts": ts or now_iso(), "run_id": "run-x",
        "file": f"src/g{i}.c", "function": f"gfn{i}",
        "verdict": "suspicious", "source_hash": f"h{i}",
        "schema_version": 1, "body": "x" * body_bytes,
    }


def _write_claim_run(project: Path, name: str,
                     rows: list[dict]) -> Path:
    run = project / name
    run.mkdir(parents=True)
    (run / JOURNAL_FILENAME).write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    return run


def _escalations(project: Path) -> list[dict]:
    return [
        a for a in ledger_mod.load_policy_amendments(project)
        if a.get("kind") == "escalation"
        and a.get("escalation") == "journal_index_over_budget"
    ]


def _scale(monkeypatch: pytest.MonkeyPatch,
           budget: int = 8 * 1024) -> None:
    monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", budget)


def _frozen_project(tmp_path: Path,
                    monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project whose index is over the (scaled) ceiling with
    unsheddable legacy claim rows: the next merge hits the terminal
    refusal arm on the REAL write path."""
    project = tmp_path / "project"
    project.mkdir()
    legacy = {
        f"src/g{i}.c:gfn{i}::empty:audit@0": _claim_row(i)
        for i in range(6)
    }
    journal_mod._write_index(project / INDEX_FILENAME, legacy)
    _scale(monkeypatch)  # ceiling now far below the on-disk file
    return project


class TestFrozenMergeEscalates:
    def test_terminal_refusal_records_escalation_with_ledger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project = _frozen_project(tmp_path, monkeypatch)
        _build_ledger(tmp_path, project)
        before = (project / INDEX_FILENAME).read_bytes()
        run = _write_claim_run(
            project, "run1", [_claim_row(100, body_bytes=10)])
        assert merge_into_index(project, run) == 0
        # The refusal contract is intact (on-disk bytes untouched) …
        assert (project / INDEX_FILENAME).read_bytes() == before
        # … AND the frozen merge surfaced in engagement state.
        (esc,) = _escalations(project)
        assert "over the" in esc["message"]

    def test_frozen_merge_without_ledger_stays_quiet(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project = _frozen_project(tmp_path, monkeypatch)
        run = _write_claim_run(
            project, "run1", [_claim_row(100, body_bytes=10)])
        # No raise, same refusal, and no store minted as a side
        # effect of the contact.
        assert merge_into_index(project, run) == 0
        assert not (project / ledger_mod.LEDGER_FILENAME).exists()


class TestEvictionResolvedMergeDoesNotEscalate:
    def test_degraded_but_landed_merge_records_no_escalation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _scale(monkeypatch, budget=16 * 1024)
        project = tmp_path / "project"
        project.mkdir()
        _build_ledger(tmp_path, project)
        rows = [_claim_row(i, body_bytes=1500) for i in range(8)]
        run = _write_claim_run(project, "run1", rows)
        merged = merge_into_index(project, run)
        # The ceiling fired (identities degraded, disclosure
        # recorded, counts conserved) but the merge LANDED …
        assert 0 < merged < 8
        assert merged == len(load_index_full(project))
        (record,) = load_index_aggregates(project).values()
        assert merged + record["identities"] == 8
        # … so the governor hears nothing: not a frozen merge.
        assert _escalations(project) == []

    def test_shed_all_but_landed_merge_records_no_escalation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # merged == 0 alone is NOT the escalation trigger: a run
        # whose one giant row is shed still WRITES its disclosure —
        # the index moved, nothing froze.
        _scale(monkeypatch)
        project = tmp_path / "project"
        project.mkdir()
        _build_ledger(tmp_path, project)
        seed = _write_claim_run(
            project, "seed", [_claim_row(50, body_bytes=10)])
        assert merge_into_index(project, seed) == 1
        run = _write_claim_run(
            project, "run1", [_claim_row(0, body_bytes=6_000)])
        assert merge_into_index(project, run) == 0
        (record,) = load_index_aggregates(project).values()
        assert record["identities"] == 1
        assert _escalations(project) == []
