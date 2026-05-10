"""Corpus integrity check — every committed finding+label pair loads,
ids match, referenced fixture paths resolve, and the snippets recorded
at each step's claimed line still match the fixture file content.

Runs against ``core/dataflow/corpus/findings/`` and is the canary that
catches drift between corpus JSON and its in-tree fixture references.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.dataflow import (
    Finding,
    GroundTruth,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CORPUS_DIR = _REPO_ROOT / "core" / "dataflow" / "corpus" / "findings"


def _finding_paths() -> list[Path]:
    return sorted(p for p in _CORPUS_DIR.glob("*.json") if not p.name.endswith(".label.json"))


def _label_path(finding_path: Path) -> Path:
    return finding_path.with_suffix(".label.json")


def _load_label(finding_path: Path) -> GroundTruth:
    return GroundTruth.from_json(_label_path(finding_path).read_text())


def _load_finding(finding_path: Path) -> Finding:
    return Finding.from_json(finding_path.read_text())


def test_corpus_dir_exists():
    assert _CORPUS_DIR.is_dir(), f"missing corpus dir: {_CORPUS_DIR}"


def test_corpus_has_at_least_seed_entries():
    assert len(_finding_paths()) >= 7, (
        "PR0 seed expects at least 7 findings; "
        "tasks #5 and #6 grow this to 50+"
    )


def test_corpus_has_both_true_and_false_positives():
    """Without at least one of each, precision/recall metrics are
    undefined. Tasks #5 and #6 grow the FP side to realistic balance."""
    verdicts = {_load_label(p).verdict for p in _finding_paths()}
    assert VERDICT_TRUE_POSITIVE in verdicts, "corpus has no TPs"
    assert VERDICT_FALSE_POSITIVE in verdicts, "corpus has no FPs"


@pytest.mark.parametrize("finding_path", _finding_paths(), ids=lambda p: p.stem)
def test_finding_loads_and_label_matches(finding_path: Path):
    finding = _load_finding(finding_path)
    label_path = _label_path(finding_path)
    assert label_path.exists(), f"missing label: {label_path}"

    label = _load_label(finding_path)
    assert finding.finding_id == label.finding_id, (
        f"id mismatch: finding {finding.finding_id} vs label {label.finding_id}"
    )


@pytest.mark.parametrize("finding_path", _finding_paths(), ids=lambda p: p.stem)
def test_finding_fixture_paths_exist(finding_path: Path):
    finding = _load_finding(finding_path)
    referenced = {finding.source.file_path, finding.sink.file_path}
    referenced.update(s.file_path for s in finding.intermediate_steps)
    for rel in referenced:
        assert (_REPO_ROOT / rel).exists(), (
            f"finding {finding.finding_id} references missing fixture: {rel}"
        )


@pytest.mark.parametrize("finding_path", _finding_paths(), ids=lambda p: p.stem)
def test_finding_snippets_match_fixture_content(finding_path: Path):
    """Every (file_path, line, snippet) triple must correspond to the
    actual content of the fixture file at that line. Catches silent
    drift when iris_e2e fixtures change upstream without corpus updates."""
    finding = _load_finding(finding_path)

    def _check(step, role: str) -> None:
        path = _REPO_ROOT / step.file_path
        lines = path.read_text().splitlines()
        assert step.line <= len(lines), (
            f"{finding.finding_id} {role}: line {step.line} > "
            f"file len {len(lines)} ({step.file_path})"
        )
        actual = lines[step.line - 1].strip()
        claimed = step.snippet.strip()
        assert claimed in actual or actual in claimed, (
            f"{finding.finding_id} {role} L{step.line} drift "
            f"({step.file_path}):\n"
            f"  claimed: {claimed!r}\n"
            f"  actual:  {actual!r}"
        )

    _check(finding.source, "source")
    _check(finding.sink, "sink")
    for i, step in enumerate(finding.intermediate_steps):
        _check(step, f"step[{i}]")


def test_corpus_finding_ids_are_unique():
    ids = [_load_finding(p).finding_id for p in _finding_paths()]
    assert len(ids) == len(set(ids)), f"duplicate finding_ids: {ids}"
