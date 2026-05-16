"""End-to-end test: run the libexec shims against the real corpus.

Verifies the full pipeline (libexec shim → core module → CSV → metrics)
works against the committed corpus without any LLM/network dependencies.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from core.dataflow.label import VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE


_REPO_ROOT = Path(__file__).resolve().parents[3]
_LIBEXEC = _REPO_ROOT / "libexec"
_CORPUS = _REPO_ROOT / "core" / "dataflow" / "corpus" / "findings"


def _shim(name: str) -> Path:
    p = _LIBEXEC / name
    if not p.exists() or not p.is_file():
        pytest.skip(f"libexec shim missing: {p}")
    return p


def test_corpus_run_shim_produces_csv_with_one_row_per_finding(tmp_path: Path):
    out = tmp_path / "result.csv"
    rc = subprocess.call(
        [sys.executable, str(_shim("raptor-corpus-run")), "--output", str(out)]
    )
    assert rc == 0
    assert out.exists()
    rows = out.read_text().splitlines()
    expected_findings = sum(
        1 for p in _CORPUS.glob("*.json") if not p.name.endswith(".label.json")
    )
    assert len(rows) == expected_findings + 1  # +1 for header


def test_corpus_run_shim_then_metrics_shim_succeeds(tmp_path: Path):
    csv_path = tmp_path / "result.csv"
    rc = subprocess.call(
        [sys.executable, str(_shim("raptor-corpus-run")), "--output", str(csv_path)]
    )
    assert rc == 0

    proc = subprocess.run(
        [sys.executable, str(_shim("raptor-corpus-metrics")), str(csv_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "Total findings:" in out
    assert "Precision:" in out
    assert VERDICT_TRUE_POSITIVE in out or "True positives" in out
    assert VERDICT_FALSE_POSITIVE in out or "False positives" in out


def test_metrics_shim_pivot_gate_passes_on_seed_corpus(tmp_path: Path):
    """The 7-entry seed has 1 FP, all of it missing_sanitizer_model.
    Vacuous pass at 100% — documented in corpus README. Tasks #5/#6
    grow the corpus where the gate becomes meaningful."""
    csv_path = tmp_path / "result.csv"
    subprocess.check_call(
        [sys.executable, str(_shim("raptor-corpus-run")), "--output", str(csv_path)]
    )
    rc = subprocess.call(
        [sys.executable, str(_shim("raptor-corpus-metrics")),
         str(csv_path), "--check-pivot-gate"]
    )
    assert rc == 0
