"""SARIF read-cap parity across the core/dataflow consumers.

The budget lives in ``core.sarif.parser.SARIF_MAX_BYTES``; the
corpus/bridge/pipeline loaders and ``finding_diff`` alias it. Before
the aliasing, ``finding_diff`` carried a hand-copied value that had
drifted to 128 MiB while its docstring claimed to match the parser's
policy — these tests keep the aliases from re-drifting and pin the
cap's behavior in both directions.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

import core.dataflow
from core.dataflow import finding_diff
from core.sarif.parser import SARIF_MAX_BYTES

_DATAFLOW_ROOT = Path(core.dataflow.__file__).resolve().parent


def _alias_bearing_modules() -> list[str]:
    """Mechanically derived universe: every core/dataflow module that
    spells the shared-alias name. A hand-enumerated tuple here is the
    exact re-drift hole this suite exists to close — a new consumer
    that aliases the constant joins the check automatically, and one
    that hand-types the cap is caught by the literal scan below."""
    return sorted(
        py.stem for py in _DATAFLOW_ROOT.glob("*.py")
        if "_MAX_SARIF_BYTES" in py.read_text(encoding="utf-8")
    )


def test_every_dataflow_alias_matches_the_parser_policy():
    mods = _alias_bearing_modules()
    # The five known consumers must be present (a refactor silently
    # dropping one from the alias discipline should fail loudly).
    assert {"barrier_synth", "cvefix_bridge", "cvefix_pipeline",
            "cvefix_walk", "owasp_corpus_generator"} <= set(mods)
    for name in mods:
        mod = importlib.import_module(f"core.dataflow.{name}")
        assert mod._MAX_SARIF_BYTES == SARIF_MAX_BYTES, name


def test_no_hand_typed_sarif_scale_caps_in_dataflow():
    """Any ``max_bytes=`` call-site literal in the SARIF budget scale
    (>= 10 MiB) must go through the shared alias — finding_diff once
    carried a hand-copy that drifted to 128 MiB while its docstring
    claimed parser parity."""
    literal = re.compile(r"max_bytes\s*=\s*([0-9][0-9_\s*+]*)")
    offenders: list[str] = []
    for py in _DATAFLOW_ROOT.glob("*.py"):
        for m in literal.finditer(py.read_text(encoding="utf-8")):
            expr = m.group(1).strip().rstrip("*+ ")
            try:
                value = eval(expr, {"__builtins__": {}}, {})  # noqa: S307 — arithmetic over a digit/operator-only regex capture
            except SyntaxError:
                continue
            if value >= 10 * 1024 * 1024:
                offenders.append(f"{py.name}: max_bytes={expr}")
    assert not offenders, offenders


_EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": []})


def test_diff_sarif_files_refuses_over_cap(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.sarif"
    augmented = tmp_path / "augmented.sarif"
    baseline.write_text(_EMPTY_SARIF)
    augmented.write_text(_EMPTY_SARIF)
    monkeypatch.setattr(
        finding_diff, "SARIF_MAX_BYTES", len(_EMPTY_SARIF) - 1,
    )
    with pytest.raises(RuntimeError, match="exceeds .*-byte cap"):
        finding_diff.diff_sarif_files(baseline, augmented)


def test_diff_sarif_files_accepts_under_cap(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.sarif"
    augmented = tmp_path / "augmented.sarif"
    baseline.write_text(_EMPTY_SARIF)
    augmented.write_text(_EMPTY_SARIF)
    monkeypatch.setattr(
        finding_diff, "SARIF_MAX_BYTES", len(_EMPTY_SARIF),
    )
    diff = finding_diff.diff_sarif_files(baseline, augmented)
    assert diff.baseline_count == 0
    assert diff.augmented_count == 0
