"""Unit tests for the launch-contract closure gate.

The closure itself (inventory rows, witness pins, shell routers all
matching the reviewed catalogue) used to be enforced only by the slow
pytest tier, so per-PR CI could merge an unreviewed launch site. The
gate reruns the same closure per PR; these tests pin each drift
dimension on a synthetic tree so a comparison defect cannot silently
make the gate vacuous.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO / ".github/scripts/check_launch_contracts.py"
_INVENTORY = _REPO / "core/testing/cli_launch_inventory.py"

_PROBE_TEST = (
    "import subprocess\n"
    "def test_probe(tmp_path):\n"
    "    subprocess.run(['true'], check=True)\n"
)
_PROBE_PATH = "core/testing/tests/test_probe.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location(
        "check_launch_contracts", _SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _tree(tmp_path: Path) -> tuple[Path, list[str]]:
    """Minimal tree: the real inventory module plus one launch site."""
    root = tmp_path / "root"
    inventory = root / "core/testing/cli_launch_inventory.py"
    inventory.parent.mkdir(parents=True)
    inventory.write_text(_INVENTORY.read_text(encoding="utf-8"),
                         encoding="utf-8")
    probe = root / _PROBE_PATH
    probe.parent.mkdir(parents=True)
    probe.write_text(_PROBE_TEST, encoding="utf-8")
    return root, [_PROBE_PATH]


def _catalogue_for(gate, root: Path, paths: list[str]) -> dict:
    """Derive a catalogue that exactly matches the tree's inventory."""
    mod = gate._load_inventory_module(root)
    rows = mod.inventory(root, paths)
    sites = [
        {"path": row["path"], "scope": row["scope"],
         "signature": row["signature"], "count": 1,
         "contract": "non-cli-probe", "purpose": "reviewed test probe"}
        for row in rows
    ]
    return {
        "version": 1, "note": "test catalogue", "sites": sites,
        "sources": mod.source_witnesses(root, paths, rows),
        "shell_routers": {},
    }


def _write_catalogue(root: Path, catalogue: dict) -> None:
    data = root / "core/testing/tests/data/cli_launch_contracts.json"
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_text(json.dumps(catalogue), encoding="utf-8")


def test_matching_tree_is_closed(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    assert gate.closure_failures(root, paths) == []


def test_new_launch_site_is_unclassified(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    extra = root / "core/testing/tests/test_extra.py"
    extra.write_text(_PROBE_TEST, encoding="utf-8")
    failures = gate.closure_failures(
        root, paths + ["core/testing/tests/test_extra.py"])
    assert any("unreviewed" in f and "test_extra.py" in f
               for f in failures), failures


def test_removed_launch_site_is_retired(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    (root / _PROBE_PATH).write_text("def test_probe():\n    pass\n",
                                    encoding="utf-8")
    failures = gate.closure_failures(root, paths)
    assert any("retire" in f and _PROBE_PATH in f
               for f in failures), failures


def test_witness_content_drift_is_reported(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    probe = root / _PROBE_PATH
    # A comment changes the pinned bytes but no launch-call AST, so the
    # site row still matches — only the witness sha may catch it.
    probe.write_text(probe.read_text(encoding="utf-8")
                     + "# changed environment setup\n", encoding="utf-8")
    failures = gate.closure_failures(root, paths)
    assert any("producers changed" in f and _PROBE_PATH in f
               for f in failures), failures


def test_new_witness_file_is_reported(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    conftest = root / "core/testing/tests/conftest.py"
    conftest.write_text("import os\n", encoding="utf-8")
    failures = gate.closure_failures(
        root, paths + ["core/testing/tests/conftest.py"])
    assert any("new launch environment/helper witnesses" in f
               and "conftest.py" in f for f in failures), failures


def test_shell_router_drift_is_reported(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    _write_catalogue(root, _catalogue_for(gate, root, paths))
    router = root / "bin/raptor-route"
    router.parent.mkdir(parents=True)
    router.write_text('#!/usr/bin/env bash\nexec python3 raptor.py "$@"\n',
                      encoding="utf-8")
    failures = gate.closure_failures(root, paths + ["bin/raptor-route"])
    assert any("shell routing changed" in f and "bin/raptor-route" in f
               for f in failures), failures


def test_unknown_contract_and_empty_purpose_are_rejected(gate, tmp_path) -> None:
    root, paths = _tree(tmp_path)
    catalogue = _catalogue_for(gate, root, paths)
    catalogue["sites"][0]["contract"] = "rubber-stamp"
    catalogue["sites"][-1]["purpose"] = "  "
    _write_catalogue(root, catalogue)
    failures = gate.closure_failures(root, paths)
    assert any("unknown contract 'rubber-stamp'" in f for f in failures), failures
    assert any("empty purpose" in f for f in failures), failures


def test_report_is_bounded(gate) -> None:
    items = [f"item-{i}" for i in range(gate._REPORT_LIMIT + 7)]
    line = gate._bounded(items, "label")
    assert "(+7 more)" in line
    assert "item-0" in line and f"item-{gate._REPORT_LIMIT}" not in line


def test_missing_catalogue_is_a_usage_error(gate, tmp_path, capsys) -> None:
    assert gate.main(["--root", str(tmp_path)]) == 2
    assert "no launch-contract catalogue" in capsys.readouterr().err


@pytest.mark.slow
def test_live_tree_closure_is_green(gate) -> None:
    """Mirror of the CI invocation: the checked-in catalogue must match
    the live tree exactly."""
    paths = gate.tracked_paths(_REPO)
    assert gate.closure_failures(_REPO, paths) == []
