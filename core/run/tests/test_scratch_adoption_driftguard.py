"""Drift guard for the core.run.scratch adoption sweep.

Pins the swept scratch-dir call sites to the substrate (import-or-fail
style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py): each direct owner imports ``scratch_dir``;
delegating callers must invoke their shared owner. Neither may re-grow a
hand-rolled ``tempfile.mkdtemp`` work area.

Consumers converted by the substrate's own wave (git_oracle,
dark_verify) are covered by their suites; this file pins the adoption
sweep on top: coccinelle's two TMPDIR clones, the compiler_sweep /
preprocessor_view / compiler_scan trio, iris' CodeQL runner,
barrier_synth's --work-dir fallback, and cc_adapter's
process-lifetime neutral cwd.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_SCRATCH_ADOPTERS = [
    "packages/coccinelle/runner.py",
    "core/audit/compiler_sweep.py",
    "core/audit/preprocessor_view.py",
    "core/detectors/compiler.py",
    "core/iris/codeql_runner.py",
    "core/dataflow/barrier_synth.py",
    "core/llm/cc_adapter.py",
    "core/inventory/perlasm.py",
    "packages/binary_analysis/radare2_understand.py",
    "packages/code_understanding/dispatch/hunt_cocci_dispatch.py",
]

# These callers pass their scratch configuration to the shared owner.
_DELEGATED_SCRATCH_ADOPTERS = {
    "packages/static-analysis/compiler_scan.py": "core.detectors.compiler",
}

_MKDTEMP = re.compile(r"\bmkdtemp\s*\(")


@pytest.mark.parametrize("rel_path", _SCRATCH_ADOPTERS)
def test_module_uses_scratch_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.run\.scratch import .*\bscratch_dir\b", src
    ), f"{rel_path} must import scratch_dir from core.run.scratch"


@pytest.mark.parametrize("rel_path", _SCRATCH_ADOPTERS + list(_DELEGATED_SCRATCH_ADOPTERS))
def test_no_hand_rolled_mkdtemp(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert not _MKDTEMP.search(src), (
        f"{rel_path} re-grew a hand-rolled tempfile.mkdtemp scratch "
        "dir; use core.run.scratch.scratch_dir"
    )


@pytest.mark.parametrize("rel_path,owner", list(_DELEGATED_SCRATCH_ADOPTERS.items()))
def test_module_delegates_to_scratch_owner(rel_path, owner):
    tree = ast.parse((REPO_ROOT / rel_path).read_text(encoding="utf-8"))
    aliases = {alias.asname or alias.name for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.module == owner
               for alias in node.names if alias.name == "run_compiler_analysis"}
    assert aliases, f"{rel_path} must import its shared compiler runner from {owner}"
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id in aliases for node in ast.walk(tree)), (
        f"{rel_path} must delegate invocation and scratch lifetime to {owner}"
    )
