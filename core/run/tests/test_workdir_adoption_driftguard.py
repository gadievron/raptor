"""Drift guard for the core.run.workdir adoption sweep (EDR
coexistence).

RAPTOR-executed temp artifacts — compiled harnesses, PoC stubs,
probe binaries — must be created under the canonical work family
(``dir=exec_workdir()``), not scattered across the temp root where
every execution trips the generic "ran a binary from /tmp"
endpoint-security heuristic. Same import-or-fail pinning style as
test_scratch_adoption_driftguard.py.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_WORKDIR_ADOPTERS = [
    "core/audit/dark_verify/_execute.py",
    "core/audit/dynamic_sweep.py",
    "packages/llm_analysis/exploit_verify.py",
    "packages/exploit_feasibility/analyzer.py",
    "packages/fuzzing/capability.py",
]


@pytest.mark.parametrize("rel_path", _WORKDIR_ADOPTERS)
def test_module_imports_exec_workdir(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.run\.workdir import .*\bexec_workdir\b", src,
    ), f"{rel_path} must import exec_workdir from core.run.workdir"


@pytest.mark.parametrize("rel_path", _WORKDIR_ADOPTERS)
def test_every_tempfile_factory_is_workdir_wired(rel_path):
    """Each tempfile factory call in an adopter passes
    ``dir=exec_workdir()`` (or an explicit non-tmp ``dir=``) — a new
    bare call would quietly re-grow the scattered-artifact shape."""
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for m in re.finditer(
        r"tempfile\.(NamedTemporaryFile|TemporaryDirectory|mkdtemp|mkstemp)"
        r"\s*\(",
        src,
    ):
        # Capture the balanced argument span.
        depth, i = 1, m.end()
        while depth and i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
            i += 1
        args = src[m.end():i - 1]
        assert "dir=" in args, (
            f"{rel_path}: tempfile.{m.group(1)} without dir= — executed "
            "artifacts must land under exec_workdir()"
        )


@pytest.mark.parametrize("rel_path", _WORKDIR_ADOPTERS)
def test_executed_artifacts_carry_a_raptor_prefix(rel_path):
    """Anonymous ``tmpXXXX`` names in the temp tree are not
    attributable to RAPTOR by an operator triaging an EDR alert —
    every factory call must pass a prefix."""
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for m in re.finditer(
        r"tempfile\.(NamedTemporaryFile|TemporaryDirectory|mkdtemp)\s*\(",
        src,
    ):
        depth, i = 1, m.end()
        while depth and i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
            i += 1
        args = src[m.end():i - 1]
        assert "prefix=" in args, (
            f"{rel_path}: tempfile.{m.group(1)} without prefix="
        )
