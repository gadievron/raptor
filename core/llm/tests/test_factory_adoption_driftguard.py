"""Drift guard for the core.llm.factory adoption sweep.

Pins the swept factory call sites to the substrate (import-or-fail
style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py).

Deliberately NOT swept:

* ``packages/codeql/evidence_validator.py`` — constructs
  ``LLMClient()`` directly as the documented no-injection default;
  the soft-fail factory returns ``None`` where its caller expects a
  client (or the constructor's own failure).
* The direct ``LLMClient(config)`` constructions across
  core/audit and packages (agent, orchestrator, crash_agent,
  barrier_synth, ...) — config injection, not factories; the audit
  pipeline's budget-capped builder stays separate per the factory's
  own docstring.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_FACTORY_ADOPTERS = [
    "raptor_codeql.py",
    "raptor_fuzzing.py",
    "packages/web/scanner.py",
    "packages/sca/llm/__init__.py",
]


@pytest.mark.parametrize("rel_path", _FACTORY_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.llm\.factory import .*\bget_client\b", src
    ), f"{rel_path} must import get_client from core.llm.factory"


def test_no_legacy_get_client_import_outside_shim():
    """The packages.llm_analysis re-export exists for compatibility;
    non-test production modules must import the core home."""
    offenders = []
    for base in ("core", "packages"):
        for py in (REPO_ROOT / base).rglob("*.py"):
            rel = py.relative_to(REPO_ROOT).as_posix()
            if "/tests/" in rel or rel.endswith("__init__.py"):
                continue
            src = py.read_text(encoding="utf-8", errors="replace")
            if re.search(
                r"from packages\.llm_analysis import .*\bget_client\b",
                src,
            ):
                offenders.append(rel)
    assert not offenders, (
        f"legacy get_client import spelling re-appeared in {offenders}; "
        "import from core.llm.factory"
    )
