"""Drift guard for the core.run.toolprobe adoption sweep.

Pins the swept which+``--version`` call sites to the substrate
(import-or-fail style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py): each module must import ``probe`` and
must not re-grow a hand-rolled version-probe subprocess.

Deliberately NOT swept:

* ``packages/joern/prereqs.version()`` — resolves the joern launcher
  through its own multi-name which cache (joern / joern-cli) and a
  dist-jar shortcut; converting it to a by-name probe would change
  resolution semantics. Its ``_java_version`` half IS swept.
* ``packages/static-analysis/codeql/env.py`` — deleted by the
  dead-code series; the codeql version-triple target no longer
  exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_PROBE_ADOPTERS = [
    "packages/describe/tool_readiness.py",
    "core/inventory/binary_oracle_corpora/toolchain.py",
    "packages/joern/prereqs.py",
    "packages/binary_analysis/crash_analyser.py",
    # tool_version: the engine-version stamps in every completed
    # run's provenance manifest — was an exec-the-bare-name drift in
    # the chokepoint's OWN package.
    "core/run/provenance.py",
]

# A version-probe re-growth: subprocess/run_trusted invoked with a
# --version / -version argv. (joern's own --version probe is the
# declared exception — see module docstring.)
_HAND_ROLLED = re.compile(
    r"""(_run_trusted|subprocess\.run)\(\s*\n?\s*\[[^\]]*['"]-{1,2}[Vv]ersion['"]"""
)

_ALLOWED = {
    # version() keeps its own resolved-path probe by design.
    "packages/joern/prereqs.py": 1,
}


@pytest.mark.parametrize("rel_path", _PROBE_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.run\.toolprobe import .*\bprobe\b", src
    ), f"{rel_path} must import probe from core.run.toolprobe"


@pytest.mark.parametrize("rel_path", _PROBE_ADOPTERS)
def test_no_hand_rolled_version_probe(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    hits = _HAND_ROLLED.findall(src)
    allowed = _ALLOWED.get(rel_path, 0)
    assert len(hits) <= allowed, (
        f"{rel_path} re-grew a hand-rolled version probe "
        f"({len(hits)} found, {allowed} allowed); use "
        "core.run.toolprobe.probe"
    )


def test_probe_retention_is_capped(monkeypatch):
    """A hostile PATH tool can answer --version with an arbitrarily
    large stream — the retained ToolInfo streams are bounded (the
    first_line consumers never wanted the payload)."""
    import subprocess as _subprocess

    from core.run import toolprobe

    def fake_run(argv, **kwargs):
        return _subprocess.CompletedProcess(
            argv, 0, stdout="v1.0\n" + "A" * (2 * 1024 * 1024),
            stderr="B" * (2 * 1024 * 1024))

    monkeypatch.setattr(toolprobe.shutil, "which",
                        lambda name: "/usr/bin/faketool")
    monkeypatch.setattr(toolprobe.subprocess, "run", fake_run)
    info = toolprobe.probe("faketool")
    assert info is not None
    assert len(info.stdout) <= toolprobe._CAPTURE_RETAIN_CHARS
    assert len(info.stderr) <= toolprobe._CAPTURE_RETAIN_CHARS
    assert info.first_line == "v1.0"
