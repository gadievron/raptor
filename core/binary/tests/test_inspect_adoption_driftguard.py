"""Drift guard for the core.binary.inspect adoption sweep.

Pins the swept binutils invocations to the sandboxed substrate
(import-or-fail style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py): the consumers must import the inspect
wrappers and must not re-grow raw ``run_trusted`` invocations of the
allowlisted read-only inspection tools against target binaries.

The no-raw-invocation sweep derives its universe MECHANICALLY (every
tracked ``*.py`` plus the ``libexec/`` launchers) rather than from a
hand-picked file list: a positive list decays exactly like the three
pre-chokepoint families the substrate's docstring documents — a new
consumer of the retired idiom anywhere else would pass CI silently.
Exemptions are hit-count pins, never file-level blindness: an
exempted file's match count must EQUAL its budget, so a real second
invocation added there (or the documented occurrence going away)
fails until this file is consciously edited.

Deliberately NOT swept (named, budgeted, or out-of-alternation):

* ``core/analysis/binary_oracle*`` — corpus-precision-validated;
  keeps its own ``_run``/``_stream`` per the substrate's docstring.
  Pinned below: it must NOT silently start importing the substrate.
* ``core/sandbox/__init__.py`` — its module docstring quotes ONE
  ``run_trusted(["readelf", ...])`` example as documentation text,
  not an invocation (budget pinned to exactly 1). The example
  predates the substrate and its rewrite is owned with the sandbox
  module itself.
* test directories — fixtures legitimately spell the retired idiom.
* crash_analyser's ``addr2line`` call and the macOS ``otool`` calls
  are outside the sweep by construction: neither tool is in the
  regex's allowlisted-tool alternation (addr2line's operand order
  needs a substrate extension first; otool is a documented
  darwin-only seam).
* analyzer.py's ``ldd`` (executes the loader), ``ROPgadget`` /
  one_gadget (not read-only binutils) and ``uname`` (host probe) —
  also outside the alternation.

Known limits of the regex sweep (accepted, documented): argv[0] must
be a LITERAL quoted tool name — a variable-argv
``run_trusted([tool_var, ...])`` over an inspection tool is outside
the pattern (the one such loop, the fuzz orchestrator's nm/strings
probe, was converted to the substrate alongside this guard); and the
``git ls-files`` universe sees only tracked files, which is exactly
CI's view of a PR.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_INSPECT_ADOPTERS = [
    "packages/binary_analysis/crash_analyser.py",
    "packages/exploit_feasibility/analyzer.py",
    "packages/exploit_feasibility/constants.py",
]

# Files where the pattern occurs as documentation or sanctioned text.
# Values are EXACT expected match counts — growth (a real invocation
# added beside the documented one) and shrinkage (the documented
# occurrence rewritten) both fail until this pin is consciously
# edited. Keep each entry justified in the module docstring.
_EXEMPTED_HIT_BUDGET: dict[str, int] = {
    "core/sandbox/__init__.py": 1,   # module-docstring example
}

# A re-grown raw invocation: run_trusted/_run_trusted with an
# allowlisted inspection tool as argv[0].
_HAND_ROLLED = re.compile(
    r"""_?run_trusted\(\s*\n?\s*\[\s*['"](readelf|nm|objdump|strings|"""
    r"""c\+\+filt|file)['"]"""
)


def _tracked_python_universe() -> list[Path]:
    """Every tracked *.py file plus the libexec launchers.

    ``git ls-files`` when available (tracked view — build junk and
    scratch dirs excluded by construction); falls back to a pruned
    rglob so the guard still runs outside a git checkout.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files",
             "*.py", "libexec/"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        names = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    except (OSError, subprocess.SubprocessError):
        names = []
    if names:
        files = [REPO_ROOT / name for name in names]
    else:                                          # pragma: no cover
        pruned = {".git", "out", ".out", "node_modules", "__pycache__",
                  ".venv", "venv"}
        files = [
            p for p in REPO_ROOT.rglob("*.py")
            if not (pruned & set(p.relative_to(REPO_ROOT).parts))
        ]
        files += [p for p in (REPO_ROOT / "libexec").glob("*")
                  if p.is_file()]
    return [
        p for p in files
        if p.is_file()
        and "tests" not in p.relative_to(REPO_ROOT).parts
    ]


@pytest.mark.parametrize("rel_path", _INSPECT_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "from core.binary.inspect import" in src, (
        f"{rel_path} must route binutils inspection through "
        "core.binary.inspect"
    )


def test_pattern_still_catches_the_retired_idiom():
    """Regex-rot guard: a sweep whose pattern silently stopped
    matching the canonical raw invocation is vacuously green."""
    canonical = 'run_trusted(\n    ["readelf", "-h", str(binary)],'
    assert _HAND_ROLLED.search(canonical)
    assert _HAND_ROLLED.search('_run_trusted(["nm", path])')


def test_universe_is_mechanical_not_hand_picked():
    """The sweep must cover the whole runtime surface — spot-pin a
    few files a hand-picked list historically missed."""
    universe = {str(p.relative_to(REPO_ROOT))
                for p in _tracked_python_universe()}
    for expected in (
        "packages/binary_analysis/macho.py",
        "packages/binary_analysis/pipeline.py",
        "core/binary/fingerprint.py",
        "core/analysis/binary_oracle.py",
        "core/sandbox/__init__.py",   # budgeted files ARE swept
    ):
        assert expected in universe, f"{expected} missing from sweep"
    assert len(universe) > 500, "universe suspiciously small"


def test_no_raw_binutils_invocation_tree_wide():
    offenders: dict[str, object] = {}
    for path in _tracked_python_universe():
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = _HAND_ROLLED.findall(src)
        rel = str(path.relative_to(REPO_ROOT))
        budget = _EXEMPTED_HIT_BUDGET.get(rel)
        if budget is not None:
            if len(hits) != budget:
                offenders[rel] = (
                    f"expected exactly {budget} documented "
                    f"occurrence(s), found {len(hits)} — a new raw "
                    "invocation beside the documented one, or a stale "
                    "exemption pin"
                )
        elif hits:
            offenders[rel] = hits
    assert not offenders, (
        f"raw run_trusted binutils invocations re-grew: {offenders}; "
        "route them through core.binary.inspect (or add a justified "
        "hit-count pin)"
    )


def test_binary_oracle_stays_independent():
    """The oracle keeps its own corpus-validated execution path; a
    silent convergence would invalidate its precision claims."""
    for py in (REPO_ROOT / "core" / "analysis").glob("binary_oracle*.py"):
        src = py.read_text(encoding="utf-8")
        assert "core.binary.inspect" not in src, (
            f"{py.name} must not import core.binary.inspect (see "
            "substrate docstring — the oracle is the template, not a "
            "consumer)"
        )
