"""One derivation of the runtime Python-source universe.

Every tree-walking oracle that means "all runtime source files" must
derive its member set here instead of growing its own root list.
Before this module, at least five oracles each hand-derived the
universe (redos idiom census, vocabulary guardrail, canonical-JSON
guardrail, miswiring detector, env-docs drift check) and the copies
drifted in both directions:

* the guardrails' repo-root-artifact skip lists carried the bare
  name ``build`` — which also matches the runtime package
  ``core/build/`` (~2k lines of build detection), silently dropping
  it from every gate that copied the list;
* root sets disagreed (with/without ``plugins/``, ``engine/``,
  ``libexec/``, repo-root entry modules), so each new root or entry
  module had to be added N times and usually was added fewer.

Universe definition (the documented contract):

* **Roots:** ``RUNTIME_ROOTS`` — the five runtime source roots —
  plus the repo-root entry modules (``raptor.py`` and siblings),
  derived from the tree per codeql_scope's doctrine (a
  hand-maintained entry-module list silently dropped new entry
  points before).
* **Python file:** ``*.py``, or an extensionless file whose shebang
  line mentions ``python`` (the libexec launchers, plugin hook
  scripts).
* **Excluded, always:** test-side dirs (``tests``, ``test``,
  ``fixtures``), interpreter/tooling artifacts (``__pycache__``,
  ``node_modules``), any dot-named dir (vendored venvs, caches), and
  ``conftest.py`` (pytest infrastructure, not runtime source).
  Repo-root junk dirs (``out/``, ``dist/``, a root ``build/``) never
  enter — the walk starts inside the runtime roots, so no name-based
  blanket skip (the ``core/build`` failure mode) is needed.
* **Excluded by default:** subsystem ``scripts/`` dirs — dev-time
  verification harnesses per the dev-tools placement doctrine. An
  oracle that audits dev tooling too passes
  ``include_dev_scripts=True``.
* **Gate-specific legitimate homes** (curated data packs, seed
  lists, corpora) are NOT this module's business: pass them via
  ``extra_excluded_parts`` so the adjudication stays declared at the
  gate that owns it.

Pinned both directions by ``.github/tests/test_runtime_file_universe.py``
(a planted runtime file appears; a planted test file does not; the
``core/build`` regression stays healed).
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

#: The runtime source roots. ``libexec`` carries the extensionless
#: launcher scripts; ``plugins`` carries hook scripts loaded by the
#: launcher at session time.
RUNTIME_ROOTS: tuple[str, ...] = (
    "core", "packages", "plugins", "engine", "libexec",
)

#: Path parts that mark a file as outside the runtime universe.
EXCLUDED_PARTS: frozenset[str] = frozenset({
    "tests", "test", "fixtures", "__pycache__", "node_modules",
})

#: Subsystem dev-tools dir name (excluded unless opted in).
DEV_SCRIPTS_PART: str = "scripts"

_SHEBANG_PROBE_BYTES = 128


def repo_root() -> Path:
    """The repository root this module is checked into."""
    return Path(__file__).resolve().parents[2]


def is_runtime_python_file(path: Path) -> bool:
    """True for ``*.py`` files and extensionless python-shebang
    scripts (the libexec/plugin-hook launcher form)."""
    if path.suffix == ".py":
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as fh:
            head = fh.read(_SHEBANG_PROBE_BYTES)
    except OSError:
        return False
    if not head.startswith(b"#!"):
        return False
    return b"python" in head.split(b"\n", 1)[0]


def _is_excluded(rel_parts: tuple[str, ...], excluded: frozenset[str]) -> bool:
    for part in rel_parts[:-1]:
        if part in excluded or part.startswith("."):
            return True
    return rel_parts[-1] == "conftest.py"


def runtime_file_universe(
    repo: Path | None = None,
    *,
    include_dev_scripts: bool = False,
    extra_excluded_parts: Iterable[str] = (),
) -> list[Path]:
    """Every runtime Python source file, derived from the tree.

    Returns sorted absolute paths: all python files (see
    :func:`is_runtime_python_file`) under :data:`RUNTIME_ROOTS` plus
    the repo-root entry modules, minus the documented exclusions
    (module docstring).

    Args:
        repo: repository root; defaults to the checkout this module
            lives in (overridable so the two-direction pin can walk a
            planted synthetic tree).
        include_dev_scripts: also yield files under subsystem
            ``scripts/`` dirs (dev-time harnesses) — for oracles
            whose invariant covers dev tooling too.
        extra_excluded_parts: gate-specific legitimate-home dir names
            (curated data packs, seeds, corpora) excluded on top of
            the standing set.
    """
    root = repo if repo is not None else repo_root()
    excluded = EXCLUDED_PARTS | frozenset(extra_excluded_parts)
    if not include_dev_scripts:
        excluded |= {DEV_SCRIPTS_PART}
    out: list[Path] = []
    for sub in RUNTIME_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if _is_excluded(rel_parts, excluded):
                continue
            if is_runtime_python_file(p):
                out.append(p)
    # Repo-root entry modules (raptor.py, raptor_agentic.py, ...),
    # derived from the tree — never a name list. conftest.py is
    # pytest infrastructure and stays out via _is_excluded.
    for p in sorted(root.glob("*.py")):
        if p.is_file() and not _is_excluded((p.name,), excluded):
            out.append(p)
    return sorted(out)
