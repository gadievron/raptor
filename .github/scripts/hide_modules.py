#!/usr/bin/env python3
r"""Stub-module writer: simulate absent dependencies for the PR preflight.

Bare CI installs ``requirements-dev.txt`` only, so every dependency that
ships commented out in ``requirements.txt`` (the anthropic SDK, botocore,
the tree-sitter grammar wheels, ...) is absent there — a test that
touches one must SKIP, not fail (``pytest.importorskip``, ``try/except
ImportError``, a ``skipif`` probe). Provisioned developer hosts have the
packages installed, which hides an unguarded import until it breaks a
leaner environment. ``check_optional_dep_imports.py`` lints the import
shapes statically; this helper makes the absence REAL for a test run on
any host.

Mechanism: for each module name, write ``<name>.py`` whose body raises
``ModuleNotFoundError`` into a stub directory, and prepend that directory
to ``PYTHONPATH``. The stub shadows the installed package on ``sys.path``
(PYTHONPATH entries precede site-packages), so ``import <name>`` — and
any ``import <name>.submodule`` — raises the exception a missing package
raises, and every ImportError-based guard behaves as it would on a bare
host.

Known limits: only top-level names can be hidden, and
``importlib.util.find_spec("<name>")`` finds the stub's spec, so
spec-probe availability checks (e.g. the HTTP/2 opt-in probe in
core/llm/http_pool.py) report the module as present; the simulated
failure then surfaces at the actual import instead.

Named sets:
  * ``optional-deps`` — the provider/transport dependencies whose
    consumers are written to degrade when they are absent. instructor
    is currently a pinned install, but its production imports are lazy
    and its tests guard it, so it is hidden too — coverage holds if it
    ever moves to the optional set.
  * ``tree-sitter`` — tree-sitter core + every grammar wheel, derived
    from requirements-grammars.txt at run time so a newly pinned
    grammar wheel is hidden automatically (no second list to maintain).

Usage:
    python3 .github/scripts/hide_modules.py --dest DIR \
        [--set optional-deps] [--set tree-sitter] [NAME ...]

Prints the stub directory path — the value to prepend to PYTHONPATH.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

OPTIONAL_DEP_MODULES = ("anthropic", "botocore", "instructor", "h2", "sage_sdk")

# Importable top-level module names only: dots (submodules) and dashes
# (distribution names) cannot be shadowed by a single stub file.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ``name==version`` pin at the start of a line (comments excluded).
_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==")


def tree_sitter_modules(repo_root: Path = REPO_ROOT) -> tuple[str, ...]:
    """Module names for tree-sitter core + every pinned grammar wheel.

    Derived from requirements-grammars.txt (dash-to-underscore maps the
    distribution name to the import name for every tree-sitter wheel).
    """
    req = repo_root / "requirements-grammars.txt"
    names = []
    for line in req.read_text(encoding="utf-8").splitlines():
        match = _PIN_RE.match(line.strip())
        if match:
            names.append(match.group(1).replace("-", "_"))
    if not names:
        msg = f"no ==-pinned distributions found in {req}"
        raise ValueError(msg)
    return tuple(names)


NAMED_SETS = {
    "optional-deps": lambda: OPTIONAL_DEP_MODULES,
    "tree-sitter": tree_sitter_modules,
}

_STUB_BODY = (
    "raise ModuleNotFoundError(\n"
    "    \"No module named {name!r} \"\n"
    "    \"(hidden by the CI preflight dependency simulation)\",\n"
    "    name={name!r},\n"
    ")\n"
)


def write_stubs(dest: Path, names: list[str]) -> Path:
    """Write one raising stub module per name into ``dest``.

    Names are de-duplicated; invalid (non-top-level-importable) names
    raise ``ValueError`` before anything is written.
    """
    ordered = sorted(set(names))
    bad = [n for n in ordered if not _NAME_RE.match(n)]
    if bad:
        msg = (
            f"not importable top-level module names: {bad} "
            "(hide the top-level package, not a submodule/distribution)"
        )
        raise ValueError(msg)
    dest.mkdir(parents=True, exist_ok=True)
    for name in ordered:
        body = _STUB_BODY.format(name=name)
        (dest / f"{name}.py").write_text(body, encoding="utf-8")
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write stub modules that raise ModuleNotFoundError."
    )
    parser.add_argument(
        "--dest", required=True, help="Directory to write the stubs into"
    )
    parser.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        choices=sorted(NAMED_SETS),
        help="Named module set to hide (repeatable)",
    )
    parser.add_argument(
        "names", nargs="*", help="Additional module names to hide"
    )
    args = parser.parse_args(argv)

    names = list(args.names)
    for set_name in args.sets:
        names.extend(NAMED_SETS[set_name]())
    if not names:
        parser.error("nothing to hide: pass --set and/or module names")

    try:
        dest = write_stubs(Path(args.dest), names)
    except ValueError as exc:
        parser.error(str(exc))
    print(dest.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
