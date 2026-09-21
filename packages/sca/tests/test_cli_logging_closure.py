"""Closure: every raptor-sca dispatch target installs the escaping
console formatter.

Each subcommand runs in its own libexec-dispatched process. A dispatch
target that configures no logging serves WARNING+ records through
``logging.lastResort`` — a plain formatter writing straight to stderr
— so foreign-derived relay text (Dependency-Track server HTTP error
bodies, OCI registry fetch exception text, YAMLError text quoting a
hostile suppressions file) reaches the operator TTY outside
``EscapingConsoleFormatter``. The bare-config closure scan in
core/logging cannot see a NO-config CLI (there is no basicConfig call
to flag), so the universe is enumerated here from the dispatch table
itself: every module ``_dispatch`` / ``_dispatch_fix`` routes to must
call the chokepoint (``cli._configure_logging`` or
``core.logging.configure_cli_logging``).

``agent.py`` joins the universe explicitly: it is not in the dispatch
table (it is the sandboxed subprocess entry, ``python3
packages/sca/agent.py``) but it is an independent process with the
same lastResort exposure.
"""

from __future__ import annotations

import ast
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]

# Modules dispatched in-process by cli.py itself (the analyse path is
# configured by cli._run_analyse before any work).
_IN_PROCESS = {"cli"}

# Standalone process entries outside the dispatch table.
_EXTRA_ENTRY_MODULES = {"agent"}


def _dispatch_target_modules(source: str | None = None) -> set[str]:
    """Package-relative module names imported inside _dispatch /
    _dispatch_fix (the mechanical universe — a new subcommand joins
    automatically as long as dispatch stays on import statements;
    a dynamic-dispatch spelling fails the guard below instead of
    silently shrinking the universe). ``source`` overrides the real
    cli.py for the guard's own fixtures."""
    if source is None:
        source = (_PKG / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    mods: set[str] = set()
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef)
                and fn.name in ("_dispatch", "_dispatch_fix")):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                for alias in node.names:
                    mods.add(f"{base}.{alias.name}" if base else alias.name)
            elif isinstance(node, ast.Import):
                # `import packages.sca.newmod` spelling — keep it in
                # the universe rather than letting it vanish.
                for alias in node.names:
                    name = alias.name
                    if name.startswith("packages.sca."):
                        mods.add(name.removeprefix("packages.sca."))
            elif isinstance(node, ast.Call) and (
                    (isinstance(node.func, ast.Attribute)
                     and node.func.attr == "import_module")
                    or (isinstance(node.func, ast.Name)
                        and node.func.id in ("import_module",
                                             "__import__"))):
                # Attribute AND bare-name spellings (importlib.
                # import_module / from importlib import import_module
                # / __import__) — a partial dynamic route must fail
                # loudly, not shrink the universe below the guard.
                raise AssertionError(
                    "dynamic dispatch (import_module/__import__) in "
                    "_dispatch/_dispatch_fix — this closure test "
                    "cannot enumerate it; use an import statement")
    return mods


def test_every_dispatch_target_installs_the_console_chokepoint():
    mods = (_dispatch_target_modules() - _IN_PROCESS) | _EXTRA_ENTRY_MODULES
    # Vacuousness guard: the dispatch table routes to well over a
    # dozen modules; an AST-shape drift that finds none must fail
    # loudly, not pass an empty universe.
    assert len(mods) >= 14, f"dispatch-table enumeration collapsed: {sorted(mods)}"
    offenders = []
    for mod in sorted(mods):
        path = _PKG / (mod.replace(".", "/") + ".py")
        assert path.is_file(), f"dispatch target has no module file: {mod}"
        # Substring oracle (documented): a chokepoint CALL spelling
        # anywhere in the module. A comment or shadow def could
        # satisfy it — accepted; the behavioural frida twins and the
        # writer gate's shadow arm cover that direction.
        text = path.read_text(encoding="utf-8")
        if ("_configure_logging(" not in text
                and "configure_cli_logging(" not in text):
            offenders.append(mod)
    assert not offenders, (
        "raptor-sca dispatch targets without a console-logging "
        "chokepoint (logging.lastResort would relay foreign text "
        f"raw): {offenders}"
    )


def test_dynamic_dispatch_spellings_fail_loudly():
    """Guard fixture: every dynamic-dispatch spelling must raise, not
    silently shrink the universe (the bare-name spelling empirically
    evaded the attribute-only arm)."""
    import pytest

    for planted in (
        "def _dispatch(s, argv):\n"
        "    import importlib\n"
        "    return importlib.import_module('packages.sca.x').main(argv)\n",
        "def _dispatch(s, argv):\n"
        "    from importlib import import_module\n"
        "    return import_module('packages.sca.x').main(argv)\n",
        "def _dispatch(s, argv):\n"
        "    return __import__('packages.sca.x').main(argv)\n",
    ):
        with pytest.raises(AssertionError, match="dynamic dispatch"):
            _dispatch_target_modules(planted)
    # Static import statements still enumerate.
    static = (
        "def _dispatch(s, argv):\n"
        "    from . import purl\n"
        "    import packages.sca.newmod\n"
        "    return purl.main(argv)\n"
    )
    assert _dispatch_target_modules(static) == {"purl", "newmod"}
