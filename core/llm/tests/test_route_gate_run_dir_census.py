"""Dispatcher route-gate callers must thread ``run_dir``.

Contract under test: every runtime call to the shared self-serve
route gates (``ensure_route_for_client``,
``ensure_route_for_model_configs``, ``ensure_inprocess_dispatcher_env``)
passes a ``run_dir`` keyword so the dispatcher's L5 audit JSONL lands
in the caller's run output directory — or the call sits on a small
allowlist with a rationale (a caller with no run directory keeps the
gate's documented in-memory fallback). Wrappers that forward to a
gate and expose their own ``run_dir`` parameter are swept
transitively: their call sites carry the same obligation, so the
threading cannot be dropped one hop above the gate. The sweep crosses
module boundaries through ``from … import`` — a compliant forwarding
wrapper factored into a shared module keeps its importers obligated
instead of ending the census's reach at the consolidation seam.
(``import module`` attribute access to a wrapper and package
``__init__`` re-export chains stay out of scope, like the other
determined respellings below.)

The census is a write-site tripwire, not a security boundary: a
literal-shape census is evadable by a determined respelling (an alias
assignment, a lambda assignment, ``functools.partial``, ``**kwargs``
forwarding). Import
aliases (``from … import <gate> as <alias>``) are NOT an escape: they
are an ordinary low-intent spelling, so the census maps each asname
back to the gate it names. The
guarded property is producer-side dev-time correctness — a new
standalone CLI reaching for the gate without threading its run
directory, the exact class this sweep closed — so an AST census over
call spellings plus the allowlist is proportionate for that risk.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The shared route gates (core.llm.dispatcher.lifecycle). All three
#: accept ``run_dir`` and own the L5 audit-log placement contract.
GATE_NAMES = frozenset({
    "ensure_route_for_client",
    "ensure_route_for_model_configs",
    "ensure_inprocess_dispatcher_env",
})

#: (repo-relative path, canonical callee name) → rationale. Every
#: entry must SUPPRESS an actual violation on every run — an entry
#: whose caller has become compliant (or vanished) is stale and fails
#: the census, so a preemptive entry for a compliant file cannot
#: silently pre-disarm the sweep for that (file, gate) pair (rot
#: guard).
ALLOWLIST: dict[tuple[str, str], str] = {
    ("libexec/raptor-llm-ask", "ensure_route_for_model_configs"):
        "free-form ask CLI: no run lifecycle and no output directory "
        "(the response goes to stdout), so the gate's documented "
        "in-memory audit fallback is the intended placement.",
}

#: Non-vacuity floors — the census must keep seeing the swept callers
#: (2 gate calls internal to lifecycle.py, checker_synthesis, the
#: audit pipeline, cve-env's provider resolution, raptor-llm-ask, the
#: standalone libexec CLIs, and core.llm.session_fallback — which
#: took over the validation helper's two former direct gate calls).
#: A new caller raises the count; the floor only guards the census
#: against going vacuous. Lower it ONLY when a caller demonstrably
#: moved behind a swept wrapper, never to paper over a dropped call.
_KNOWN_GATE_CALLS = 11
_KNOWN_WRAPPER_CALLS = 10


def _callee_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _has_run_dir_param(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = fn.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    return any(p.arg == "run_dir" for p in params)


def _gate_import_aliases(tree: ast.Module) -> dict[str, str]:
    """asname → gate for every ``from … import <gate> as <asname>``.

    Unlike an alias assignment or ``functools.partial``, an import
    alias is an ordinary spelling a well-meaning caller reaches for,
    so the census maps it back to the gate it names instead of
    letting it end the sweep.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name in GATE_NAMES and alias.asname:
                aliases[alias.asname] = alias.name
    return aliases


def _module_keys(rel: str) -> tuple[str, ...]:
    """Dotted import spellings the repo file *rel* answers to.

    core/… and the root CLIs import as their path. A packages/<dist>/
    DIST tree — the dist directory itself goes on sys.path and carries
    an inner top-level package named after the dist (the cve_env /
    cve_diff launcher shape) — is ALSO importable as that inner
    package, so it registers under both spellings. A flat
    packages/<name>/ module is importable only by its path spelling:
    registering its bare leaf name would falsely obligate importers
    of a same-named EXTERNAL module on a name collision. libexec
    scripts are not importable modules.
    """
    if not rel.endswith(".py"):
        return ()
    parts = rel[: -len(".py")].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return ()
    keys = [".".join(parts)]
    if (parts[0] == "packages" and len(parts) > 2
            and parts[2] == parts[1]):
        keys.append(".".join(parts[2:]))
    return tuple(keys)


def _imports(tree: ast.Module, rel: str) -> tuple[tuple[str, str, str], ...]:
    """(local name, source-module dotted spelling, original name) for
    every ``from X import name [as alias]`` in the module — the seam a
    shared forwarding wrapper crosses. ``from X import *`` records a
    star edge ``("*", X, "*")``; the driver treats it as importing
    every wrapper X exports, so a star import cannot silently end the
    obligation. Relative imports resolve against the importing file's
    own repo path.
    """
    pkg: list[str] | None = None
    if rel.endswith(".py"):
        parts = rel[: -len(".py")].split("/")
        pkg = parts[:-1]  # the current package (__init__ included)
    out: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            if pkg is None or node.level - 1 > len(pkg):
                continue  # not resolvable as a repo package member
            base = pkg[: len(pkg) - (node.level - 1)]
            src_parts = base + (node.module.split(".") if node.module else [])
        elif node.module is not None:
            src_parts = node.module.split(".")
        else:
            continue
        src = ".".join(src_parts)
        for alias in node.names:
            out.append((alias.asname or alias.name, src, alias.name))
    return tuple(out)


class _ModuleCensus(NamedTuple):
    """One module's sweep result."""

    violations: list[tuple[str, str]]  # (canonical name, message)
    gate_calls: int
    wrapper_calls: int
    wrappers: frozenset[str]  # wrapper names DEFINED in this module
    imports: tuple[tuple[str, str, str], ...]  # (local, src, orig)


def _census_source(
    source: str,
    *,
    rel: str = "<memory>",
    imported_wrappers: frozenset[str] = frozenset(),
) -> _ModuleCensus:
    """Sweep one module. A *wrapper* is a function that has a
    ``run_dir`` parameter and calls a censused name (gates first,
    then fixpoint over wrappers-of-wrappers) — its call sites carry
    the threading obligation too, including sites in OTHER modules
    when the driver passes the imported wrapper names back in via
    *imported_wrappers*. A function WITHOUT a ``run_dir`` parameter
    that satisfies the gate internally (e.g. deriving the run dir
    from a config argument) ends the obligation there.
    """
    tree = ast.parse(source)
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    # Censused spelling → canonical name (gates map through their
    # import aliases; wrappers are their own canonical).
    censused: dict[str, str] = {name: name for name in GATE_NAMES}
    censused.update(_gate_import_aliases(tree))
    censused.update({name: name for name in imported_wrappers})
    local_wrappers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for fn in functions:
            if fn.name in censused or not _has_run_dir_param(fn):
                continue
            calls_censused = any(
                isinstance(node, ast.Call)
                and _callee_name(node) in censused
                for node in ast.walk(fn)
            )
            if calls_censused:
                censused[fn.name] = fn.name
                local_wrappers.add(fn.name)
                changed = True

    violations: list[tuple[str, str]] = []
    gate_calls = 0
    wrapper_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee_name(node)
        if name is None or name not in censused:
            continue
        canonical = censused[name]
        if canonical in GATE_NAMES:
            gate_calls += 1
        else:
            wrapper_calls += 1
        kw = next(
            (k for k in node.keywords if k.arg == "run_dir"), None)
        # Violations carry the CANONICAL name (allowlist entries stay
        # stable however a caller spells its import); the message
        # cites the spelling at the call site.
        if kw is None:
            violations.append((canonical, (
                f"line {node.lineno}: {name}(...) without run_dir — "
                "thread the caller's run directory, or allowlist with "
                "a rationale when it genuinely has none")))
        elif isinstance(kw.value, ast.Constant) and kw.value.value is None:
            violations.append((canonical, (
                f"line {node.lineno}: {name}(run_dir=None) literal — "
                "an explicit None defeats the audit-log placement; "
                "run-dir-less callers belong on the allowlist instead")))
    return _ModuleCensus(violations, gate_calls, wrapper_calls,
                         frozenset(local_wrappers), _imports(tree, rel))


def _census_repo(
    modules: Mapping[str, str],
    allowlist: Mapping[tuple[str, str], str] = ALLOWLIST,
) -> tuple[list[str], int, int, set[tuple[str, str]]]:
    """Sweep the whole surface: (reported violations, gate-call total,
    wrapper-call total, allowlist entries that suppressed a
    violation). An entry is *used* only when it masks an actual
    violation — merely naming a censused callee in the file does not
    count, so an entry for a compliant caller reads as stale instead
    of silently disarming the census for that (file, gate) pair.
    Wrapper obligations propagate across modules via ``from … import``
    (see the fixpoint below).
    """
    censuses: dict[str, _ModuleCensus] = {}
    sources: dict[str, str] = {}
    for rel, source in modules.items():
        try:
            censuses[rel] = _census_source(source, rel=rel)
        except SyntaxError:
            # A module the census cannot parse can only hide a gate
            # caller if it names a gate at all.
            assert not any(name in source for name in GATE_NAMES), (
                f"{rel}: names a route gate but does not parse — "
                "the census cannot sweep it")
            continue
        sources[rel] = source
    # Cross-module sweep: a compliant forwarding wrapper factored
    # into a shared module keeps its ``from … import`` call sites
    # obligated. Re-census every importer with the imported wrapper
    # names in scope, to a fixpoint — wrappers-of-wrappers can chain
    # across modules. Terminates: each module's imported set is
    # monotone non-decreasing and bounded by its import count.
    exported: dict[str, set[str]] = {}
    for rel, census in censuses.items():
        for key in _module_keys(rel):
            exported.setdefault(key, set()).update(census.wrappers)
    applied: dict[str, frozenset[str]] = {}
    progressed = True
    while progressed:
        progressed = False
        for rel, census in list(censuses.items()):
            names: set[str] = set()
            for local, src, orig in census.imports:
                if orig == "*":
                    # A star edge imports every wrapper the source
                    # module exports, under their original names.
                    names.update(exported.get(src, ()))
                elif orig in exported.get(src, ()):
                    names.add(local)
            imported = frozenset(names)
            if imported == applied.get(rel, frozenset()):
                continue
            applied[rel] = imported
            census = _census_source(
                sources[rel], rel=rel, imported_wrappers=imported)
            censuses[rel] = census
            for key in _module_keys(rel):
                exported.setdefault(key, set()).update(census.wrappers)
            progressed = True
    reported: list[str] = []
    gate_total = 0
    wrapper_total = 0
    used: set[tuple[str, str]] = set()
    for rel, census in censuses.items():
        gate_total += census.gate_calls
        wrapper_total += census.wrapper_calls
        for name, msg in census.violations:
            if (rel, name) in allowlist:
                used.add((rel, name))
            else:
                reported.append(f"{rel}: {msg}")
    return reported, gate_total, wrapper_total, used


def _python_sources() -> Iterator[tuple[str, Path]]:
    """Runtime source surface: core/, packages/, libexec/ (python
    scripts by shebang), and the repo-root ``raptor*.py`` CLIs
    (raptor.py plus the raptor_* pipeline scripts it executes — all
    structural peers for gate access). Test files are excluded —
    tests legitimately exercise the gates with default placement.
    """
    for base in ("core", "packages"):
        for path in sorted((REPO_ROOT / base).rglob("*.py")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if ("/tests/" in rel or path.name.startswith("test_")
                    or path.name == "conftest.py"):
                continue
            yield rel, path
    for path in sorted((REPO_ROOT / "libexec").iterdir()):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                first = fh.readline()
        except OSError:
            continue
        if "python" not in first:
            continue
        yield path.relative_to(REPO_ROOT).as_posix(), path
    for path in sorted(REPO_ROOT.glob("raptor*.py")):
        if (not path.is_file() or path.name.startswith("test_")
                or path.name == "conftest.py"):
            continue
        yield path.name, path


class TestRouteGateRunDirCensus:
    def test_every_gate_call_threads_run_dir(self) -> None:
        modules = {
            rel: path.read_text(encoding="utf-8", errors="replace")
            for rel, path in _python_sources()
        }
        reported, gate_total, wrapper_total, used = _census_repo(modules)
        assert not reported, (
            "route-gate calls missing run_dir threading:\n  "
            + "\n  ".join(reported))
        # Non-vacuity: the census must keep seeing the swept callers.
        assert gate_total >= _KNOWN_GATE_CALLS, gate_total
        assert wrapper_total >= _KNOWN_WRAPPER_CALLS, wrapper_total
        # Rot guard: every allowlist entry must still suppress an
        # actual violation.
        stale = set(ALLOWLIST) - used
        assert not stale, f"stale allowlist entries: {sorted(stale)}"


class TestSweepSurface:
    """The repo-root sweep must cover every raptor*.py CLI (miss
    direction) and nothing else at the root (over-match direction)."""

    @staticmethod
    def _root_entries() -> set[str]:
        return {rel for rel, _ in _python_sources() if "/" not in rel}

    def test_every_root_raptor_cli_is_swept(self) -> None:
        # Independent spelling (iterdir + name checks, not glob) so a
        # sweep regression cannot hide inside a shared helper.
        on_disk = {
            path.name for path in REPO_ROOT.iterdir()
            if path.is_file() and path.name.startswith("raptor")
            and path.name.endswith(".py")
            and not path.name.startswith("test_")
        }
        assert "raptor.py" in on_disk  # root sweep must stay non-vacuous
        assert on_disk <= self._root_entries()

    def test_root_sweep_matches_only_raptor_clis(self) -> None:
        for rel in self._root_entries():
            assert rel.startswith("raptor") and rel.endswith(".py"), rel


class TestCrossModuleWrappers:
    """A compliant run_dir-forwarding wrapper factored into a shared
    module keeps its ``from … import`` call sites obligated — the
    consolidation refactor must not silently end the sweep at the
    module boundary."""

    _SHARED = (
        "def shared_boot(client, label, run_dir=None):\n"
        "    ensure_route_for_client(client, label, run_dir=run_dir)\n"
    )

    def test_imported_wrapper_call_sites_stay_obligated(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "libexec/raptor-example": (
                "from core.llm.shared import shared_boot\n"
                'shared_boot(client, "example-cli")\n'),
        }
        reported, gates, wrappers, _ = _census_repo(modules, {})
        assert gates == 1 and wrappers == 1
        assert reported and reported[0].startswith("libexec/raptor-example")

    def test_threaded_imported_wrapper_call_accepted(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "libexec/raptor-example": (
                "from core.llm.shared import shared_boot\n"
                'shared_boot(client, "example-cli", run_dir=out_dir)\n'),
        }
        reported, gates, wrappers, _ = _census_repo(modules, {})
        assert not reported and gates == 1 and wrappers == 1

    def test_imported_wrapper_asname_is_swept(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "libexec/raptor-example": (
                "from core.llm.shared import shared_boot as boot\n"
                'boot(client, "example-cli")\n'),
        }
        reported, _, _, _ = _census_repo(modules, {})
        assert reported and reported[0].startswith("libexec/raptor-example")

    def test_relative_import_is_resolved(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "core/llm/caller.py": (
                "from .shared import shared_boot\n"
                'shared_boot(client, "example-cli")\n'),
        }
        reported, _, _, _ = _census_repo(modules, {})
        assert reported and reported[0].startswith("core/llm/caller.py")

    def test_packages_inner_import_spelling_is_resolved(self) -> None:
        # packages/<dist>/ trees import as their inner top-level
        # package (cve_env.…, not packages.cve_env.cve_env.…).
        modules = {
            "packages/cve_env/cve_env/agent/core_loop.py": self._SHARED,
            "packages/cve_env/cve_env/cli.py": (
                "from cve_env.agent.core_loop import shared_boot\n"
                'shared_boot(client, "example-cli")\n'),
        }
        reported, _, _, _ = _census_repo(modules, {})
        assert reported and reported[0].startswith(
            "packages/cve_env/cve_env/cli.py")

    def test_star_imported_wrapper_call_sites_stay_obligated(self) -> None:
        # ``from X import *`` binds the wrapper just like a named
        # import — it must not silently end the obligation.
        modules = {
            "core/llm/shared.py": self._SHARED,
            "core/audit/caller.py": (
                "from core.llm.shared import *\n"
                'shared_boot(client, "star-cli")\n'),
        }
        reported, gates, wrappers, _ = _census_repo(modules, {})
        assert gates == 1 and wrappers == 1
        assert reported and reported[0].startswith("core/audit/caller.py")

    def test_threaded_star_imported_wrapper_call_accepted(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "core/audit/caller.py": (
                "from core.llm.shared import *\n"
                'shared_boot(client, "star-cli", run_dir=out_dir)\n'),
        }
        reported, gates, wrappers, _ = _census_repo(modules, {})
        assert not reported and gates == 1 and wrappers == 1

    def test_inner_spelling_registers_only_for_dist_trees(self) -> None:
        # Two-level dist tree (dist dir on sys.path, inner top-level
        # package named after the dist): both spellings register.
        assert _module_keys("packages/cve_env/cve_env/agent/core_loop.py") \
            == ("packages.cve_env.cve_env.agent.core_loop",
                "cve_env.agent.core_loop")
        # Flat packages/<name>/ module: path spelling only — no bare
        # leaf key that could falsely obligate importers of a
        # same-named external module.
        assert _module_keys("packages/scanner/agent.py") == (
            "packages.scanner.agent",)

    def test_wrapper_chain_across_modules(self) -> None:
        modules = {
            "core/llm/shared.py": self._SHARED,
            "core/llm/mid.py": (
                "from core.llm.shared import shared_boot\n"
                "def outer(client, run_dir=None):\n"
                '    shared_boot(client, "mid", run_dir=run_dir)\n'),
            "libexec/raptor-example": (
                "from core.llm.mid import outer\n"
                "outer(client)\n"),
        }
        reported, _, _, _ = _census_repo(modules, {})
        assert reported and reported[0].startswith("libexec/raptor-example")

    def test_config_deriving_shared_owner_ends_the_obligation(self) -> None:
        # A shared gate owner WITHOUT a run_dir parameter derives the
        # placement itself — importers stay free, exactly like the
        # same-module obligation-ender.
        modules = {
            "core/llm/shared.py": (
                "def build(config):\n"
                "    ensure_route_for_client(\n"
                '        config.client, "shared", run_dir=config.out_dir)\n'),
            "libexec/raptor-example": (
                "from core.llm.shared import build\n"
                "build(config)\n"),
        }
        reported, gates, wrappers, _ = _census_repo(modules, {})
        assert not reported and gates == 1 and wrappers == 0


class TestAllowlistRotGuard:
    """An allowlist entry is used only when it suppresses an actual
    violation — masking works, but a compliant or vanished caller
    leaves its entry visibly stale."""

    _ENTRY = ("libexec/raptor-example", "ensure_route_for_client")
    _ALLOW = {_ENTRY: "test rationale"}

    def test_entry_suppressing_a_violation_counts_as_used(self) -> None:
        modules = {
            "libexec/raptor-example":
                'ensure_route_for_client(client, "example-cli")\n',
        }
        reported, _, _, used = _census_repo(modules, self._ALLOW)
        assert not reported and used == {self._ENTRY}

    def test_entry_for_compliant_caller_reads_stale(self) -> None:
        # The file names and CALLS the gate, compliantly — under the
        # old seen-a-callee rule this masked future regressions; now
        # the entry is unused and the census reports it stale.
        modules = {
            "libexec/raptor-example":
                'ensure_route_for_client(client, "example-cli", '
                "run_dir=out_dir)\n",
        }
        reported, _, _, used = _census_repo(modules, self._ALLOW)
        assert not reported and not used

    def test_entry_for_vanished_caller_reads_stale(self) -> None:
        reported, _, _, used = _census_repo({}, self._ALLOW)
        assert not reported and not used


class TestCensusMechanics:
    """Mutant shapes: the census must trip on the defect spellings it
    exists to catch, and accept the threaded ones."""

    def test_trips_on_gate_call_without_run_dir(self) -> None:
        census = _census_source(
            'ensure_route_for_client(client, "some-cli")\n')
        assert census.violations and census.gate_calls == 1

    def test_trips_on_none_literal(self) -> None:
        census = _census_source(
            'ensure_route_for_client(client, "some-cli", run_dir=None)\n')
        assert census.violations

    def test_accepts_threaded_gate_call(self) -> None:
        census = _census_source(
            'ensure_route_for_client(client, "some-cli", '
            "run_dir=out_dir)\n")
        assert not census.violations and census.gate_calls == 1

    def test_trips_on_aliased_gate_import(self) -> None:
        source = (
            "from core.llm.dispatcher.lifecycle import (\n"
            "    ensure_route_for_client as _gate,\n"
            ")\n"
            '_gate(client, "some-cli")\n'
        )
        census = _census_source(source)
        assert census.violations and census.gate_calls == 1
        # Canonical name, so an allowlist entry keyed on the gate
        # matches regardless of the caller's import spelling.
        assert census.violations[0][0] == "ensure_route_for_client"

    def test_accepts_threaded_aliased_gate_call(self) -> None:
        source = (
            "from core.llm.dispatcher.lifecycle import (\n"
            "    ensure_route_for_client as _gate,\n"
            ")\n"
            '_gate(client, "some-cli", run_dir=out_dir)\n'
        )
        census = _census_source(source)
        assert not census.violations and census.gate_calls == 1

    def test_wrapper_over_aliased_gate_is_swept(self) -> None:
        source = (
            "from core.llm.dispatcher.lifecycle import (\n"
            "    ensure_route_for_client as _gate,\n"
            ")\n"
            "def _wrap(client, label, run_dir=None):\n"
            '    _gate(client, label, run_dir=run_dir)\n'
            "def main(out_dir):\n"
            '    _wrap(client, "cli")\n'
        )
        census = _census_source(source)
        assert census.gate_calls == 1 and census.wrapper_calls == 1
        assert census.violations and census.violations[0][0] == "_wrap"

    def test_wrapper_call_sites_are_swept(self) -> None:
        source = (
            "def _wrap(client, label, run_dir=None):\n"
            "    ensure_route_for_client(client, label, run_dir=run_dir)\n"
            "def main(out_dir):\n"
            '    _wrap(client, "cli")\n'
        )
        census = _census_source(source)
        assert census.gate_calls == 1 and census.wrapper_calls == 1
        assert census.violations and census.violations[0][0] == "_wrap"

    def test_threaded_wrapper_call_accepted_transitively(self) -> None:
        source = (
            "def _wrap(client, label, run_dir=None):\n"
            "    ensure_route_for_client(client, label, run_dir=run_dir)\n"
            "def _outer(client, run_dir=None):\n"
            '    _wrap(client, "cli", run_dir=run_dir)\n'
            "def main(out_dir):\n"
            '    _outer(client, run_dir=out_dir)\n'
        )
        census = _census_source(source)
        assert not census.violations and census.wrapper_calls == 2

    def test_config_deriving_owner_ends_the_obligation(self) -> None:
        # A gate owner WITHOUT a run_dir parameter that threads the
        # placement from its own argument (checker_synthesis's
        # ``_build_llm_callable`` shape): its call sites are free.
        source = (
            "def _build(config):\n"
            "    ensure_route_for_client(\n"
            '        client, "checker-synthesis", run_dir=config.out_dir)\n'
            "def caller(config):\n"
            "    _build(config)\n"
        )
        census = _census_source(source)
        assert not census.violations and census.gate_calls == 1
        assert census.wrapper_calls == 0
