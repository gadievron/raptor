"""Dispatcher route-gate callers must thread ``run_dir``.

Contract under test: every runtime call to the shared self-serve
route gates (``ensure_route_for_client``,
``ensure_route_for_model_configs``, ``ensure_inprocess_dispatcher_env``)
passes a ``run_dir`` keyword so the dispatcher's L5 audit JSONL lands
in the caller's run output directory — or the call sits on a small
allowlist with a rationale (a caller with no run directory keeps the
gate's documented in-memory fallback). Local wrappers that forward to
a gate and expose their own ``run_dir`` parameter are swept
transitively: their call sites carry the same obligation, so the
threading cannot be dropped one hop above the gate.

The census is a write-site tripwire, not a security boundary: a
literal-shape census is evadable by a determined respelling (an alias
assignment, ``functools.partial``, ``**kwargs`` forwarding). Import
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


class _ModuleCensus(NamedTuple):
    """One module's sweep result."""

    violations: list[tuple[str, str]]  # (canonical name, message)
    gate_calls: int
    wrapper_calls: int


def _census_source(source: str) -> _ModuleCensus:
    """Sweep one module. A *wrapper* is a function that has a
    ``run_dir`` parameter and calls a censused name (gates first,
    then fixpoint over wrappers-of-wrappers) — its call sites carry
    the threading obligation too. A function WITHOUT a ``run_dir``
    parameter that satisfies the gate internally (e.g. deriving the
    run dir from a config argument) ends the obligation there.
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
    return _ModuleCensus(violations, gate_calls, wrapper_calls)


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
    """
    reported: list[str] = []
    gate_total = 0
    wrapper_total = 0
    used: set[tuple[str, str]] = set()
    for rel, source in modules.items():
        try:
            census = _census_source(source)
        except SyntaxError:
            # A module the census cannot parse can only hide a gate
            # caller if it names a gate at all.
            assert not any(name in source for name in GATE_NAMES), (
                f"{rel}: names a route gate but does not parse — "
                "the census cannot sweep it")
            continue
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
