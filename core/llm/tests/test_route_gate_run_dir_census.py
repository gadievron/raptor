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
assignment, ``functools.partial``, ``**kwargs`` forwarding). The
guarded property is producer-side dev-time correctness — a new
standalone CLI reaching for the gate without threading its run
directory, the exact class this sweep closed — so an AST census over
call spellings plus the allowlist is proportionate for that risk.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The shared route gates (core.llm.dispatcher.lifecycle). All three
#: accept ``run_dir`` and own the L5 audit-log placement contract.
GATE_NAMES = frozenset({
    "ensure_route_for_client",
    "ensure_route_for_model_configs",
    "ensure_inprocess_dispatcher_env",
})

#: (repo-relative path, callee name) → rationale. Every entry must be
#: exercised by the scan — a stale entry fails the census (rot guard).
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


def _census_source(
    source: str,
) -> tuple[list[tuple[str, str]], int, int, set[str]]:
    """Sweep one module: (violations, gate-call count, wrapper-call
    count, callee names seen). A *wrapper* is a function that has a
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

    censused: set[str] = set(GATE_NAMES)
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
                censused.add(fn.name)
                changed = True

    violations: list[tuple[str, str]] = []
    gate_calls = 0
    wrapper_calls = 0
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee_name(node)
        if name not in censused:
            continue
        seen.add(name)
        if name in GATE_NAMES:
            gate_calls += 1
        else:
            wrapper_calls += 1
        kw = next(
            (k for k in node.keywords if k.arg == "run_dir"), None)
        if kw is None:
            violations.append((name, (
                f"line {node.lineno}: {name}(...) without run_dir — "
                "thread the caller's run directory, or allowlist with "
                "a rationale when it genuinely has none")))
        elif isinstance(kw.value, ast.Constant) and kw.value.value is None:
            violations.append((name, (
                f"line {node.lineno}: {name}(run_dir=None) literal — "
                "an explicit None defeats the audit-log placement; "
                "run-dir-less callers belong on the allowlist instead")))
    return violations, gate_calls, wrapper_calls, seen


def _python_sources() -> Iterator[tuple[str, Path]]:
    """Runtime source surface: core/, packages/, libexec/ (python
    scripts by shebang), raptor.py. Test files are excluded — tests
    legitimately exercise the gates with default placement.
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
    yield "raptor.py", REPO_ROOT / "raptor.py"


class TestRouteGateRunDirCensus:
    def test_every_gate_call_threads_run_dir(self) -> None:
        all_violations: list[str] = []
        gate_total = 0
        wrapper_total = 0
        used_allowlist: set[tuple[str, str]] = set()
        for rel, path in _python_sources():
            source = path.read_text(encoding="utf-8", errors="replace")
            try:
                violations, gates, wrappers, seen = _census_source(source)
            except SyntaxError:
                # A module the census cannot parse can only hide a gate
                # caller if it names a gate at all.
                assert not any(name in source for name in GATE_NAMES), (
                    f"{rel}: names a route gate but does not parse — "
                    "the census cannot sweep it")
                continue
            gate_total += gates
            wrapper_total += wrappers
            for name in seen:
                if (rel, name) in ALLOWLIST:
                    used_allowlist.add((rel, name))
            allowed = {name for (p, name) in ALLOWLIST if p == rel}
            all_violations.extend(
                f"{rel}: {msg}" for name, msg in violations
                if name not in allowed
            )
        assert not all_violations, (
            "route-gate calls missing run_dir threading:\n  "
            + "\n  ".join(all_violations))
        # Non-vacuity: the census must keep seeing the swept callers.
        assert gate_total >= _KNOWN_GATE_CALLS, gate_total
        assert wrapper_total >= _KNOWN_WRAPPER_CALLS, wrapper_total
        # Rot guard: every allowlist entry must still match a caller.
        stale = set(ALLOWLIST) - used_allowlist
        assert not stale, f"stale allowlist entries: {sorted(stale)}"


class TestCensusMechanics:
    """Mutant shapes: the census must trip on the defect spellings it
    exists to catch, and accept the threaded ones."""

    def test_trips_on_gate_call_without_run_dir(self) -> None:
        violations, gates, _, _ = _census_source(
            'ensure_route_for_client(client, "some-cli")\n')
        assert violations and gates == 1

    def test_trips_on_none_literal(self) -> None:
        violations, _, _, _ = _census_source(
            'ensure_route_for_client(client, "some-cli", run_dir=None)\n')
        assert violations

    def test_accepts_threaded_gate_call(self) -> None:
        violations, gates, _, _ = _census_source(
            'ensure_route_for_client(client, "some-cli", '
            "run_dir=out_dir)\n")
        assert not violations and gates == 1

    def test_wrapper_call_sites_are_swept(self) -> None:
        source = (
            "def _wrap(client, label, run_dir=None):\n"
            "    ensure_route_for_client(client, label, run_dir=run_dir)\n"
            "def main(out_dir):\n"
            '    _wrap(client, "cli")\n'
        )
        violations, gates, wrappers, _ = _census_source(source)
        assert gates == 1 and wrappers == 1
        assert violations and violations[0][0] == "_wrap"

    def test_threaded_wrapper_call_accepted_transitively(self) -> None:
        source = (
            "def _wrap(client, label, run_dir=None):\n"
            "    ensure_route_for_client(client, label, run_dir=run_dir)\n"
            "def _outer(client, run_dir=None):\n"
            '    _wrap(client, "cli", run_dir=run_dir)\n'
            "def main(out_dir):\n"
            '    _outer(client, run_dir=out_dir)\n'
        )
        violations, _, wrappers, _ = _census_source(source)
        assert not violations and wrappers == 2

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
        violations, gates, wrappers, _ = _census_source(source)
        assert not violations and gates == 1 and wrappers == 0
