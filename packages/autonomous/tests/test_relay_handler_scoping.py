"""raptor_agentic.py error-relay handlers must survive their own error paths.

``main()``'s degrade/refusal handlers relay exception text through
``sanitise_for_terminal``. A branch-local ``from ... import`` anywhere in
``main()`` makes that name function-local for the WHOLE function, so every
handler outside the importing branch raises ``UnboundLocalError`` exactly
when its error path fires — the designed "continue anyway" / clean-refusal
behaviour becomes a run-killing crash, invisible on the happy path.

Two layers:

* Structural: symtable proves the sanitiser is module-global (not local in
  any function), and an AST sweep rejects ANY name that is bound only by
  branch-nested imports yet consumed in other branches of the same
  function (the general never-armed-binding shape, with the guarded
  ``try/except ImportError`` optional-dependency idiom exempted).
* Live: each relay handler's error path is actually exercised — a fault is
  injected at the module seam its ``try`` block calls, ``main()`` is
  driven with real CLI arguments, and the test asserts the DESIGNED
  outcome (degrade message + run continues, or clean refusal + exit 1)
  instead of a crash. These are the landing tests the original relay
  burn-down lacked: they fail with ``UnboundLocalError`` on the broken
  scoping.
"""

from __future__ import annotations

import ast
import contextlib
import io
import os
import shutil
import subprocess
import symtable
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import pytest

# parents[3] climbs:
#   [0] packages/autonomous/tests/
#   [1] packages/autonomous/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_AGENTIC = REPO_ROOT / "raptor_agentic.py"

GIT = shutil.which("git")


def _guarded_by_import_error(node: ast.stmt, parents: dict[int, ast.AST]) -> bool:
    """True when ``node`` sits in a ``try`` that names ImportError.

    The optional-dependency idiom — ``try: from x import y / except
    ImportError: y_fallback`` — is the one legitimate shape for a nested
    import whose name is consumed elsewhere: the except arm establishes
    the guard the later use checks. Only an EXPLICIT
    ImportError/ModuleNotFoundError handler qualifies; a broad
    ``except Exception`` is not a scoping guard.
    """
    cur: ast.AST = node
    while id(cur) in parents:
        cur = parents[id(cur)]
        if isinstance(cur, ast.Try):
            for handler in cur.handlers:
                names: list[ast.expr] = []
                if isinstance(handler.type, ast.Tuple):
                    names = list(handler.type.elts)
                elif handler.type is not None:
                    names = [handler.type]
                for expr in names:
                    if isinstance(expr, ast.Name) and expr.id in (
                            "ImportError", "ModuleNotFoundError"):
                        return True
    return False


def _cross_branch_nested_import_uses(fn: ast.FunctionDef) -> list[str]:
    """Names bound only by branch-nested imports but used cross-branch.

    Granularity is the function's top-level statement blocks: a use in
    the same top-level statement as its import is assumed dominated by
    it (this file's job is the cross-branch shape, where the binding
    provably cannot arm the use).
    """
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(fn):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    def block_of(node: ast.AST) -> ast.AST | None:
        cur = node
        while id(cur) in parents:
            up = parents[id(cur)]
            if up is fn:
                return cur
            cur = up
        return None

    nested_imports: dict[str, list[ast.stmt]] = {}
    toplevel_bound: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bound = [a.asname or a.name.split(".")[0] for a in node.names]
            if parents.get(id(node)) is fn:
                toplevel_bound.update(bound)
                continue
            if _guarded_by_import_error(node, parents):
                continue
            for name in bound:
                nested_imports.setdefault(name, []).append(node)

    other_bound: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            other_bound.add(node.id)
        if isinstance(node, ast.ExceptHandler) and node.name:
            other_bound.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn:
            other_bound.add(node.name)
    arg_names = {
        a.arg
        for a in (
            fn.args.args + fn.args.posonlyargs + fn.args.kwonlyargs
            + ([fn.args.vararg] if fn.args.vararg else [])
            + ([fn.args.kwarg] if fn.args.kwarg else [])
        )
    }

    offences: list[str] = []
    for name, imports in nested_imports.items():
        if name in toplevel_bound or name in other_bound or name in arg_names:
            continue
        import_blocks = {id(block_of(imp)) for imp in imports}
        bad_uses = [
            node.lineno
            for node in ast.walk(fn)
            if isinstance(node, ast.Name) and node.id == name
            and isinstance(node.ctx, ast.Load)
            and id(block_of(node)) not in import_blocks
        ]
        if bad_uses:
            offences.append(
                f"{fn.name}:{fn.lineno} binds {name!r} only via branch-local "
                f"import(s) at line(s) {sorted(i.lineno for i in imports)} but "
                f"uses it cross-branch at line(s) {sorted(bad_uses)} — the "
                "binding never arms those uses; import at module (or "
                "function-top) level instead",
            )
    return offences


class RelayScopingStructuralTests(unittest.TestCase):
    """The sanitiser name is global; no never-armed nested-import bindings."""

    def test_sanitiser_is_module_global_never_function_local(self):
        source = RAPTOR_AGENTIC.read_text(encoding="utf-8")
        table = symtable.symtable(source, str(RAPTOR_AGENTIC), "exec")
        self.assertTrue(
            table.lookup("sanitise_for_terminal").is_imported(),
            "raptor_agentic.py must import sanitise_for_terminal at module "
            "level — the error-relay handlers in main() depend on the "
            "global binding",
        )

        def walk(scope):
            yield scope
            for child in scope.get_children():
                yield from walk(child)

        for scope in walk(table):
            if scope.get_type() != "function":
                continue
            try:
                symbol = scope.lookup("sanitise_for_terminal")
            except KeyError:
                continue
            self.assertFalse(
                symbol.is_local(),
                f"function {scope.get_name()!r} (line {scope.get_lineno()}) "
                "makes 'sanitise_for_terminal' function-local — a branch-"
                "local import turns every other handler's relay into an "
                "UnboundLocalError",
            )

    def test_no_cross_branch_nested_import_consumption(self):
        tree = ast.parse(RAPTOR_AGENTIC.read_text(encoding="utf-8"))
        offences: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                offences.extend(_cross_branch_nested_import_uses(node))
        self.assertEqual(
            offences, [],
            "branch-local import bindings consumed from other branches:\n"
            + "\n".join(offences),
        )


class _Boom(RuntimeError):
    """Injected fault; message carries a control char to prove defanging."""


_HOSTILE = "injected failure \x1b[2Jhostile"


@unittest.skipUnless(GIT, "git binary required for target fixtures")
class RelayHandlerLiveTests(unittest.TestCase):
    """Drive main() into each relay handler's error path.

    Fault injection is at module seams only; the code under test is the
    installed tree. Each lane asserts the handler's DESIGNED behaviour:
    the sanitised message reaches the terminal (control chars defanged)
    and the run continues or refuses cleanly — never an
    UnboundLocalError out of the handler itself.
    """

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(REPO_ROOT))
        import raptor_agentic
        cls.raptor_agentic = raptor_agentic

    @classmethod
    def tearDownClass(cls):
        with contextlib.suppress(ValueError):
            sys.path.remove(str(REPO_ROOT))

    def setUp(self):
        self._env = os.environ.copy()
        self._argv = list(sys.argv)
        self._patched: list[tuple[object, str, object]] = []

    def tearDown(self):
        for obj, name, original in reversed(self._patched):
            setattr(obj, name, original)
        sys.argv = self._argv
        os.environ.clear()
        os.environ.update(self._env)

    def _patch(self, obj, name, replacement):
        self._patched.append((obj, name, getattr(obj, name)))
        setattr(obj, name, replacement)

    # ---- fixtures ----------------------------------------------------

    def _make_target(self, git: bool = True) -> Path:
        import tempfile
        target = Path(tempfile.mkdtemp(prefix="relay-target-"))
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        (target / "app.c").write_text(
            "#include <stdio.h>\nint main(void){return 0;}\n",
            encoding="utf-8",
        )
        if git:
            for cmd in (
                [GIT, "init", "-q"],
                [GIT, "add", "."],
                [GIT, "-c", "user.name=t", "-c", "user.email=t@t",
                 "commit", "-qm", "snapshot"],
            ):
                subprocess.run(cmd, cwd=target, check=True,
                               capture_output=True, timeout=60)
        return target

    def _out_dir(self) -> Path:
        import tempfile
        out = Path(tempfile.mkdtemp(prefix="relay-out-")) / "run"
        self.addCleanup(shutil.rmtree, out.parent, ignore_errors=True)
        return out

    def _fake_binary(self) -> Path:
        import tempfile
        handle = tempfile.NamedTemporaryFile(
            prefix="relay-bin-", delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(b"\x7fELF-not-really")
        handle.close()
        return Path(handle.name)

    def _drive(self, argv: list[str]):
        """Run main() with captured stdio; return (result, out, err).

        ``result`` is the return value, or the SystemExit code, or the
        propagated exception instance.
        """
        sys.argv = ["raptor_agentic.py", *argv]
        stdout, stderr = io.StringIO(), io.StringIO()
        outcome: object = None
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            try:
                outcome = self.raptor_agentic.main()
            except SystemExit as exc:
                outcome = exc.code
            except BaseException as exc:  # noqa: BLE001 — the assertion subject
                outcome = exc
        return outcome, stdout.getvalue(), stderr.getvalue()

    def _base_args(self, target: Path, out: Path) -> list[str]:
        return ["--repo", str(target), "--out", str(out), "--project", "-"]

    def _assert_handled(self, outcome, streams: str, needle: str):
        self.assertNotIsInstance(
            outcome, BaseException,
            f"relay handler crashed instead of handling: {outcome!r}",
        )
        self.assertIn(needle, streams)
        self.assertNotIn("\x1b", streams.split(needle, 1)[-1][:400])

    # ---- lanes -------------------------------------------------------

    def test_lane_git_init_failure_relays_and_refuses(self):
        """Non-git target, git init errors: '✗ Error initializing git'."""
        target = self._make_target(git=False)
        import core.sandbox

        def _boom_run(*_a, **_k):
            raise _Boom(_HOSTILE)

        self._patch(core.sandbox, "run", _boom_run)
        outcome, out, err = self._drive(
            self._base_args(target, self._out_dir()))
        self._assert_handled(outcome, err, "Error initializing git")
        self.assertEqual(outcome, 1)

    def test_lane_oplock_refusal_is_clean_message_not_traceback(self):
        """OpLockContention from start_run: sanitised '✗ ...' + exit 1."""
        target = self._make_target()
        import core.run
        from core.project.oplock import OpLockContention

        def _contended(*_a, **_k):
            raise OpLockContention(_HOSTILE)

        self._patch(core.run, "start_run", _contended)
        outcome, out, err = self._drive(
            self._base_args(target, self._out_dir()))
        self._assert_handled(outcome, err, "injected failure")
        self.assertEqual(outcome, 1)

    def test_lane_mitigation_check_degrades_and_continues(self):
        """analyze_binary raises: degrade message, scan still reached."""
        target = self._make_target()
        import packages.exploit_feasibility as feasibility

        def _boom(*_a, **_k):
            raise _Boom(_HOSTILE)

        class _Reached(Exception):
            pass

        calls = {"n": 0}

        def _trust_probe(*_a, **_k):
            # First post-mitigation call proves the run CONTINUED past
            # the degrade handler; stop there to bound the test.
            calls["n"] += 1
            raise _Reached

        self._patch(feasibility, "analyze_binary", _boom)
        self._patch(self.raptor_agentic, "check_repo_claude_trust",
                    _trust_probe)
        outcome, out, err = self._drive(
            self._base_args(target, self._out_dir())
            + ["--binary", str(self._fake_binary())])
        self.assertIsInstance(
            outcome, _Reached,
            f"run did not continue past the mitigation handler: {outcome!r}"
            f"\nstderr: {err[-500:]}",
        )
        self.assertIn("Mitigation check failed", err)
        self.assertNotIn("\x1b[2J", err)

    def _one_finding_sarif(self) -> Path:
        """A minimal 1-result SARIF: keeps the run past the no-findings
        abort so the post-scan degrade lanes are reachable."""
        import json
        import tempfile
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", prefix="relay-", delete=False)
        self.addCleanup(os.unlink, handle.name)
        json.dump({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "imported", "rules": [
                    {"id": "test/format-string"},
                ]}},
                "results": [{
                    "ruleId": "test/format-string",
                    "level": "warning",
                    "message": {"text": "imported test finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.c"},
                            "region": {"startLine": 2},
                        },
                    }],
                }],
            }],
        }, handle)
        handle.close()
        return Path(handle.name)

    @pytest.mark.slow  # full main() traversal — two real end-to-end degrade runs
    def test_lane_mechanical_sca_and_fuzz_phase_degrade_to_completion(self):
        """SCA subprocess + fuzz phase both fail: run still completes."""
        target = self._make_target()
        try:
            import packages.fuzzing.orchestrator as fuzz_orch
            import packages.sca.agent as sca_agent_mod
        except ImportError as exc:  # pragma: no cover - optional deps
            self.skipTest(f"optional packages missing: {exc}")

        def _boom(*_a, **_k):
            raise _Boom(_HOSTILE)

        self._patch(sca_agent_mod, "_find_sca_agent",
                    lambda: "/nonexistent/sca-agent")
        self._patch(sca_agent_mod, "run_sca_subprocess", _boom)
        self._patch(fuzz_orch, "FuzzingOrchestrator", _boom)
        outcome, out, err = self._drive(
            self._base_args(target, self._out_dir())
            + ["--sarif", str(self._one_finding_sarif()), "--fuzz",
               "--binary", str(self._fake_binary()), "--skip-dedup",
               "--no-exploits", "--no-patches", "--no-binary-oracle"])
        self._assert_handled(outcome, err, "SCA failed")
        self._assert_handled(outcome, err, "Fuzz phase error")
        self.assertEqual(
            outcome, 0,
            f"degrade lanes must not fail the run\nstderr: {err[-800:]}",
        )

    @pytest.mark.slow  # full main() traversal — two real end-to-end degrade runs
    def test_lane_deep_sca_and_crash_triage_degrade_to_completion(self):
        """Deep SCA + crash-triage handoff both fail: run completes."""
        target = self._make_target()
        try:
            import packages.fuzzing.orchestrator as fuzz_orch
            import packages.sca.pipeline as sca_pipeline
        except ImportError as exc:  # pragma: no cover - optional deps
            self.skipTest(f"optional packages missing: {exc}")

        def _boom(*_a, **_k):
            raise _Boom(_HOSTILE)

        class _FakeOrchestrator:
            def __init__(self, llm=None):
                pass

            def plan(self, _binary):
                return SimpleNamespace(
                    summary=lambda: "  fake plan", fuzzer="afl",
                    can_run=True, blockers=[])

            def execute(self, _plan, **_kwargs):
                return {
                    "crashes": 1, "crashes_dir": None, "stats": {},
                    "telemetry": None, "fuzzer": "afl",
                    "generated_corpus": None,
                }

        self._patch(sca_pipeline, "run_sca", _boom)
        self._patch(fuzz_orch, "FuzzingOrchestrator", _FakeOrchestrator)
        self._patch(self.raptor_agentic,
                    "_prepare_fuzz_crashes_for_validate", _boom)
        outcome, out, err = self._drive(
            self._base_args(target, self._out_dir())
            + ["--sarif", str(self._one_finding_sarif()), "--sca", "--fuzz",
               "--binary", str(self._fake_binary()), "--skip-dedup",
               "--no-exploits", "--no-patches", "--no-binary-oracle"])
        self._assert_handled(outcome, err, "SCA failed")
        self._assert_handled(
            outcome, err, "Crash triage / validation handoff failed")
        self.assertEqual(
            outcome, 0,
            f"degrade lanes must not fail the run\nstderr: {err[-800:]}",
        )


if __name__ == "__main__":
    unittest.main()
