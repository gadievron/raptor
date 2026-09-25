"""Structural pins for the analyzed-units coverage-overlay wiring.

The projection itself is unit-tested in test_coverage_projection.py;
these pins hold the two dispatch scripts to the wiring contract so a
refactor can't silently drop or weaken it. What the pin ENFORCES
(exactly — no more is claimed):

  * both scripts wire the overlay (the import line is present) and
    reference ``project_scan_coverage`` ONLY as directly-called
    ``Name``/``Attribute`` nodes — aliasing (``_p =
    project_scan_coverage`` or ``_p = mod.project_scan_coverage``)
    and string-keyed lookups (a ``"project_scan_coverage"`` constant
    anywhere, the getattr escape) fail the pin;
  * every call sits inside its OWN dedicated try: the innermost
    enclosing ``Try``'s body may call nothing but the projection and
    ``print`` (so hiding the call inside a phase-level try — whose
    handler fails the phase — cannot satisfy it);
  * that try's handlers catch broadly (bare or ``Exception``), contain
    NO ``raise``, and are loud (at least one call — the print/log).

The pin is structural, not behavioural: it cannot prove the handler's
loud line is truthful, only that a swallow-and-report shape exists at
every call site.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

_ROOT = Path(__file__).parents[3]

_TARGET = "project_scan_coverage"
#: Calls allowed inside a dedicated overlay try-body besides the
#: projection itself (the success print).
_ALLOWED_TRY_CALLS = frozenset({_TARGET, "print"})


def _call_name(node: ast.Call) -> str:
    return getattr(node.func, "id", getattr(node.func, "attr", ""))


def _handler_is_broad(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    names = []
    t = handler.type
    for n in t.elts if isinstance(t, ast.Tuple) else [t]:
        names.append(getattr(n, "id", getattr(n, "attr", "")))
    return "Exception" in names or "BaseException" in names


def check_wiring(source: str) -> list[str]:
    """Return the list of contract violations in *source* ([] = ok)."""
    tree = ast.parse(source)
    problems: list[str] = []

    # 1. No indirect references: every Name OR Attribute mention of
    #    the target must be the func of a Call; no string constant may
    #    spell it.
    calls: list[ast.Call] = []
    call_funcs: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if _call_name(node) == _TARGET:
                calls.append(node)
                if isinstance(node.func, (ast.Name, ast.Attribute)):
                    call_funcs.add(id(node.func))
        if isinstance(node, ast.Constant) and node.value == _TARGET:
            problems.append("string reference to the projection "
                            "(getattr-style escape)")
    for node in ast.walk(tree):
        is_ref = ((isinstance(node, ast.Name) and node.id == _TARGET)
                  or (isinstance(node, ast.Attribute)
                      and node.attr == _TARGET))
        if is_ref and id(node) not in call_funcs:
            problems.append("non-call reference to the projection "
                            "(aliasing escape)")
    if not calls:
        problems.append("no project_scan_coverage call")
        return problems

    # 2. Innermost enclosing Try per call: dedicated + fail-open.
    class _Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.try_stack: list[ast.Try] = []

        def visit_Try(self, node: ast.Try) -> None:
            self.try_stack.append(node)
            for child in node.body:
                self.visit(child)
            self.try_stack.pop()
            for part in (node.handlers, node.orelse, node.finalbody):
                for child in part:
                    self.visit(child)

        def visit_Call(self, node: ast.Call) -> None:
            if _call_name(node) == _TARGET:
                if not self.try_stack:
                    problems.append("projection call outside any try")
                else:
                    self._check_try(self.try_stack[-1])
            self.generic_visit(node)

        def _check_try(self, t: ast.Try) -> None:
            body_calls = {
                _call_name(n) for stmt in t.body
                for n in ast.walk(stmt) if isinstance(n, ast.Call)
            }
            if not body_calls <= _ALLOWED_TRY_CALLS:
                problems.append(
                    "projection call's innermost try is not dedicated "
                    f"(also calls: {sorted(body_calls - _ALLOWED_TRY_CALLS)})")
            if not t.handlers:
                problems.append("projection try has no handlers")
            for h in t.handlers:
                if not _handler_is_broad(h):
                    problems.append("projection handler is not broad")
                for n in ast.walk(h):
                    if isinstance(n, ast.Raise):
                        problems.append("projection handler re-raises")
                if not any(isinstance(n, ast.Call)
                           for stmt in h.body for n in ast.walk(stmt)):
                    problems.append("projection handler is silent "
                                    "(no loud line)")

    _Visitor().visit(tree)
    return problems


class TestOverlayWiring(unittest.TestCase):

    def _assert_wired(self, script: str) -> None:
        src = (_ROOT / script).read_text(encoding="utf-8")
        self.assertIn("from packages.openant.coverage import", src,
                      f"{script} must wire the coverage overlay")
        self.assertEqual(
            check_wiring(src), [],
            f"{script} violates the fail-open overlay wiring contract")

    def test_standalone_openant_projects_fail_open(self):
        self._assert_wired("raptor_openant.py")

    def test_agentic_openant_phase_projects_fail_open(self):
        self._assert_wired("raptor_agentic.py")

    # ---- the pin's own detection power (mutation controls) ----

    def test_pin_rejects_phase_level_try(self):
        # M2: only the outer phase try guards the call — its body runs
        # the scan too, so a projection failure fails the phase.
        src = (
            "try:\n"
            "    run_openant_scan(a)\n"
            "    project_scan_coverage(a, b)\n"
            "except Exception:\n"
            "    record_phase_failure()\n"
        )
        self.assertTrue(any("not dedicated" in p for p in check_wiring(src)))

    def test_pin_rejects_reraising_handler(self):
        src = (
            "try:\n"
            "    project_scan_coverage(a, b)\n"
            "except Exception:\n"
            "    log(1)\n"
            "    raise\n"
        )
        self.assertTrue(any("re-raises" in p for p in check_wiring(src)))

    def test_pin_rejects_alias_and_getattr_escapes(self):
        src = (
            "try:\n"
            "    project_scan_coverage(a, b)\n"
            "except Exception:\n"
            "    log(1)\n"
            "_p = project_scan_coverage\n"
            "_p(c, d)\n"
        )
        self.assertTrue(any("aliasing" in p for p in check_wiring(src)))
        src2 = 'getattr(mod, "project_scan_coverage")(a, b)\n'
        self.assertTrue(any("string reference" in p
                            for p in check_wiring(src2)))
        # Attribute-reference escape (module attr aliased, not called).
        src3 = (
            "try:\n"
            "    project_scan_coverage(a, b)\n"
            "except Exception:\n"
            "    log(1)\n"
            "_p = cov_mod.project_scan_coverage\n"
            "_p(c, d)\n"
        )
        self.assertTrue(any("aliasing" in p for p in check_wiring(src3)))

    def test_pin_rejects_narrow_and_silent_handlers(self):
        src = (
            "try:\n"
            "    project_scan_coverage(a, b)\n"
            "except ValueError:\n"
            "    log(1)\n"
        )
        self.assertTrue(any("not broad" in p for p in check_wiring(src)))
        src2 = (
            "try:\n"
            "    project_scan_coverage(a, b)\n"
            "except Exception:\n"
            "    pass\n"
        )
        self.assertTrue(any("silent" in p for p in check_wiring(src2)))

    def test_pin_accepts_the_contract_shape(self):
        src = (
            "try:\n"
            "    from packages.openant.coverage import project_scan_coverage\n"
            "    line = project_scan_coverage(a, b, level=c)\n"
            "    if line:\n"
            "        print(line)\n"
            "except Exception as e:\n"
            "    print('overlay failed', e)\n"
        )
        self.assertEqual(check_wiring(src), [])


if __name__ == "__main__":
    unittest.main()
