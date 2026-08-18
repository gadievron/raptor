"""Call-site signature conformance for suppressed-exception seams.

The orchestrator wraps per-function context enrichment in
``contextlib.suppress(Exception)`` — a call-site arity mismatch there
does not crash, it silently disables the feature.  These tests bind
the call sites to the real substrate signatures so a drift fails
loudly in CI instead of vanishing into the suppress.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

ORCHESTRATOR = Path(__file__).resolve().parents[1] / "orchestrator.py"


def _find_calls(func_name: str) -> list[ast.Call]:
    tree = ast.parse(ORCHESTRATOR.read_text(encoding="utf-8"))
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
            name = getattr(target, "id", None) or getattr(target, "attr", None)
            if name == func_name:
                calls.append(node)
    return calls


class TestExtractTypeConstraintsCallSite:
    def test_call_site_matches_signature(self):
        """The enrichment call must bind cleanly to the substrate.

        Regression: the call passed ``(source, function_name)`` to a
        ``(source, file_path, function_name)`` signature — the
        TypeError was eaten by ``contextlib.suppress`` and
        ``type_constraints`` never reached any review prompt.
        """
        from core.audit.mechanical_gates import extract_type_constraints

        sig = inspect.signature(extract_type_constraints)
        calls = _find_calls("extract_type_constraints")
        assert calls, "orchestrator no longer calls extract_type_constraints"
        for call in calls:
            n_pos = len(call.args)
            kw = [k.arg for k in call.keywords if k.arg]
            # Bind positionally against the real signature: raises
            # TypeError when the call shape is wrong.
            params = list(sig.parameters)
            assert n_pos + len(kw) >= 3, (
                f"extract_type_constraints called with {n_pos} positional "
                f"+ {kw} keyword args; signature is {params}"
            )
            bound_names = params[:n_pos] + kw
            assert set(bound_names) >= {"source", "file_path", "function_name"}, (
                f"call binds {bound_names}, missing required parameters "
                f"of {params}"
            )

    def test_functional_type_constraints_reach_result(self):
        """End-to-end shape check on the substrate itself."""
        from core.audit.mechanical_gates import extract_type_constraints

        src = "def process(count: int, name: str) -> None:\n    pass\n"
        results = extract_type_constraints(src, "svc/app.py", "process")
        assert isinstance(results, list)
