"""Regression test for F105.

`raptor_agentic.py` prints "✓ Scanned with Semgrep" in the final
summary block, gated only on:

    if not args.codeql_only:
        print("   ✓ Scanned with Semgrep")

That fires regardless of whether Semgrep actually ran successfully:
the operator sees the green check even when the scan timed out,
returned a non-{0,1} exit code, or produced no metrics file
(`scan_metrics.json` absent). The print is asymmetric vs. the very
next block which correctly gates on the metrics dict:

    if codeql_metrics:
        print("   ✓ Scanned with CodeQL")

Fix: tighten the gate to ALSO check the metrics dict (a non-empty
`semgrep_metrics` only exists on rc in {0, 1} + metrics file
present + not-timed-out). Matches the CodeQL pattern at line 1444.

This test parses `raptor_agentic.py` with ``ast`` (avoiding the
heavyweight import path) and asserts the gate condition around the
"Scanned with Semgrep" print includes a reference to
`semgrep_metrics`.
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "raptor_agentic.py"
)


def test_semgrep_summary_print_is_gated_on_semgrep_metrics() -> None:
    """The summary-block 'Scanned with Semgrep' print must be gated
    on `semgrep_metrics` (a truthy dict), not solely on the CLI flag.
    """
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find every print(...) call whose first arg is a constant string
    # containing "Scanned with Semgrep", and trace up the parent chain
    # to find the enclosing If.
    # `ast` doesn't track parents — walk with explicit parent ptrs.
    parents: dict[ast.AST, ast.AST | None] = {tree: None}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    target_calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "print" and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) \
                    and "Scanned with Semgrep" in arg0.value:
                target_calls.append(node)

    assert target_calls, (
        "could not find the 'Scanned with Semgrep' print — has the "
        "summary block moved? Update this test."
    )

    # Walk up to the closest enclosing If and inspect the test expression.
    for call in target_calls:
        node: ast.AST | None = call
        while node is not None and not isinstance(node, ast.If):
            node = parents.get(node)
        assert isinstance(node, ast.If), (
            "'Scanned with Semgrep' print is not inside any `if` block"
        )
        # Stringify the condition and look for 'semgrep_metrics'.
        cond_src = ast.unparse(node.test)
        assert "semgrep_metrics" in cond_src, (
            f"the gate around the 'Scanned with Semgrep' print is "
            f"`if {cond_src}:` — it must also check `semgrep_metrics` "
            f"(mirror of the CodeQL block which gates on "
            f"`if codeql_metrics:`). Without that check, the green "
            f"summary tick fires even when Semgrep timed out / errored "
            f"/ produced no metrics."
        )
