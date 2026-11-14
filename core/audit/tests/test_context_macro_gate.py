"""Context macro dispatch without context assembly or source parsing."""

import ast
from pathlib import Path


def test_recognised_cpp_headers_dispatch_macro_context():
    source = Path(__file__).parents[1] / "context.py"
    tree = ast.parse(source.read_text())
    gate = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Attribute)
        and node.test.func.attr == "endswith"
        and isinstance(node.test.args[0], ast.Tuple)
        and any(isinstance(child, ast.Constant) and child.value == "macro_definitions"
                for child in ast.walk(node))
    )
    dispatch = compile(ast.Module(body=[gate], type_ignores=[]), str(source), "exec")
    for suffix in [".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".rs", ".txt"]:
        calls = []
        retained = [("OWNED", "scalar replacement")]

        def resolve(target, text, lang="c"):
            calls.append((target, text, lang))
            return retained

        ctx = {"source": "owned scalar source"}
        target = Path("owned-target")
        exec(dispatch, {"file_path": "owned" + suffix, "ctx": ctx,
                        "target_path": target, "_resolve_macros": resolve})
        if suffix == ".txt":
            assert calls == []
            assert "macro_definitions" not in ctx
        else:
            assert calls == [(target, ctx["source"], "rust" if suffix == ".rs" else "c")]
            assert ctx["macro_definitions"] is retained
