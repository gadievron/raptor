"""Source-pinned stdlib DAG generation only, without NetworkX admission."""

import ast
import hashlib
import json
from pathlib import Path
import random

import pytest

ROOT = Path(__file__).resolve().parents[3]
METHOD_PIN = "e12949e8c2fef04f5dee88351fa1c335b521bc38c9c4c44c96247fb883e9ce8d"


@pytest.mark.parametrize(
    "boundary", [False, True], ids=["complete", "controlled-boundary"]
)
def test_graph_rng_fixture_ownership(tmp_path, boundary):
    source = ROOT / "core/analysis/tests/test_dominators.py"
    text = source.read_text()
    method = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_matches_networkx_on_random_dag"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, method).encode()).hexdigest()
        == METHOD_PIN
    )
    assert (
        len(method.decorator_list) == 1
    )  # Native optional guard is not executed/copied.
    start = next(
        i
        for i, n in enumerate(method.body)
        if isinstance(n, ast.Assign)
        and isinstance(n.value, ast.Call)
        and ast.unparse(n.value.func) == "random.Random"
    )
    end = next(i for i, n in enumerate(method.body) if isinstance(n, ast.For))
    prefix = method.body[start : end + 1]
    before = random.getstate()
    try:
        namespace = {"random": random}

        class ControlledBoundary(Exception):
            pass

        def stop():
            raise ControlledBoundary("after graph generation")

        namespace["stop"] = stop
        statements = [*prefix]
        if boundary:
            statements.extend(ast.parse("stop()").body)
            with pytest.raises(ControlledBoundary, match="after graph generation"):
                exec(
                    compile(
                        ast.Module(body=statements, type_ignores=[]),
                        str(source),
                        "exec",
                    ),
                    namespace,
                )
        else:
            exec(
                compile(
                    ast.Module(body=statements, type_ignores=[]), str(source), "exec"
                ),
                namespace,
            )
        after = random.getstate()
        assert before == after
        edges = namespace["edges"]
        digest = hashlib.sha256(json.dumps(edges, sort_keys=True).encode()).hexdigest()
        assert (
            digest == "51a4792d9eb640f6b8d9f9950be66dbf8b6af2f929ca6626365b7da06aa8873c"
        )
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "global_rng_unchanged_before_rescue": True,
                    "controlled_boundary": boundary,
                    "graph_sha256": digest,
                    "edges": edges,
                    "scope": "stdlib graph-generation component only; native optional guard unchanged/unevaluated, no NetworkX import or algorithm execution",
                }
            )
            + "\n"
        )
    finally:
        random.setstate(before)
