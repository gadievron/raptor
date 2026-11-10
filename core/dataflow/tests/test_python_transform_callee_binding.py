"""Python certificates must bind the actual qualified call result."""
import json

import pytest


from core.dataflow import tier1_llm
from core.dataflow.smt_barrier import Tier0Status


def _run(tmp_path, target, first="good", sink="safe"):
    line = '    ' + first + ', ' + target + ' = html.escape(value), helper.escape(value)'
    source = ('import html\ndef handle(value, helper):\n'
              '    if type(value) is not str: return\n' + line + '\n    consume(' + sink + ')\n')
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "html.escape"})
    return tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                               sink_uri="app.py", sink_line=5, sink_class="xss", language="python",
                               complete=lambda *_args: reply)


def test_tuple_binding_does_not_credit_a_different_same_tail_callee(tmp_path):
    result = _run(tmp_path, "safe")
    assert result.status is Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None



def test_repeated_tuple_target_does_not_keep_an_earlier_call_certificate(tmp_path):
    result = _run(tmp_path, "safe", first="safe")
    assert result.status is Tier0Status.NOT_APPLICABLE, result.reasoning


def test_mechanical_substitution_does_not_exempt_another_same_tail_call(tmp_path):
    from core.dataflow import smt_barrier

    line = "    value = re.sub(r'[" + chr(92) * 2 + "/.]', '', value); value = helper.sub(value)"
    source = 'import re\ndef handle(value, helper):\n' + line + '\n    consume(value)\n'
    (tmp_path / "app.py").write_text(source)
    result = smt_barrier.try_tier0(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                  sink_uri="app.py", sink_line=4, sink_class="pathtrav", language="python")
    assert result.status is Tier0Status.NOT_APPLICABLE, result.reasoning



def test_canonical_tuple_element_retains_its_source_type_receipt(tmp_path):
    result = _run(tmp_path, "raw", first="safe", sink="safe")
    assert result.status is Tier0Status.SOUND, result.reasoning
    assert result.extras["input_type_evidence"]["origin"] == "adjacent-exact-type-guard"


def test_whitelist_never_falls_back_to_a_same_tail_name():
    import ast
    from core.dataflow import smt_barrier
    from core.dataflow.source_identity import canonical_python_call_spans

    source = 'import html\ngood, bad = html.escape(value), helper.escape(value)\n'
    tree = ast.parse(source)
    spans = canonical_python_call_spans(tree, 2, frozenset({"html.escape"}))
    assert len(spans) == 1
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert smt_barrier._is_sanitizer_call_value(calls[0], frozenset({"escape"}), call_spans=spans)
    assert not smt_barrier._is_sanitizer_call_value(calls[1], frozenset({"escape"}), call_spans=spans)
    assert not smt_barrier._is_sanitizer_call_value(calls[0], None, call_spans=frozenset())


def test_source_import_alias_resolves_without_granting_type_authority():
    import ast
    from core.dataflow.source_identity import canonical_python_call_spans

    source = 'from html import escape as encode\nsafe = encode(value)\n'
    tree = ast.parse(source)
    spans = canonical_python_call_spans(tree, 2, frozenset({"html.escape"}))
    assert len(spans) == 1
    targets = tier1_llm._transform_binding_targets(
        tree, source, 2, "html.escape", language="python", call_spans=spans,
    )
    assert targets == {"safe"}


def test_ambiguous_canonical_calls_have_no_binding_exemption():
    import ast
    from core.dataflow.source_identity import canonical_python_call_spans

    tree = ast.parse('import html\na, b = html.escape(first), html.escape(second)\n')
    assert canonical_python_call_spans(tree, 2, frozenset({"html.escape"})) == frozenset()


def test_mechanical_substitution_own_call_remains_eligible(tmp_path):
    from core.dataflow import smt_barrier

    line = "    value = re.sub(r'[" + chr(92) * 2 + "/.]', '', value)"
    source = 'import re\ndef handle(value):\n' + line + '\n    consume(value)\n'
    (tmp_path / "app.py").write_text(source)
    result = smt_barrier.try_tier0(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                  sink_uri="app.py", sink_line=4, sink_class="pathtrav", language="python")
    assert result.status is Tier0Status.SOUND, result.reasoning



@pytest.mark.parametrize("overwrite", [False, True], ids=["own-call", "same-tail-overwrite"])
def test_loop_exemption_is_limited_to_the_qualified_call(overwrite):
    import ast
    from core.dataflow import smt_barrier
    from core.dataflow.source_identity import canonical_python_call_spans

    line = '    safe = html.escape(value)' + ('; safe = helper.escape(value)' if overwrite else '')
    source = 'import html\nfor item in items:\n' + line + '\n    consume(safe)\n'
    tree = ast.parse(source)
    spans = canonical_python_call_spans(tree, 3, frozenset({"html.escape"}))
    assert len(spans) == 1
    assert smt_barrier._rebound_in_loop_containing_sink(
        tree, "safe", 3, 4, sanitizer_call_tails=frozenset({"escape"}),
        sanitizer_call_spans=spans,
    ) is overwrite


def test_walrus_rebinding_does_not_receive_another_call_exemption(tmp_path):
    line = '    ((safe := html.escape(value)), (safe := helper.escape(value)))'
    source = ('import html\ndef handle(value, helper):\n'
              '    if type(value) is not str: return\n' + line + '\n    consume(safe)\n')
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "html.escape"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=5, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "does not reach the sink line" in result.reasoning



def test_production_python_chain_consumers_supply_source_call_spans():
    """Keep source consumers distinct from the legacy tail-only model API."""
    import ast
    from pathlib import Path

    expected = {
        "_python_chain_reaches_sink": {
            ("smt_barrier.py", "try_tier0"),
            ("tier1_llm.py", "try_tier1b"),
            ("tier1_llm.py", "_try_known_safe_call"),
            ("injection_prescreen.py", "_step_refutes_path"),
        },
        "_rebound_in_loop_containing_sink": {
            ("smt_barrier.py", "_python_chain_reaches_sink"),
            ("smt_barrier.py", "_lexical_substitution_dominates"),
        },
    }
    found = {name: set() for name in expected}
    for path in Path(__file__).resolve().parents[1].glob("*.py"):
        source = path.read_text(encoding="utf-8")
        if not any(name in source for name in expected):
            continue
        tree = ast.parse(source)
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in expected:
                continue
            owner = node
            while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = parents[owner]
            assert isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef))
            found[node.func.id].add((path.name, owner.name))
            arguments = {keyword.arg: keyword.value for keyword in node.keywords}
            assert "sanitizer_call_spans" in arguments, (path.name, owner.name)
            value = arguments["sanitizer_call_spans"]
            assert not (isinstance(value, ast.Constant) and value.value is None)
    assert found == expected
